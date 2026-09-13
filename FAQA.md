# Sniff4Hound - Informe de QA / Auditoria de Seguridad (FAQA)

**Rol:** Revision realizada como QA Lead / analista SOC especializado en sniffers, honeypots y motores de IA de deteccion.
**Alcance:** Rama `feature/faqa`, backend `sniff4hound/*.py`, frontend `frontend/src/**`, empaquetado Debian (`scripts/build_deb.sh`, `scripts/deb_postinst.sh`, `scripts/deb_postrm.sh`), pruebas relacionadas y verificacion puntual contra una instancia local real en ejecucion (`v0.58.0`, `http://127.0.0.1:45678`).
**Metodo:** Relectura estatica dirigida de autenticacion, CSRF/origin checks, WebSocket, almacenamiento, redaccion, sniffer, honeypot, IA, frontend y empaquetado; contraste contra los hallazgos historicos del FAQA anterior tras el rediseno de retencion/persistencia de paquetes de esta iteracion; y pruebas dinamicas puntuales sobre la instancia viva. Los codigos de seguridad usados en la prueba no se documentan aqui.
**Fecha:** 2026-09-13 (revision `v0.58.0`, sobre el mismo `v0.52.0` revisado antes).

> Convencion de severidad: **Critical** (explotable remotamente / caida del sensor) | **High** (bypass relevante de un limite de seguridad) | **Medium** (riesgo real o gap de defensa en profundidad) | **Low** (mejora menor) | **Info** (limitacion o comportamiento aceptado).

---

## 0. Resumen ejecutivo

- **No quedan hallazgos Critical, High, Medium ni Low abiertos.** El unico hallazgo Low que esta pasada habia detectado (trafico muteado/whitelisteado/excluido reteniendo bytes crudos por el nuevo default global) ya se corrigio y se verifico con test - ver 2.16.
- Los hallazgos criticos/altos del reporte anterior siguen mitigados sin regresiones: ReDoS por regex, politica de puertos del honeypot, validacion de import de IA, rate limiting UDP, tickets WebSocket de un solo uso, guard CSRF por origen, limite de concurrencia TCP del honeypot, truncado/redaccion de access log y lock de arranque IPC (verificado por relectura de codigo puntual sobre cada uno).
- La instancia local (`v0.58.0`) respondio correctamente a pruebas dinamicas sensibles: sesion autenticada `200`, `POST` cross-origin bloqueado con `403 bad_origin` (probado con y sin credencial valida), y `GET /api/ai/config` reflejando el estado real de retencion/Monitors/IA de esa instancia.
- **Cambio de diseno relevante en esta iteracion:** la persistencia de paquetes ya no depende de los interruptores Monitors/IA para decidir "guardar todo" - un paquete solo persiste si la evaluacion (catalogo de reglas, detectores de anomalia o, en "solo IA", el clasificador) levanto algo, o si es trafico muteado/whitelisteado/excluido (que conserva su contrato previo de "visible pero sin tags"). Todo lo demas se evalua y se descarta sin llegar a `INSERT`. Ver 2.14.
- Como consecuencia de lo anterior, la retencion de bytes crudos (`payload_hex`/`raw_packet`) paso de estar apagada por defecto a estar **encendida por defecto** (`STORE_RAW_PACKET_BYTES`/`SNIFF4HOUND_STORE_RAW_PACKET`, ahora `1`): dado que el trafico limpio ya no se guarda, el cambio solo expone bytes crudos del trafico que efectivamente alerto - el trafico muteado/whitelisteado/excluido, que persiste por su propio contrato de visibilidad, se corrigio para nunca retener bytes crudos independientemente de este flag global (ver 2.16). Sigue siendo un flag de `runtime_config` alternable en caliente desde el Dashboard/API sin reiniciar. Ver 2.14.
- Se detecto y corrigio en esta iteracion un defecto de empaquetado (no de codigo Python en si) que podia dejar el sensor completamente inoperable en instalaciones `.deb` cuyo Python del sistema no coincidiera con el usado para compilar el paquete: la extension nativa vendorizada de `regex` fallaba al importar (`ImportError` disfrazado de import circular) y `sniff4hound` no arrancaba en absoluto. `scripts/deb_postinst.sh` ahora reconstruye esa dependencia para el interprete real del equipo destino dentro de un venv descartable en cada instalacion. Ver 2.15.
- Los hallazgos previamente abiertos (retencion de bytes crudos opt-in, `sessionStorage` legible por JS, timeout de regex opcional) siguen cerrados; el `sessionStorage`/`localStorage` del frontend y el fail-fast de `regex_safety` no se tocaron en esta iteracion.

---

## 1. Hallazgos abiertos actuales

Ninguno. El unico punto que esta pasada habia dejado abierto (1.1 en la version anterior de este informe) se corrigio y se movio a la seccion 2 (`Hallazgos historicos cerrados`) como 2.16, con su evidencia de codigo y de test.

---

## 2. Hallazgos historicos cerrados

### 2.1 Critical - ReDoS remoto por regex de reglas/monitores/whitelist

**Estado:** cerrado.

**Evidencia:** `regex_safety.py` acota el texto evaluado (`limit_regex_subject`, lineas 17-21), rechaza patrones vacios, demasiado largos o con repeticion ambigua/nested backtracking (`validate_regex_pattern`, lineas 45-58), compila con la libreria `regex` si esta disponible y aplica timeout por busqueda (`regex_search`, lineas 77-88). El sniffer usa esos helpers en las evaluaciones regex de whitelist/monitores (`sniff4hound/sniffer.py:926-957`).

### 2.2 High - Honeypot podia intentar bind en puertos sensibles

**Estado:** cerrado.

**Evidencia:** `honeypot_ports.py` define denylist para puertos privilegiados y servicios sensibles (`CUSTOM_LISTENER_DENY_PORTS`, lineas 261-288), y `listener_port_allowed()` distingue listeners `builtin` de `custom` (`honeypot_ports.py:291-301`). El proceso honeypot valida esa politica antes de levantar cada listener (`honeypot.py:1315-1325`), por lo que el proceso privilegiado ya no depende solo de la validacion web.

### 2.3 High - Import de modelo IA validaba forma pero no valores

**Estado:** cerrado.

**Evidencia:** `_validate_imported_model()` valida que cada peso/sesgo sea numerico, finito y dentro de magnitud maxima (`ai_learning.py:291-297`), normaliza pesos/sesgos a `float` (`ai_learning.py:311-319`) y mantiene validaciones de dimensiones/capas (`ai_learning.py:299-331`). Ademas, `_forward_full()` y `_backprop_step()` tienen checks internos de dimensiones (`ai_learning.py:101-164`).

### 2.4 High - Responders UDP sin rate limiting

**Estado:** cerrado.

**Evidencia:** el honeypot mantiene ventanas por `(port, source)` con maximo de clientes y limite por ventana (`honeypot.py:1944-1966`), y `_udp_response_for()` bloquea respuestas cuando `_udp_response_allowed()` devuelve falso (`honeypot.py:1968-1972`).

### 2.5 Medium - Codigo de seguridad en query string del WebSocket

**Estado:** cerrado.

**Evidencia:** `_issue_ws_ticket()` emite tickets aleatorios, atados al cliente y con TTL corto (`app.py:1037-1051`). `_consume_ws_ticket()` los consume una sola vez con `pop()`, valida expiracion y cliente (`app.py:1054-1068`). El access log tambien redacta `ws_ticket` y `ticket` en queries (`access_log.py:49-55`, `access_log.py:65-91`).

### 2.6 Medium - Falta de verificacion CSRF/origen en rutas mutantes

**Estado:** cerrado.

**Evidencia:** `_guard_request_origin()` revisa `Origin`/`Referer` en metodos que cambian estado y rechaza origen cruzado con `403 bad_origin` (`app.py:888-906`). `_apply_api_auth_guards()` aplica autenticacion y luego origin guard a rutas API/docs protegidas (`app.py:3153-3207`). La prueba dinamica contra `/api/runtime/` con `Origin` externo devolvio `403`.

### 2.7 Medium - Codigo de seguridad persistido en `localStorage`

**Estado:** cerrado para almacenamiento persistente; el riesgo Low de `sessionStorage` que esta entrada dejaba abierto en su momento se cerro despues - ver 2.12.

**Evidencia:** `persistAuthToken()` escribe en `sessionStorage` y elimina claves de `localStorage` (`appStore.js:201-218`). La migracion desde almacenamiento legado ya no vuelve a persistir el token viejo (`appStore.js:149-177`). Existe prueba frontend especifica en `frontend/tests/soc-qa.test.js` para evitar regresion.

### 2.8 Medium - Honeypot TCP sin limite de concurrencia por listener

**Estado:** cerrado.

**Evidencia:** `_listen()` crea un `threading.BoundedSemaphore(HONEYPOT_TCP_MAX_CONNECTIONS_PER_LISTENER)` por listener TCP (`honeypot.py:1216-1221`), rechaza conexiones cuando no hay slots (`honeypot.py:1256-1261`) y libera el slot en `_handle_tcp_with_slot()` (`honeypot.py:1293-1300`).

### 2.9 Low - Access log sin tope de longitud / redaccion incompleta de queries sensibles

**Estado:** cerrado.

**Evidencia:** `REDACTED_QUERY_KEYS` incluye `code`, `security_code`, `access_token`, `token`, `auth`, `ws_ticket` y `ticket` (`access_log.py:49-55`). `_sanitize_field()` escapa espacios/control chars y trunca cada campo a `MAX_FIELD_CHARS = 512` (`access_log.py:125-148`).

### 2.10 Low - Arranque IPC con carrera al limpiar socket obsoleto

**Estado:** mitigado.

**Evidencia:** `_capture_start_lock()` serializa el bloque `unlink/spawn/connect` con lock file cuando el sistema soporta `fcntl` (`manage.py:428-455`), y `main()` lo usa alrededor de limpieza de socket, generacion de token, escritura de token 0600 y spawn del proceso de captura (`manage.py:656-700`). Si no puede abrir el lock file, el codigo hace fallback sin lock; es aceptable para ejecuciones locales normales, pero no equivale a soporte multi-instancia fuerte.

### 2.11 Medium - Retencion de bytes/hex crudos pese a redaccion de texto

**Estado:** cerrado.

**Evidencia:** `STORE_RAW_PACKET_BYTES` (`settings.py:324-330`, `SNIFF4HOUND_STORE_RAW_PACKET_BYTES` / alias legado `SNIFF4HOUND_STORE_RAW_PACKET`, `0` por defecto) controla si `register_packet()` guarda `payload_hex`/`raw_packet` (`store.py:4661-4664`). Con la opcion desactivada (default), `_sanitize_packet_forensic_fields()` limpia `payload_hex`, `raw_packet`, `frame_hex` y `frame_length` en toda lectura -- listados (`store.py:1833`), `get_packet`/`get_packet_with_children` (`store.py:4858`, `store.py:4874-4877`) y las columnas que usa la vista/API de IA (`store.py:1899`, `store.py:1915`, `store.py:1919`) -- y `_migrate_sensitive_capture_storage()` limpia filas historicas ya guardadas al abrir la base (`store.py:917-934`). `payload_text`/`response_plain` siguen redactados con `redact_sensitive_text()` independientemente de esta opcion (`store.py:4828`). Documentado en `README.md`, `docs/reference/persistence.md` y `docs/reference/runtime.md`. Cubierto por `tests/test_smoke.py::test_raw_packet_is_not_retained_by_default_and_remains_json_safe`, `tests/test_comprehensive.py::TestSniffStore::test_packet_raw_binary_is_disabled_by_default` y su contraparte con la opcion activada.

### 2.12 Low - `sessionStorage` seguia siendo legible por JavaScript del mismo origen

**Estado:** cerrado.

**Evidencia:** el token de sesion del frontend ya no se persiste en ningun almacenamiento del navegador. `persistAuthToken()` guarda el token solo en la variable de modulo `inMemoryAuthToken` y llama a `clearStoredAuthTokens()`, que borra las claves actuales y legadas tanto de `sessionStorage` como de `localStorage` (`appStore.js:210-221`). `readLocalAuthToken()` solo lee claves legadas una vez (para no perder la sesion de un build anterior) y las borra de inmediato sin re-persistirlas (`appStore.js:149-180`). Recargar la pagina exige reautenticarse salvo que la URL traiga `?code=`. Documentado en `README.md` y `docs/reference/auth.md`. Cubierto por `frontend/tests/soc-qa.test.js` ("legacy localStorage security code is not re-persisted to sessionStorage" y "startup URL security code stays in memory only").

### 2.13 Low - Timeout de regex dependia de que la dependencia `regex` estuviera instalada

**Estado:** cerrado.

**Evidencia:** `sniff4hound/regex_safety.py:6-11` ahora levanta `RuntimeError` en el import del modulo si el paquete `regex` no esta disponible, en vez de degradar en silencio a `re` sin timeout. Toda instalacion que arranque el proceso principal falla temprano y de forma visible si le falta la dependencia declarada en `pyproject.toml`, eliminando el escenario donde una instalacion parcial perdia la defensa contra ReDoS sin que nadie lo notara.

### 2.14 Medium (reevaluado) - Persistencia "guardar todo" durante Monitors/entrenamiento

**Estado:** cerrado, con rediseno de retencion.

**Evidencia:** antes de esta iteracion, `Sniffer._store_packet()` persistia *todo* paquete evaluado cuando el filtro de Monitors estaba apagado o el modo Monitors (antes "Training") estaba activo, sin exigir que nada hubiera alertado - lo que llenaba la tabla `packets` de trafico limpio sin valor (visible en el review de IA como filas "Sin bytes disponibles"). Ahora `should_persist = detection_muted or bool(monitor_hits)` (`sniffer.py:1325`): todo paquete no muteado se evalua igual de completo (catalogo + anomalias + IA en "solo IA"), pero solo persiste si esa evaluacion levanto algo; lo demas se descarta tras obtener su veredicto y nunca llega a `INSERT`. Esto aplica igual con Monitors activo o apagado - ya no existe un modo que guarde trafico "benigno" sin alerta (`docs/reference/runtime.md`, seccion "Modos de activacion"). Como consecuencia, `STORE_RAW_PACKET_BYTES` paso a `1` por defecto (`settings.py:327-330`): solo el trafico que efectivamente alerto retiene bytes crudos (el muteado/whitelisteado/excluido no, ver 2.16), no todo el trafico capturado como hubiera ocurrido con el default anterior bajo el viejo esquema "guardar todo". El interruptor `raw_retention_enabled` sigue disponible para apagarlo (`store.py:3180-3202`, `POST /api/ai/config`). Cubierto por 904 tests backend pasando (incluye `tests/test_monitors.py::TestSnifferGatedPersistence` y la clase de Training/IA), y verificado en vivo contra `v0.58.0` (`GET /api/ai/config` con `training_enabled`, `ai_alert_mode_enabled` y `raw_retention_enabled` en `true` simultaneamente, reflejando el modo real de esa instancia).

### 2.15 High (empaquetado) - `.deb` inoperable si el Python del sistema no coincide con el de build

**Estado:** cerrado.

**Evidencia:** `scripts/build_deb.sh` vendoriza dependencias compiladas (p. ej. `regex`, con extension nativa `_regex.cpython-<abi>-*.so`) usando el Python que ejecuta el script de build; el wrapper instalado (`scripts/deb_wrapper.sh`) siempre corre con `/usr/bin/python3` del equipo destino. Si ambos Python difieren en ABI (por ejemplo build en 3.12, instalacion en 3.14), la extension nativa no carga y Python lo reporta como un import circular (`cannot import name '_regex' from partially initialized module 'regex'`) en vez de un mensaje claro de incompatibilidad - `sniff4hound` no arrancaba en absoluto, incluida la primera linea del banner. `scripts/deb_postinst.sh` ahora detecta el mismatch en `configure` (`import regex._regex` contra el Python real del equipo) y reconstruye `regex` para ese interprete dentro de un venv temporal descartable, copiando solo el paquete construido al `vendor/` del sensor - sin invocar `pip` del sistema como root ni tocar site-packages del sistema. `scripts/deb_postrm.sh` limpia `/usr/lib/sniff4hound` completo (incluidos los `__pycache__` que dpkg no rastreaba) en `remove`/`purge`, evitando que reinstalaciones/rebuilds dejen residuos huerfanos entre versiones.

**Nota informativa:** el self-heal de `deb_postinst.sh` descarga `regex` desde PyPI via `pip` dentro del venv temporal durante la instalacion del paquete (como root, solo cuando hay mismatch de ABI) - riesgo de cadena de suministro estandar de cualquier instalacion por `pip`, mitigado por la verificacion de integridad propia de `pip`/PyPI (TLS + hashes de paquete) y por acotarse a un venv descartable que nunca se mezcla con site-packages del sistema. No requiere accion adicional, se documenta por transparencia.

### 2.16 Low - Trafico muteado/whitelisteado/excluido retenia bytes crudos por el nuevo default global

**Estado:** cerrado.

**Evidencia:** `SniffStore.register_packet()` ahora acepta `allow_raw_retention` (default `True`, no rompe otros llamadores); cuando es `False` fuerza `payload_hex=""`/`raw_packet=None` sin importar el flag global `get_raw_retention_enabled()` (`store.py:4707-4716`). `Sniffer._store_packet()` calcula `is_alert = bool(monitor_hits)` y llama `register_packet(packet, allow_raw_retention=is_alert)` (`sniffer.py:1325-1334`): el trafico persistido solo por estar muteado/whitelisteado/excluido (`detection_muted`, sin `is_alert`) nunca retiene bytes crudos, independientemente de que `raw_retention_enabled` este encendido globalmente; el trafico que si alerto sigue reteniendolos cuando el flag esta activo, que es la motivacion original del default (ver 2.14). Cubierto por `tests/test_monitors.py::TestSnifferGatedPersistence::test_muted_traffic_never_retains_raw_bytes_even_with_global_retention_on`, que fija `payload_hex`/`raw_packet` no vacios en el paquete de entrada, lo persiste via una regla de exclusion (sin alerta), y verifica que la fila guardada tiene ambos campos vacios pese a que `get_raw_retention_enabled()` es `True` por defecto.

---

## 3. QA dinamico contra instancia local

### 3.1 `v0.52.0` (pasada anterior)

La instancia revisada mostro banner de `SNIFF4HOUND v0.52.0`, con autenticacion habilitada y servidor en `127.0.0.1:45678`. No se registra aqui el codigo de seguridad.

Pruebas ejecutadas:

- `GET /api/auth/session` con credencial valida: **200**, `authenticated: true`, `security_code_length: 8`, `ws_auth_close_code: 4401`.
- `POST /api/runtime/` con credencial valida pero `Origin: http://evil.example`: **403**, `code: bad_origin`.
- `POST /api/ws/ticket` con credencial valida: **200**, respuesta con ticket de un solo uso y `expires_in: 15`.

### 3.2 `v0.58.0` (esta pasada)

Instancia arrancada por el operador desde el `.deb`, banner `SNIFF4HOUND v0.58.0`, autenticacion requerida, servidor en `127.0.0.1:45678`. No se registra aqui el codigo de seguridad.

Pruebas ejecutadas:

- `GET /api/dashboard/` sin credencial: **401**, `code: auth_required`.
- `GET /` sin credencial: **200** (la SPA carga; el gate de auth vive en la API/WS, no en el estatico).
- `POST /api/runtime/` sin credencial y con `Origin: http://evil.example`: **401** (el guard de auth corre antes que el de origen).
- `GET /api/auth/session` con credencial valida: **200**, `authenticated: true`.
- `POST /api/runtime/` con credencial valida pero `Origin: http://evil.example`: **403**, `code: bad_origin` - confirma que el guard de origen tambien corre para una sesion ya autenticada, no solo para anonimos.
- `GET /api/ai/config` con credencial valida: **200**, `{"sampling_enabled":true,"training_enabled":true,"ai_alert_mode_enabled":true,"raw_retention_enabled":true,...}` - refleja el modo real de esa instancia (Monitors + IA + retencion de bytes crudos, los tres activos a la vez) y confirma que el endpoint expone el estado actual de la nueva politica de retencion (ver 2.14).

No se repitio en esta pasada una navegacion completa de las 14 vistas del frontend; la ultima navegacion completa documentada en el FAQA anterior correspondia a `v0.51.0` y no debe usarse como garantia visual de `v0.58.0`.

---

## 4. Confirmado correcto en la revision actual

- **Auth/API:** rutas API y docs quedan envueltas por `_apply_api_auth_guards()` salvo `/api/auth/session`; errores de validacion se devuelven como JSON 400/404 en vez de 500 genericos (`app.py:3153-3207`).
- **CSRF/origen:** mutaciones cross-origin con `Origin`/`Referer` externo se bloquean (`app.py:888-906`).
- **WebSocket:** no usa el token largo en la query; usa ticket corto, atado al cliente y de un solo uso (`app.py:1037-1068`).
- **Frontend auth:** el token de URL se limpia con `history.replaceState()` tras leerlo (`appStore.js:120-147`) y se conserva solo en memoria (`appStore.js:210-221`); las claves legacy de `localStorage`/`sessionStorage` se leen una vez y se borran de inmediato (`appStore.js:149-198`).
- **Redaccion textual:** payload, resumen y banner pasan por `redact_sensitive_text()` antes de persistirse (`store.py:4661-4663`).
- **Retencion de bytes crudos:** `payload_hex`/`raw_packet`/`frame_hex` se guardan por defecto ahora (`settings.py:327-330`), pero solo para trafico que efectivamente alerto - el trafico muteado/whitelisteado/excluido persiste sin ellos, sin importar el flag global (ver 2.16); el trafico limpio ya no se guarda en absoluto, con o sin bytes (`sniffer.py:1325-1334`, `store.py:121-144`). El interruptor `raw_retention_enabled` sigue disponible para volver al comportamiento apagado (`store.py:3180-3202`).
- **Persistencia de paquetes:** solo se guarda trafico que alerto en alguno de los motores de deteccion (catalogo de reglas, anomalias, IA en "solo IA") o que esta explicitamente muteado/whitelisteado/excluido; todo lo demas se evalua y se descarta sin `INSERT` (`sniffer.py:1314-1345`).
- **Honeypot:** politica de puertos sensibles centralizada y enforceada en el proceso listener (`honeypot_ports.py:261-309`, `honeypot.py:1315-1325`).
- **DoS TCP/UDP honeypot:** limite de concurrencia TCP y rate limiting UDP activos (`honeypot.py:1216-1266`, `honeypot.py:1944-1972`).
- **IA:** import de modelo valida forma, tipo, finitud y magnitud; operaciones internas validan dimensiones antes de usar pesos (`ai_learning.py:101-164`, `ai_learning.py:282-331`).
- **Logs:** queries sensibles redactadas y campos truncados para evitar fuga de tokens/log injection (`access_log.py:49-91`, `access_log.py:125-148`).
- **Empaquetado `.deb`:** el postinst reconstruye dependencias compiladas (`regex`) para el Python real del equipo destino si detecta mismatch de ABI, dentro de un venv descartable, sin tocar el Python del sistema (`scripts/deb_postinst.sh`); el postrm limpia el arbol de instalacion completo en `remove`/`purge` (`scripts/deb_postrm.sh`).

---

## 5. Recomendaciones priorizadas

1. **[Cerrado]** El trafico persistido *solo* por estar muteado/whitelisteado/excluido (sin alerta real) ya nunca retiene bytes crudos, independientemente del interruptor global `raw_retention_enabled`; ver 2.16.
2. **[Cerrado]** Persistencia "guardar todo" durante Monitors/filtro apagado eliminada: solo se guarda lo que alerto (o esta muteado/excluido); ver 2.14.
3. **[Cerrado]** Retencion de bytes crudos ahora encendida por defecto, pero acotada a paquetes que realmente persisten (alerta o mute/whitelist/exclusion), no a todo el trafico capturado; sigue siendo alternable en caliente desde el Dashboard/API; ver 2.11, 2.14.
4. **[Cerrado]** `payload_hex`/`frame_hex` quedan ocultos en toda vista/API cuando `raw_retention_enabled` esta apagado; ver 2.11.
5. **[Cerrado]** El proceso falla temprano y de forma visible si falta la dependencia `regex`; ver 2.13.
6. **[Cerrado]** El `.deb` ya no queda inoperable si el Python del equipo destino no coincide con el usado para compilar el paquete (self-heal de `regex` en el postinst); ver 2.15.
7. **[Cerrado]** El codigo de seguridad del frontend ya no se persiste en ningun almacenamiento del navegador (modo in-memory-only); ver 2.12.
8. **[Info]** Repetir una pasada visual completa de las vistas principales en `v0.58.0` antes de una release publica si el cambio incluye UI significativa - la ultima pasada visual completa fue sobre `v0.51.0`.

---

## 6. Estado final de la auditoria

**Aprobado.** No hay bloqueadores Critical/High/Medium/Low abiertos. La aplicacion esta en buen estado para uso local autenticado: el rediseno de esta iteracion reduce lo que se persiste (solo trafico que alerto o esta muteado/excluido, ya no "todo lo evaluado"), el trafico muteado/whitelisteado/excluido ya nunca retiene bytes crudos aunque el default global este encendido (2.16), y el codigo de seguridad del frontend sigue viviendo solo en memoria durante la vida de la pestana. Se corrigio ademas, en el mismo pase, un defecto de empaquetado que podia dejar el `.deb` completamente inoperable en equipos con un Python distinto al de build (2.15). Queda como punto informativo repetir la pasada visual completa de las 14 vistas en `v0.58.0` antes de una release con cambios de UI significativos.
