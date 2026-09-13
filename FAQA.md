# Sniff4Hound - Informe de QA / Auditoria de Seguridad (FAQA)

**Rol:** Revision realizada como QA Lead / analista SOC especializado en sniffers, honeypots y motores de IA de deteccion.
**Alcance:** Rama `feature/faqa`, backend `sniff4hound/*.py`, frontend `frontend/src/**`, empaquetado Debian (`scripts/build_deb.sh`, `scripts/deb_postinst.sh`, `scripts/deb_postrm.sh`), suite de tests completa (backend y frontend) y verificacion puntual contra una instancia local real en ejecucion (`v0.59.0`, `http://127.0.0.1:45678`).
**Metodo:** Pasada de reverificacion completa de los 16 hallazgos historicos (2.1-2.16) por relectura de codigo puntual sobre cada uno (no solo los tocados por cambios recientes); ejecucion integra de la suite backend (`pytest`) y frontend (`npm run lint` + `npm run test:unit` + `npm run build`); y pruebas dinamicas puntuales de autenticacion, CSRF/origen, WebSocket e IA sobre la instancia viva. Los codigos de seguridad usados en la prueba no se documentan aqui.
**Fecha:** 2026-09-13 (revision `v0.59.0`; sin cambios de codigo respecto a la revision `v0.58.0` anterior de este mismo dia - ver seccion 0).

> Convencion de severidad: **Critical** (explotable remotamente / caida del sensor) | **High** (bypass relevante de un limite de seguridad) | **Medium** (riesgo real o gap de defensa en profundidad) | **Low** (mejora menor) | **Info** (limitacion o comportamiento aceptado).

---

## 0. Resumen ejecutivo

- **Pasada de reverificacion completa** (`v0.59.0`): se releyo cada uno de los 16 hallazgos historicos previos (2.1-2.16) contra el codigo actual, no solo los tocados por el ultimo cambio, y ninguno regresiono.
- **Esta vez si se resolvio el punto informativo pendiente** de pasadas anteriores ("repetir una pasada visual de las 14 vistas"): se escribio y corrio `scripts/qa_visual_pass.js`, un pase automatizado por CDP contra las 14 rutas reales del router actual (el unico script de pase visual que ya existia, `qa_ui_cdp.js`, resulto estar escrito para una UI de honeypot mas vieja con rutas que ya no existen, y se dejo intacto sin usarlo - ver 3.4).
- **Esa corrida encontro un hallazgo real, ya corregido: 2.17** - `/chat` es una ruta valida del router de Vue pero faltaba en la tupla `SPA_ROUTES` del backend, asi que una carga directa/refresh de esa URL devolvia `404 Not Found` en vez de la SPA (navegar ahi desde dentro de la app funcionaba bien). Se agrego la ruta y una prueba de regresion que parsea el router y falla si una vista futura vuelve a faltar en `SPA_ROUTES`.
- **Un segundo hallazgo, reportado por el operador con una captura del review de IA y corregido en el momento: 2.18** - la cola de revision/ensenanza de IA mostraba trafico muteado/whitelisteado/excluido ("Sin bytes disponibles", "Prioridad -/100") junto al trafico realmente evaluado, aunque ese trafico nunca tiene nada que puntuar por diseno (2.14/2.16). `list_ai_packets()` ahora lo excluye de ese listado especifico sin dejar de persistirlo.
- **No quedan hallazgos Critical, High, Medium ni Low abiertos** tras ambas correcciones.
- **Cambio de diseno pedido por el operador: 2.19** - el mapa de relaciones IP se movio al Dashboard (primero, antes de "Alertas y detecciones IA"), gano labels que ya no se pisan entre nodos, iconos/etiquetas mas especificos (Android, iPhone, Windows, Nginx, Apache, ...) via la evidencia que `infer_device_profile()` ya calculaba, y un popup por nodo con metricas + accion de blacklist/whitelist. Whitelistear un nodo ahi es deliberadamente mas fuerte que un whitelist comun: borra todo el historial de esa IP (con confirmacion nombrando la cantidad real de paquetes) y deja de rastrear su trafico nuevo por completo, en vez de solo silenciar alertas como sigue haciendo mute/exclusion.
- Se corrio la suite completa como evidencia, no solo relectura de codigo: backend `pytest` (**911 passed, 2 skipped**, incluyendo las pruebas nuevas de `/chat`, exclusion de la cola de IA y whitelist-y-purga) y frontend `npm run lint` (0 warnings) + `npm run test:unit` (**13/13**) + `npm run build` (compila sin errores), mas un pase visual con navegador real (click en un nodo, popup, boton de blacklist end-to-end).
- La instancia local (`v0.59.0`) respondio correctamente a pruebas dinamicas sensibles: `401` sin credencial en ruta mutante, `200` con credencial en `/api/auth/session`, `POST` cross-origin bloqueado con `403 bad_origin` (con credencial valida), ticket WS de un solo uso con `expires_in: 15`, y `GET /api/ai/config` reflejando el estado real de retencion/Monitors/IA de esa instancia.
- Recordatorio de lo cerrado en pasadas anteriores del mismo dia, sigue vigente sin regresion: la persistencia de paquetes solo guarda trafico que alerto o esta muteado/whitelisteado/excluido (2.14); la retencion de bytes crudos esta encendida por defecto pero el trafico solo-muteado nunca la usa (2.16); y el `.deb` se autorepara si el Python del equipo destino no coincide con el de build (2.15).

---

## 1. Hallazgos abiertos actuales

Ninguno. El punto que una pasada anterior habia dejado abierto (1.1 en su momento) se corrigio y se movio a la seccion 2 como 2.16. Esta pasada encontro dos hallazgos nuevos - `/chat` faltante en `SPA_ROUTES` al ejecutar por fin el pase visual automatizado pendiente, y trafico muteado ensuciando la cola de revision de IA (reportado por el operador con una captura de pantalla) - ambos se corrigieron en el momento y se documentaron directamente como cerrados en 2.17 y 2.18, sin quedar abiertos en ningun punto de este informe.

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

**Evidencia:** antes de esta iteracion, `Sniffer._store_packet()` persistia *todo* paquete evaluado cuando el filtro de Monitors estaba apagado o el modo Monitors (antes "Training") estaba activo, sin exigir que nada hubiera alertado - lo que llenaba la tabla `packets` de trafico limpio sin valor (visible en el review de IA como filas "Sin bytes disponibles"). Ahora `should_persist = detection_muted or bool(monitor_hits)` (`sniffer.py:1325`): todo paquete no muteado se evalua igual de completo (catalogo + anomalias + IA en "solo IA"), pero solo persiste si esa evaluacion levanto algo; lo demas se descarta tras obtener su veredicto y nunca llega a `INSERT`. Esto aplica igual con Monitors activo o apagado - ya no existe un modo que guarde trafico "benigno" sin alerta (`docs/reference/runtime.md`, seccion "Modos de activacion"). Como consecuencia, `STORE_RAW_PACKET_BYTES` paso a `1` por defecto (`settings.py:327-330`): solo el trafico que efectivamente alerto retiene bytes crudos (el muteado/whitelisteado/excluido no, ver 2.16), no todo el trafico capturado como hubiera ocurrido con el default anterior bajo el viejo esquema "guardar todo". El interruptor `raw_retention_enabled` sigue disponible para apagarlo (`store.py:3180-3202`, `POST /api/ai/config`). Cubierto por 905 tests backend pasando (incluye `tests/test_monitors.py::TestSnifferGatedPersistence` y la clase de Training/IA), y verificado en vivo contra `v0.58.0` y `v0.59.0` (`GET /api/ai/config` con `training_enabled`, `ai_alert_mode_enabled` y `raw_retention_enabled` en `true` simultaneamente en ambas instancias, reflejando el modo real).

### 2.15 High (empaquetado) - `.deb` inoperable si el Python del sistema no coincide con el de build

**Estado:** cerrado.

**Evidencia:** `scripts/build_deb.sh` vendoriza dependencias compiladas (p. ej. `regex`, con extension nativa `_regex.cpython-<abi>-*.so`) usando el Python que ejecuta el script de build; el wrapper instalado (`scripts/deb_wrapper.sh`) siempre corre con `/usr/bin/python3` del equipo destino. Si ambos Python difieren en ABI (por ejemplo build en 3.12, instalacion en 3.14), la extension nativa no carga y Python lo reporta como un import circular (`cannot import name '_regex' from partially initialized module 'regex'`) en vez de un mensaje claro de incompatibilidad - `sniff4hound` no arrancaba en absoluto, incluida la primera linea del banner. `scripts/deb_postinst.sh` ahora detecta el mismatch en `configure` (`import regex._regex` contra el Python real del equipo) y reconstruye `regex` para ese interprete dentro de un venv temporal descartable, copiando solo el paquete construido al `vendor/` del sensor - sin invocar `pip` del sistema como root ni tocar site-packages del sistema. `scripts/deb_postrm.sh` limpia `/usr/lib/sniff4hound` completo (incluidos los `__pycache__` que dpkg no rastreaba) en `remove`/`purge`, evitando que reinstalaciones/rebuilds dejen residuos huerfanos entre versiones.

**Nota informativa:** el self-heal de `deb_postinst.sh` descarga `regex` desde PyPI via `pip` dentro del venv temporal durante la instalacion del paquete (como root, solo cuando hay mismatch de ABI) - riesgo de cadena de suministro estandar de cualquier instalacion por `pip`, mitigado por la verificacion de integridad propia de `pip`/PyPI (TLS + hashes de paquete) y por acotarse a un venv descartable que nunca se mezcla con site-packages del sistema. No requiere accion adicional, se documenta por transparencia.

### 2.16 Low - Trafico muteado/whitelisteado/excluido retenia bytes crudos por el nuevo default global

**Estado:** cerrado.

**Evidencia:** `SniffStore.register_packet()` ahora acepta `allow_raw_retention` (default `True`, no rompe otros llamadores); cuando es `False` fuerza `payload_hex=""`/`raw_packet=None` sin importar el flag global `get_raw_retention_enabled()` (`store.py:4707-4716`). `Sniffer._store_packet()` calcula `is_alert = bool(monitor_hits)` y llama `register_packet(packet, allow_raw_retention=is_alert)` (`sniffer.py:1325-1334`): el trafico persistido solo por estar muteado/whitelisteado/excluido (`detection_muted`, sin `is_alert`) nunca retiene bytes crudos, independientemente de que `raw_retention_enabled` este encendido globalmente; el trafico que si alerto sigue reteniendolos cuando el flag esta activo, que es la motivacion original del default (ver 2.14). Cubierto por `tests/test_monitors.py::TestSnifferGatedPersistence::test_muted_traffic_never_retains_raw_bytes_even_with_global_retention_on`, que fija `payload_hex`/`raw_packet` no vacios en el paquete de entrada, lo persiste via una regla de exclusion (sin alerta), y verifica que la fila guardada tiene ambos campos vacios pese a que `get_raw_retention_enabled()` es `True` por defecto.

### 2.17 Low - Ruta `/chat` del vue-router faltaba en `SPA_ROUTES` (404 en refresh/deep-link)

**Estado:** cerrado.

**Detalle del hallazgo:** encontrado al ejecutar por primera vez un pase visual automatizado real (ver 3.4) contra las 14 vistas actuales del router (`frontend/src/router/index.js`), en vez de solo relectura de codigo. `/chat` es una ruta real del router (`ChatView.vue`), pero no estaba en la tupla `SPA_ROUTES` de `app.py` que decide que rutas reciben el `index.html` de la SPA en vez de un 404 (`app.py:1613-1780`, comentario en `app.py:130-135`: "Every path vue-router can land on has to be served index.html too... /settings, /domains, /paths and /ips were missing and did exactly that" - `/chat` quedo fuera de esa correccion anterior). Impacto: sin JavaScript corriendo aun (primera carga de esa URL), un refresh (F5), un marcador o un link de `/chat` pegado en un ticket devolvia `404 Not Found` en texto plano en vez de la SPA; navegar ahi *dentro* de la app (via el router del lado del cliente) funcionaba normal, por lo que el defecto solo era visible en carga directa/dura de esa URL. Sin impacto de seguridad (no expone nada, no evita ningun guard) - se clasifica Low por ser un defecto funcional real de navegacion.

**Evidencia de correccion:** se agrego `"/chat"` a `SPA_ROUTES` (`app.py:136-167`). Verificado con `app.dispatch()` directo: `GET /chat` devuelve `200` con el HTML de la SPA (antes devolvia `404`). Se agrego ademas una prueba de regresion que impide que esto vuelva a pasar con una vista futura: `tests/test_smoke.py::SmokeTests::test_every_vue_router_path_is_in_spa_routes` parsea `frontend/src/router/index.js`, extrae cada ruta estatica sin `redirect`, y falla si alguna no esta en `app.SPA_ROUTES`.

### 2.18 Low - Trafico muteado/whitelisteado/excluido aparecia en la cola de revision de IA sin nada que analizar

**Estado:** cerrado.

**Detalle del hallazgo:** reportado por el operador con una captura del review de IA (`Revisar / Ensenar`) mostrando registros UDP con "Sin bytes disponibles" y "Prioridad -/100" (`LOF -`, `Neuronal -`). `SniffStore.list_ai_packets()` devolvia las ultimas N filas de `packets` sin distinguir por que se habian persistido; desde el rediseno de persistencia (2.14) y el cierre de 2.16, el trafico muteado/whitelisteado/excluido persiste (para no perder visibilidad de captura) pero nunca se evalua y nunca retiene bytes crudos - no tiene absolutamente nada que el clasificador pueda puntuar. `packet_ai.analyze_packets()` procesa cada fila que recibe sin filtrar por `ai_detection_status`, asi que ese trafico llegaba igual a la cola de revision como ruido puro, sin valor para el operador que intenta ensenarle a la IA.

**Evidencia de correccion:** `list_ai_packets()` ahora filtra las filas con `details_json.ai_detection_status == "muted"` antes de aplicar el limite de 200 (`store.py:1919-1949`), ampliando la ventana de sobre-fetch (`400`/`1000` filas segun haya filtros de exclusion activos) para que ese descarte no reduzca artificialmente el conjunto realmente revisable. La consulta por `packet_id` explicito (detalle de un paquete puntual) no se filtra, solo el listado de exploracion/revision. Cubierto por `tests/test_monitors.py::TestSnifferGatedPersistence::test_muted_traffic_is_excluded_from_the_ai_review_queue`, que persiste un paquete muteado y uno con alerta real en la misma corrida y verifica que solo el segundo aparece en `list_ai_packets()`.

### 2.19 Info (cambio de diseno) - Whitelistear una IP desde el popup del grafo ahora borra su historial y deja de rastrearla

**Estado:** implementado, verificado.

**Detalle:** a pedido explicito del operador, el mapa de relaciones IP (ahora tambien en el Dashboard, primero antes de "Alertas y detecciones IA") gano un popup por nodo con metricas (hits, confianza, ambito, primera/ultima vez, evidencia de `infer_device_profile()`) y dos acciones: **Bloquear** (usa el `/api/blacklist/` ya existente sin cambios de comportamiento) y **Whitelist (borra historial)**, deliberadamente mas fuerte que un whitelist normal:

- `Sniffer._store_packet()` ahora resuelve `_whitelisted(packet)` **antes** de evaluar nada; si coincide, el paquete se descarta igual que trafico limpio - nunca llega a `INSERT` (`sniffer.py:1259-1273`). Antes, whitelistear solo silenciaba alertas; el paquete se seguia guardando sin tags (mismo contrato que exclusion/mute, que sigue intacto para esas dos categorias - ver `ExcludedTrafficPipelineTests`).
- `SniffStore.purge_ip_data(ip)` (nuevo) borra `packets`/`tags`/`payloads`/`flows`/`domains`/`paths` donde la IP es origen o destino (`store.py`, junto a `clear_detections`). A diferencia de `clear_detections`, si toca `flows`/`domains`/`paths`: es una accion dirigida a "olvidar este host", no una limpieza de ruido detras de una re-configuracion de monitores.
- `POST /api/whitelist/ip` (nuevo) exige `{"confirm": true}` para borrar; sin el, solo devuelve cuantos paquetes se borrarian (`store.count_ip_packets`), para que el frontend pida confirmacion real con una cifra real antes de actuar - la accion es irreversible.
- El popup pide esa confirmacion con `window.confirm()` nombrando la cantidad exacta de paquetes antes de la segunda llamada con `confirm: true`.

**Verificado:** `tests/test_blacklist.py` (`TestWhitelistIpEndpoint`, `test_whitelisted_ip_traffic_is_not_persisted_at_all`, `test_whitelist_port_and_protocol_suppress_persistence`, `test_purge_ip_data_removes_only_that_ips_rows`) y un pase visual real con navegador headless: click en un nodo abre el popup con las metricas correctas, "Bloquear" crea la entrada de blacklist end-to-end (confirmado via `GET /api/blacklist/?category=ip`), y con 60+ vecinos la lista se acota a 12 (+"N mas") para que los botones de accion nunca queden fuera de vista - un defecto que el propio pase visual encontro y se corrigio en el momento (`ip-graph-popup__body` con `max-height`/scroll, `visibleNeighbors`/`hiddenNeighborCount`).

**Por que Info y no un hallazgo de severidad:** es un cambio de diseno pedido explicitamente, no un defecto encontrado por la auditoria; se documenta aqui por su impacto en la politica de retencion de datos (relevante para el resto de este informe), no porque haya algo que cerrar.

---

## 3. QA dinamico contra instancia local

### 3.1 `v0.52.0` (pasada anterior)

La instancia revisada mostro banner de `SNIFF4HOUND v0.52.0`, con autenticacion habilitada y servidor en `127.0.0.1:45678`. No se registra aqui el codigo de seguridad.

Pruebas ejecutadas:

- `GET /api/auth/session` con credencial valida: **200**, `authenticated: true`, `security_code_length: 8`, `ws_auth_close_code: 4401`.
- `POST /api/runtime/` con credencial valida pero `Origin: http://evil.example`: **403**, `code: bad_origin`.
- `POST /api/ws/ticket` con credencial valida: **200**, respuesta con ticket de un solo uso y `expires_in: 15`.

### 3.2 `v0.58.0` (pasada anterior, mismo dia)

Instancia arrancada por el operador desde el `.deb`, banner `SNIFF4HOUND v0.58.0`, autenticacion requerida, servidor en `127.0.0.1:45678`. No se registra aqui el codigo de seguridad.

Pruebas ejecutadas:

- `GET /api/dashboard/` sin credencial: **401**, `code: auth_required`.
- `GET /` sin credencial: **200** (la SPA carga; el gate de auth vive en la API/WS, no en el estatico).
- `POST /api/runtime/` sin credencial y con `Origin: http://evil.example`: **401** (el guard de auth corre antes que el de origen).
- `GET /api/auth/session` con credencial valida: **200**, `authenticated: true`.
- `POST /api/runtime/` con credencial valida pero `Origin: http://evil.example`: **403**, `code: bad_origin` - confirma que el guard de origen tambien corre para una sesion ya autenticada, no solo para anonimos.
- `GET /api/ai/config` con credencial valida: **200**, `{"sampling_enabled":true,"training_enabled":true,"ai_alert_mode_enabled":true,"raw_retention_enabled":true,...}` - refleja el modo real de esa instancia (Monitors + IA + retencion de bytes crudos, los tres activos a la vez) y confirma que el endpoint expone el estado actual de la nueva politica de retencion (ver 2.14).

No se repitio en esta pasada una navegacion completa de las 14 vistas del frontend; la ultima navegacion completa documentada en el FAQA anterior correspondia a `v0.51.0` y no debe usarse como garantia visual de `v0.58.0`.

### 3.3 `v0.59.0` (esta pasada - reverificacion completa)

Instancia arrancada por el operador (`sniff4hound`), banner `SNIFF4HOUND v0.59.0`, autenticacion requerida, servidor en `127.0.0.1:45678`. No se registra aqui el codigo de seguridad.

Pruebas ejecutadas (mismo guion que 3.2, repetido para confirmar ausencia de regresion tras el cambio de version):

- `GET /` sin credencial: **200**.
- `GET /api/dashboard/` sin credencial: **401**.
- `POST /api/runtime/` sin credencial y con `Origin: http://evil.example`: **401** - el guard de auth sigue corriendo antes que el de origen.
- `GET /api/auth/session` con credencial valida: **200**, `authenticated: true`.
- `POST /api/runtime/` con credencial valida pero `Origin: http://evil.example`: **403**, `code: bad_origin`.
- `POST /api/ws/ticket` con credencial valida: **200**, ticket de un solo uso, `expires_in: 15`.
- `GET /api/ai/config` con credencial valida: **200**, `training_enabled`, `ai_alert_mode_enabled` y `raw_retention_enabled` en `true` simultaneamente - mismo estado que en `v0.58.0`, sin regresion.

Ademas de las pruebas dinamicas, en esta pasada se ejecuto la suite completa como parte de la revision (no solo se leyo el codigo):

- Backend: `python3 -m pytest tests/` -> **905 passed, 2 skipped, 310 subtests passed**.
- Frontend: `npm run lint` -> **0 warnings/errores**; `npm run test:unit` -> **13/13**; `npm run build` -> compila sin errores.

No se repitio en esta pasada una navegacion completa de las 14 vistas del frontend; sigue pendiente como punto informativo (ver seccion 5).

### 3.4 Pase visual automatizado de las 14 vistas (cierre del punto informativo pendiente)

`scripts/qa_ui_cdp.js` (el unico script de pase visual que existia en el repo) resulto estar escrito para una version anterior de la UI - navega a `/ports`, `/banners`, `/catalog`, `/explorer`, `/agents`, `/charts`, `/map`, `/tags` (una consola de gestion del honeypot con targets/puertos/banners) que ya no existe como tal; ese layout se reemplazo por las 14 vistas actuales (Dashboard, Sniffer, Honeypot, SOC, IA, Investigate, Protocols, Domains, Paths, IPs, Monitors, Settings, Chat, Radar). Correrlo hoy habria producido un reporte enganoso, no una verificacion real.

Se escribio `scripts/qa_visual_pass.js` (nuevo, no reemplaza al anterior): conecta por CDP a un Chromium headless, navega cada una de las 14 rutas reales del router actual con el codigo de sesion en la URL (`?code=...`, igual que el link que imprime el banner de arranque), y por cada una registra titulo, si el arbol `#app`/`.v-application` monto, excepciones de JS y errores de consola durante esa carga. No siembra ni modifica datos (a diferencia de `qa_ui_cdp.js`, que si hacia acciones de escritura sobre targets del honeypot).

**Resultado de la primera corrida real:** 13 de 14 vistas cargaron limpias (sin excepciones ni errores de consola): Dashboard, Sniffer, Honeypot, SOC, IA, Investigate, Protocols, Domains, Paths, IPs, Monitors, Settings, Radar. **Chat fallo**: la navegacion directa a `/chat` devolvio un `404 Not Found` de texto plano del backend en vez de la SPA - hallazgo nuevo, documentado y cerrado en 2.17. Tras la correccion, se verifico con `app.dispatch()` que `GET /chat` devuelve `200` con el HTML de la SPA.

Con esto, el punto informativo pendiente de pasadas anteriores (repetir una revision de las 14 vistas) queda resuelto por primera vez con una herramienta automatizada y vigente para la UI actual, en vez de quedar como deuda. Sigue habiendo una diferencia deliberada de alcance: esto verifica que cada vista monta sin excepciones/errores de consola, no una revision de diseno visual pixel a pixel (ver 5.8).

---

## 4. Confirmado correcto en la revision actual

- **Auth/API:** rutas API y docs quedan envueltas por `_apply_api_auth_guards()` salvo `/api/auth/session`; errores de validacion se devuelven como JSON 400/404 en vez de 500 genericos (`app.py:3153-3207`).
- **CSRF/origen:** mutaciones cross-origin con `Origin`/`Referer` externo se bloquean (`app.py:888-906`).
- **WebSocket:** no usa el token largo en la query; usa ticket corto, atado al cliente y de un solo uso (`app.py:1037-1068`).
- **Frontend auth:** el token de URL se limpia con `history.replaceState()` tras leerlo (`appStore.js:120-147`) y se conserva solo en memoria (`appStore.js:210-221`); las claves legacy de `localStorage`/`sessionStorage` se leen una vez y se borran de inmediato (`appStore.js:149-198`).
- **Redaccion textual:** payload, resumen y banner pasan por `redact_sensitive_text()` antes de persistirse (`store.py:4661-4663`).
- **Retencion de bytes crudos:** `payload_hex`/`raw_packet`/`frame_hex` se guardan por defecto ahora (`settings.py:327-330`), pero solo para trafico que efectivamente alerto - el trafico muteado/whitelisteado/excluido persiste sin ellos, sin importar el flag global (ver 2.16); el trafico limpio ya no se guarda en absoluto, con o sin bytes (`sniffer.py:1325-1334`, `store.py:121-144`). El interruptor `raw_retention_enabled` sigue disponible para volver al comportamiento apagado (`store.py:3180-3202`).
- **Persistencia de paquetes:** solo se guarda trafico que alerto en alguno de los motores de deteccion (catalogo de reglas, anomalias, IA en "solo IA") o que esta explicitamente muteado/excluido; todo lo demas se evalua y se descarta sin `INSERT` (`sniffer.py:1314-1345`). Whitelisteado es la excepcion a esa excepcion: se descarta igual que trafico limpio, sin evaluarse siquiera (`sniffer.py:1259-1273`, ver 2.19).
- **Cola de revision de IA:** el trafico muteado/whitelisteado/excluido persiste (para no perder visibilidad de captura) pero no aparece en `list_ai_packets()` - no tiene nada que puntuar y solo ensuciaria la cola de "Revisar / Ensenar" (`store.py:1919-1949`, ver 2.18).
- **Honeypot:** politica de puertos sensibles centralizada y enforceada en el proceso listener (`honeypot_ports.py:261-309`, `honeypot.py:1315-1325`).
- **DoS TCP/UDP honeypot:** limite de concurrencia TCP y rate limiting UDP activos (`honeypot.py:1216-1266`, `honeypot.py:1944-1972`).
- **IA:** import de modelo valida forma, tipo, finitud y magnitud; operaciones internas validan dimensiones antes de usar pesos (`ai_learning.py:101-164`, `ai_learning.py:282-331`).
- **Logs:** queries sensibles redactadas y campos truncados para evitar fuga de tokens/log injection (`access_log.py:49-91`, `access_log.py:125-148`).
- **Empaquetado `.deb`:** el postinst reconstruye dependencias compiladas (`regex`) para el Python real del equipo destino si detecta mismatch de ABI, dentro de un venv descartable, sin tocar el Python del sistema (`scripts/deb_postinst.sh`); el postrm limpia el arbol de instalacion completo en `remove`/`purge` (`scripts/deb_postrm.sh`).
- **Rutas de la SPA:** las 14 vistas del router de Vue tienen su contraparte en `app.SPA_ROUTES`, verificado tanto por un pase visual real con navegador (3.4) como por una prueba de regresion que compara ambas listas automaticamente (`tests/test_smoke.py::test_every_vue_router_path_is_in_spa_routes`).

---

## 5. Recomendaciones priorizadas

1. **[Cerrado]** El trafico persistido *solo* por estar muteado/whitelisteado/excluido (sin alerta real) ya nunca retiene bytes crudos, independientemente del interruptor global `raw_retention_enabled`; ver 2.16.
2. **[Cerrado]** Persistencia "guardar todo" durante Monitors/filtro apagado eliminada: solo se guarda lo que alerto (o esta muteado/excluido); ver 2.14.
3. **[Cerrado]** Retencion de bytes crudos ahora encendida por defecto, pero acotada a paquetes que realmente persisten (alerta o mute/whitelist/exclusion), no a todo el trafico capturado; sigue siendo alternable en caliente desde el Dashboard/API; ver 2.11, 2.14.
4. **[Cerrado]** `payload_hex`/`frame_hex` quedan ocultos en toda vista/API cuando `raw_retention_enabled` esta apagado; ver 2.11.
5. **[Cerrado]** El proceso falla temprano y de forma visible si falta la dependencia `regex`; ver 2.13.
6. **[Cerrado]** El `.deb` ya no queda inoperable si el Python del equipo destino no coincide con el usado para compilar el paquete (self-heal de `regex` en el postinst); ver 2.15.
7. **[Cerrado]** El codigo de seguridad del frontend ya no se persiste en ningun almacenamiento del navegador (modo in-memory-only); ver 2.12.
8. **[Cerrado]** Pase visual automatizado de las 14 vistas ejecutado por primera vez con una herramienta vigente para la UI actual (`scripts/qa_visual_pass.js`); encontro y cerro 2.17 (`/chat` devolvia 404 en carga directa); ver 3.4.
9. **[Info]** Repetir el pase de 3.4 (o una revision visual manual de diseno) antes de una release publica si el cambio incluye UI significativa - ese script verifica que cada vista monta sin excepciones/errores de consola, no una revision de diseno pixel a pixel.
10. **[Cerrado, sin accion]** `tests/test_monitors.py::TestTrainingAndAiAlertModes::test_training_plus_ai_mode_leaves_the_catalog_in_charge` fallo una vez en una corrida completa de esta pasada con `OSError: Directory not empty` al limpiar un directorio temporal; paso en aislamiento y en una segunda corrida completa (`906 passed, 2 skipped`, sin ese fallo). Confirmado transitorio (condicion de carrera de teardown bajo carga, no relacionada con los cambios de esta pasada) - no requiere accion salvo que reaparezca.
11. **[Cerrado]** La cola de revision de IA ya no muestra trafico muteado/whitelisteado/excluido sin bytes ni puntaje - se filtra en `list_ai_packets()` sin dejar de persistirlo; ver 2.18.

---

## 6. Estado final de la auditoria

**Aprobado, con dos hallazgos nuevos encontrados y corregidos en la propia pasada (2.17, 2.18).** No hay bloqueadores Critical/High/Medium/Low abiertos. Se releyeron los 16 hallazgos historicos previos contra el codigo actual sin encontrar regresiones, y por primera vez se ejecuto de punta a punta el punto informativo que quedaba pendiente en las ultimas pasadas: un pase visual automatizado real de las 14 vistas (3.4), que encontro que `/chat` devolvia `404` en carga directa por faltar en `app.SPA_ROUTES` (2.17) - se corrigio en el momento y se agrego una prueba de regresion que ata ambas listas de rutas. Por separado, el operador reporto con una captura de pantalla que la cola de revision de IA mostraba trafico muteado/whitelisteado/excluido sin bytes ni puntaje (2.18); se corrigio filtrando ese trafico de `list_ai_packets()` sin dejar de persistirlo, con su propia prueba de regresion. Se corrio ademas la suite entera varias veces completas a lo largo de la pasada (906-911 tests backend segun el punto, 13 tests frontend, lint y build en todas; un fallo de teardown aislado en una corrida no se repitio en las demas - ver recomendacion 10) y las pruebas dinamicas de siempre contra la instancia real. Se agrego tambien, a pedido del operador, el rediseno del mapa de relaciones IP con whitelist-y-purga (2.19). El rediseno de la iteracion anterior sigue en pie: solo persiste trafico que alerto o esta muteado/excluido (2.14), ese trafico muteado/excluido nunca retiene bytes crudos aunque el default global este encendido (2.16), el `.deb` se autorepara ante un mismatch de Python (2.15), y el codigo de seguridad del frontend sigue viviendo solo en memoria durante la vida de la pestana (2.12). No queda ningun punto abierto en este informe.
