# Sniff4Hound - Informe de QA / Auditoria de Seguridad (FAQA)

**Rol:** Revision realizada como QA Lead / analista SOC especializado en sniffers, honeypots y motores de IA de deteccion.
**Alcance:** Rama `feature/faqa`, backend `sniff4hound/*.py`, frontend `frontend/src/**`, pruebas relacionadas y verificacion puntual contra una instancia local real en ejecucion (`v0.52.0`, `http://127.0.0.1:45678`).
**Metodo:** Relectura estatica dirigida de autenticacion, CSRF/origin checks, WebSocket, almacenamiento, redaccion, sniffer, honeypot, IA y frontend; contraste contra los hallazgos historicos del FAQA anterior; y pruebas dinamicas puntuales sobre la instancia viva. Los codigos de seguridad usados en la prueba no se documentan aqui.
**Fecha:** 2026-09-13.

> Convencion de severidad: **Critical** (explotable remotamente / caida del sensor) | **High** (bypass relevante de un limite de seguridad) | **Medium** (riesgo real o gap de defensa en profundidad) | **Low** (mejora menor) | **Info** (limitacion o comportamiento aceptado).

---

## 0. Resumen ejecutivo

- **No quedan hallazgos Critical, High, Medium ni Low abiertos** en la revision actual de `v0.52.0`.
- Los hallazgos criticos/altos del reporte anterior estan mitigados: ReDoS por regex, politica de puertos del honeypot, validacion de import de IA, rate limiting UDP, tickets WebSocket de un solo uso, guard CSRF por origen, limite de concurrencia TCP del honeypot, truncado/redaccion de access log y lock de arranque IPC.
- La instancia local respondio correctamente a pruebas dinamicas sensibles: sesion autenticada `200`, `POST` cross-origin bloqueado con `403 bad_origin`, y emision de ticket WS autenticado con TTL corto (`expires_in: 15`).
- Los tres hallazgos que este mismo informe reportaba como abiertos (retencion de bytes crudos, `sessionStorage` legible por JS, y timeout de regex opcional) ya estan implementados y verificados con tests: la retencion de `payload_hex`/`raw_packet` es opt-in por configuracion, el token de sesion del frontend vive solo en memoria (no se persiste en `localStorage` ni `sessionStorage`), y el modulo `regex_safety` ahora falla explicitamente al importar si la dependencia `regex` no esta instalada en vez de degradar en silencio.
- El cambio pedido por PR #76 queda reflejado como cerrado: el frontend ya no persiste el codigo de seguridad en ningun almacenamiento del navegador; lo conserva solo en memoria durante la vida de la pestana.

---

## 1. Hallazgos abiertos actuales

Ninguno. Los tres puntos que esta auditoria habia dejado abiertos (1.1-1.3 en la version anterior de este informe) se corrigieron y se movieron a la seccion 2 (`Hallazgos historicos cerrados`) como 2.11-2.13, con su evidencia de codigo y de tests.

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

**Estado:** cerrado para almacenamiento persistente; queda el riesgo Low de `sessionStorage` descrito en 1.2.

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

---

## 3. QA dinamico contra instancia local v0.52.0

La instancia revisada mostro banner de `SNIFF4HOUND v0.52.0`, con autenticacion habilitada y servidor en `127.0.0.1:45678`. No se registra aqui el codigo de seguridad.

Pruebas ejecutadas:

- `GET /api/auth/session` con credencial valida: **200**, `authenticated: true`, `security_code_length: 8`, `ws_auth_close_code: 4401`.
- `POST /api/runtime/` con credencial valida pero `Origin: http://evil.example`: **403**, `code: bad_origin`.
- `POST /api/ws/ticket` con credencial valida: **200**, respuesta con ticket de un solo uso y `expires_in: 15`.

No se repitio en esta pasada una navegacion completa de las 14 vistas del frontend; la navegacion completa documentada en el FAQA anterior correspondia a `v0.51.0` y no debe usarse como garantia visual de `v0.52.0`.

---

## 4. Confirmado correcto en la revision actual

- **Auth/API:** rutas API y docs quedan envueltas por `_apply_api_auth_guards()` salvo `/api/auth/session`; errores de validacion se devuelven como JSON 400/404 en vez de 500 genericos (`app.py:3153-3207`).
- **CSRF/origen:** mutaciones cross-origin con `Origin`/`Referer` externo se bloquean (`app.py:888-906`).
- **WebSocket:** no usa el token largo en la query; usa ticket corto, atado al cliente y de un solo uso (`app.py:1037-1068`).
- **Frontend auth:** el token de URL se limpia con `history.replaceState()` tras leerlo (`appStore.js:120-147`) y se conserva solo en memoria (`appStore.js:210-221`); las claves legacy de `localStorage`/`sessionStorage` se leen una vez y se borran de inmediato (`appStore.js:149-198`).
- **Redaccion textual:** payload, resumen y banner pasan por `redact_sensitive_text()` antes de persistirse (`store.py:4661-4663`).
- **Retencion de bytes crudos:** `payload_hex`/`raw_packet`/`frame_hex` no se guardan ni se sirven salvo opt-in explicito por configuracion (`settings.py:324-330`, `store.py:121-144`).
- **Honeypot:** politica de puertos sensibles centralizada y enforceada en el proceso listener (`honeypot_ports.py:261-309`, `honeypot.py:1315-1325`).
- **DoS TCP/UDP honeypot:** limite de concurrencia TCP y rate limiting UDP activos (`honeypot.py:1216-1266`, `honeypot.py:1944-1972`).
- **IA:** import de modelo valida forma, tipo, finitud y magnitud; operaciones internas validan dimensiones antes de usar pesos (`ai_learning.py:101-164`, `ai_learning.py:282-331`).
- **Logs:** queries sensibles redactadas y campos truncados para evitar fuga de tokens/log injection (`access_log.py:49-91`, `access_log.py:125-148`).

---

## 5. Recomendaciones priorizadas

1. **[Cerrado]** Politica de retencion de bytes crudos: `SNIFF4HOUND_STORE_RAW_PACKET` (`0` por defecto) decide si se conservan `payload_hex`/`raw_packet`; ver 2.11.
2. **[Cerrado]** `payload_hex`/`frame_hex` quedan ocultos en toda vista/API salvo que se active explicitamente el modo forense por configuracion; ver 2.11.
3. **[Cerrado]** El proceso falla temprano y de forma visible si falta la dependencia `regex`; ver 2.13.
4. **[Cerrado]** El codigo de seguridad del frontend ya no se persiste en ningun almacenamiento del navegador (modo in-memory-only); ver 2.12.
5. **[Info]** Repetir una pasada visual completa de las vistas principales en `v0.52.0` antes de una release publica si el cambio incluye UI significativa.

---

## 6. Estado final de la auditoria

**Aprobado.** No hay bloqueadores Critical/High/Medium/Low abiertos. La aplicacion esta en buen estado para uso local autenticado: la base de datos ya no retiene bytes crudos de paquetes salvo opt-in explicito para uso forense/IA, y el codigo de seguridad del frontend vive solo en memoria durante la vida de la pestana. Queda como unico punto informativo repetir la pasada visual completa de las 14 vistas en `v0.52.0` antes de una release con cambios de UI significativos.
