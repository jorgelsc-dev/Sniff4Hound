# Arquitectura

`Sniff4Hound` se organiza alrededor de una superficie HTTP/WebSocket pequena, dos motores (`sniffer` y `honeypot`) y una base SQLite compartida.

## Vista general

```text
Operador / navegador
        |
        v
  sniff4hound.manage            (usuario normal, SIN privilegios)
        |
        +--> sniff4hound.app (App, API, WS, auth, SPA)
        |       |
        |       +--> SniffStore (SQLite)
        |       +--> frontend/dist + WebSocketHub
        |       +--> RuntimeControllerClient --+
        |                                      |
        |                              IPC Unix socket 0600
        |                                      |
        +--> sudo sniff4hound-capture <---------+   (root)
                 |
                 +--> RuntimeController --> Sniffer (AF_PACKET)
                                            HoneypotEngine (puertos <1024)
```

## Modelo de privilegios

El proceso web y la base de datos corren **siempre como el usuario que
invoca el comando, nunca como root**: `manage.main()` y `manage.main_web()`
comprueban `os.geteuid() == 0` y **abortan** si se les lanza con `sudo`. El
motivo es concreto: un `Sniff4Hound.db` creado por root deja de ser
escribible por cualquier ejecucion posterior sin privilegios, que falla con
"attempt to write a readonly database".

El privilegio vive unicamente en el proceso hijo `sniff4hound-capture`, que
es lo unico que necesita root (sockets raw `AF_PACKET` y bind de puertos
bajos del honeypot). `manage.py` lo lanza via `sudo` y habla con el por un
socket Unix local con permisos `0600` (`sniff4hound/ipc.py`,
`sniff4hound/capture_service.py`). El token compartido de ese canal viaja en
un fichero `0600` cuya **ruta** - nunca su contenido - se pasa al hijo, porque
`/proc/<pid>/cmdline` es legible por cualquier usuario local.

Si `sudo` no esta en el `PATH` o la elevacion falla, el proceso imprime un
error claro y termina sin arrancar: no hay variable de entorno para saltarse
la captura privilegiada.

## Arranque

1. `sniff4hound.manage` rechaza la ejecucion como root y resuelve `HOST` y `PORT`.
2. Si el puerto pedido esta ocupado, busca otro libre en el mismo bloque de 10 puertos.
3. Importa `sniff4hound.app` (y crea `SniffStore` como usuario normal) *antes* de lanzar el hijo, para ganar la carrera por la propiedad del fichero SQLite.
4. Escribe el token IPC en un fichero `0600` y lanza `sudo sniff4hound-capture`; si no puede elevar, termina sin arrancar el servidor.
5. Conecta al hijo por IPC, borra el fichero de token, imprime el token de sesion, arranca la consola interactiva y llama a `app.run(...)`.
6. `bootstrap_capture()` arranca el motor activo si el autoarranque sigue habilitado.

## `sniff4hound.app`

Responsabilidades:

- crear `App()` de `wsbuilder`;
- servir la SPA y los assets estaticos;
- exponer `/docs` y `/docs.json`;
- proteger la API y `WS /ws/` con auth;
- coordinar `Sniffer`, `HoneypotEngine`, `SniffStore` y `WebSocketHub`;
- persistir modo de runtime e interfaces seleccionadas.

Piezas clave:

- `RuntimeController`: decide si el motor activo es `sniffer` o `honeypot`.
- `WebSocketHub`: registra clientes, emite eventos y gestiona `ping` / `close`.
- `_apply_api_auth_guards()`: envuelve todas las rutas API salvo `GET /api/auth/session`.

## `sniff4hound.sniffer`

Responsabilidades:

- descubrir interfaces disponibles;
- abrir un socket raw por interfaz activa;
- parsear Ethernet, VLAN, IPv4, IPv6, ARP, TCP, UDP, ICMP, ICMPv6 y STP;
- actualizar contadores de captura;
- emitir eventos `packet` y `stats_update`;
- escribir paquetes y flows en SQLite.

Modelo:

- un hilo por interfaz;
- `RLock` para estado y contadores;
- `snapshot()` entrega estado utilizable por UI y API.

## `sniff4hound.honeypot`

Responsabilidades:

- abrir listeners TCP/UDP en puertos comunes;
- responder con banners y payloads predefinidos;
- registrar sesiones como trafico `honeypot`;
- escribir actividad operativa en `honeypot.log`.

Detalles utiles:

- reutiliza `SniffStore`;
- marca filas con interfaces `honeypot` o `honeypot:<port>`;
- permite estudiar el mismo dashboard con datos pasivos o activos.

## `sniff4hound.store`

Es la fuente de verdad local.

Tablas principales:

- `sessions`
- `flows`
- `packets`
- `payloads`
- `tags`
- `rulesets`
- `runtime_config`

Funciones practicas:

- `dashboard_snapshot()`
- `analytics_snapshot()`
- `map_snapshot()`
- `soc_analysis_snapshot()`
- `endpoint_catalog()`

La conexion usa:

- `journal_mode=WAL`
- `synchronous=NORMAL`
- `foreign_keys=ON`
- `busy_timeout=5000`

## Auth

`sniff4hound.auth` mezcla dos mecanismos:

- token de sesion ("security code") de 8 caracteres generado al arranque e impreso en el banner;
- JWT HS256 creado con `generate_token()`, para integraciones.

Entradas aceptadas:

- `Authorization: Bearer ...`
- `X-Security-Code`
- `X-Access-Token`
- `security_code`, `access_token`, `token` o `auth` en query string
  (**solo** en el handshake de `WS /ws/`, no en HTTP plano)

Firma de los JWT:

- no existe ningun secreto por defecto en el codigo. Si `SNIFF4HOUND_JWT_SECRET`
  no esta definido, se genera uno por instalacion con `secrets.token_hex(32)`
  y se persiste con permisos `0600` en `SNIFF4HOUND_DATA_DIR/jwt_secret`; si no
  se puede escribir, se usa uno efimero en memoria, distinto en cada arranque;
- la clave de firma se *deriva* del secreto y de `JWT_KEY_VERSION`, y su `kid`
  viaja en la cabecera: rotar el secreto (o subir la version) invalida de golpe
  todos los tokens emitidos;
- `decode_jwt()` valida firma, `alg`, `kid`, `iss`, `aud`, `nbf`, `exp` y la
  lista de `jti` revocados; `expires_in` esta acotado por
  `SNIFF4HOUND_JWT_MAX_TTL`.

Efectos:

- si `SNIFF4HOUND_REQUIRE_AUTH=1`, todas las rutas API protegidas devuelven `401` sin token valido;
- cada `401` se registra en el log de seguridad con la IP de origen, y se cuenta
  contra un limitador por IP con ventana deslizante y backoff incremental
  (`auth.AuthRateLimiter`); superado el umbral la respuesta pasa a `429` con
  `Retry-After`;
- `WS /ws/` se cierra con codigo `4401` cuando la autenticacion falla;
- `GET /api/auth/session` queda abierto para que la UI sepa si debe pedir token,
  pero aplica el mismo limitador cuando se le presenta un token invalido.

## Frontend

La SPA:

- consulta `/api/auth/session` para validar el token;
- lee `/api/runtime/` para modo e interfaces;
- consume `/api/dashboard/`, `/api/charts/analytics`, `/api/map/scan` y `/api/endpoints/`;
- abre `WS /ws/?access_token=...` para eventos live;
- actualiza tablas y vistas en respuesta a `packet`, `stats_update`, `runtime_mode` y `chat_message`.

## Rutas mas importantes

- `GET /`
- `GET /docs`
- `GET /docs.json`
- `GET /api/auth/session`
- `GET|POST /api/runtime/`
- `GET /api/dashboard/`
- `GET /api/soc/analysis/`
- `GET|DELETE /ports/` y variantes
- `GET|DELETE /banners/`
- `GET /tags/`
- `GET|POST /api/catalog/*`
- `GET /api/export/` y `GET /api/export/{alerts,endpoints,flows,domains}?format=csv|json`
- `WS /ws/`

## `sniff4hound.export`

Convierte cuatro listados existentes de `store.py` en filas planas con forma
de IOC (regla, severidad, 5-tupla, dominio, evidencia, hit_count, primera y
ultima vez) y las serializa con el modulo `csv` de la stdlib. Los hits
repetidos de un mismo monitor se agrupan en un unico indicador en vez de una
fila por paquete. Las vistas SOC e Investigate lo exponen desde su boton
"Export".

## Apagado

`shutdown_capture()`:

- detiene el motor activo;
- intenta detener tambien `sniffer` y `honeypot`;
- cierra WebSocketHub;
- cierra SQLite.

Eso deja el runtime limpio cuando terminas la sesion o interrumpes con `Ctrl+C`.
