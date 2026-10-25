# Runtime

## Variables clave

| Variable | Default | Uso |
| --- | --- | --- |
| `SNIFF4HOUND_HOST` | `127.0.0.1` | Host de escucha de la app. |
| `SNIFF4HOUND_PORT` | `45678` | Override explicito del puerto HTTP principal; sin override, Sniff4Hound intenta `45678` primero. |
| `SNIFF4HOUND_MDNS` | `1` | Anuncios y resolución DNS-SD con `wsbuilder[mdns]`. `0` utiliza URLs por IP. |
| `SNIFF4HOUND_MDNS_HOST` | `sniff4hound-runtime-<id>.local` | Nombre estable por máquina para la API y el canal Electron/backend. Debe terminar en `.local`. |
| `SNIFF4HOUND_MOBILE_HOST` | `sniff4hound-<id>.local` | Nombre del stream móvil, usado en el QR y en el certificado TLS. Debe terminar en `.local` cuando mDNS está activado. |
| `SNIFF4HOUND_DB_PATH` | `Sniff4Hound.db` | Ruta de SQLite. |
| `SNIFF4HOUND_RUNTIME_MODE` | `sniffer` | Motor inicial. |
| `SNIFF4HOUND_MODE` | `sniffer` | Alias legado de `SNIFF4HOUND_RUNTIME_MODE`. |
| `SNIFF4HOUND_CAPTURE_AUTO_START` | `1` | Arranque automatico del motor. |
| `SNIFF4HOUND_CAPTURE_INTERFACES` | vacio | Interfaces activas para `sniffer`. |
| `SNIFF4HOUND_INTERFACE_VERIFY_SECONDS` | `0.5` | Ventana de observación, en segundos, tras reiniciar el sniffer por un cambio de interfaces. Se limita a `0`–`5`; valores inválidos, `NaN` e infinitos usan `0.5`. `0` omite la espera temporal y conserva el chequeo inmediato del estado y de las interfaces listas. Si el reinicio falla, se intenta restaurar la selección y la captura anteriores. |
| `SNIFF4HOUND_PROMISCUOUS` | `1` | Modo promiscuo en captura raw. |
| `SNIFF4HOUND_SNAPLEN` | `65535` | Tamano maximo del paquete capturado. |
| `SNIFF4HOUND_POLL_TIMEOUT` | `0.5` | Espera de polling en captura. |
| `SNIFF4HOUND_CAPTURE_BUFFER_BYTES` | `524288` | Buffer de captura. |
| `SNIFF4HOUND_STORE_RAW_PACKET` | `1` | Valor inicial de la retencion de `raw_packet`/`payload_hex` crudos para una base de datos que nunca la cambio desde el Dashboard/API - ver `raw_retention_enabled` mas abajo, que ahora se puede alternar en caliente. Solo importa para el trafico que ya alerto: el trafico limpio ya no persiste (ver mas abajo), asi que retener sus bytes por defecto no expone mas que antes. |
| `SNIFF4HOUND_FRONTEND_DIST` | auto | Sobrescribe el directorio compilado de la UI. |
| `SNIFF4HOUND_DECLARED_LATITUDE` | vacio | Latitud del sitio donde esta el sensor. Solo valor inicial: se ajusta desde Settings. |
| `SNIFF4HOUND_DECLARED_LONGITUDE` | vacio | Longitud del sitio donde esta el sensor. |
| `SNIFF4HOUND_DECLARED_LOCATION_LABEL` | vacio | Etiqueta legible del sitio (por ejemplo `Oficina central`). |
| `SNIFF4HOUND_DETECTION_EXCLUDE_SCOPES` | vacio | Ignora por completo el trafico interno a estos ambitos (`loopback`, `private`, `public`, separados por coma). Solo valor inicial: se ajusta en caliente desde Settings. |
| `SNIFF4HOUND_ACCESS_LOG` | `1` | Access log HTTP/WebSocket en la terminal, formato `combined` de nginx. `0` lo silencia. |
| `SNIFF4HOUND_ACCESS_LOG_COLOR` | `auto` | Color del codigo de estado: `auto` (solo en TTY), `always`, `never`. |

Sniff4Hound siempre requiere root para arrancar (captura de paquetes raw). No
existe ninguna variable de entorno para saltarse esto: si no corre como root,
intenta relanzarse con `sudo` y, si no puede, termina sin arrancar el
servidor e imprime el motivo por stderr.

## TLS del runtime

El runtime genera y gestiona su propia CA local; no acepta certificados
externos ni mTLS de cliente, y no hay variables para indicar un certificado o
una clave propios.

| Variable | Default | Uso |
| --- | --- | --- |
| `SNIFF4HOUND_TLS` | `1` | Sirve la API y el WebSocket por HTTPS/WSS. `0` vuelve a HTTP plano. |
| `SNIFF4HOUND_TLS_CERT_DAYS` | `1` | Validez del certificado de servidor, que se reemite en cada arranque. |
| `SNIFF4HOUND_TLS_CA_DAYS` | `365` | Validez de la CA local. Se reutiliza entre arranques y se renueva cuando le quedan menos de 30 días. |

Los ficheros viven en `<SNIFF4HOUND_DATA_DIR>/tls/`: `sniff4hound-ca.pem`/`.key`
(CA del runtime), `sniff4hound-server.pem`/`.key` (certificado de servidor
para el host de escucha y `SNIFF4HOUND_MDNS_HOST`) y la pareja
`sniff4hound-mobile-*` para el stream móvil. El cliente confía en la CA
pública (`sniff4hound-ca.pem`); las claves privadas nunca salen de ese
directorio.

## Variables con efecto en la seguridad

Estas variables relajan o desplazan una protección. Déjalas sin definir salvo
que entiendas y aceptes el riesgo descrito.

| Variable | Default | Uso | Riesgo |
| --- | --- | --- | --- |
| `SNIFF4HOUND_TRUST_FORWARDED_HEADERS` | `0` | `1` hace que la comprobación de mismo origen use `X-Forwarded-Host` y `X-Forwarded-Proto` en lugar de la cabecera `Host` real. Solo para un proxy inverso propio que reescriba esas cabeceras. | Sin un proxy que las sobrescriba, quien hace la petición controla los dos lados de la comparación de origen y anula la protección CSRF de las peticiones que cambian estado. El limitador de autenticación sigue usando siempre la dirección de transporte. |
| `SNIFF4HOUND_IPC_TOKEN_FILE` | vacío | Ruta a un fichero (modo `0600`) con el token del canal IPC entre el proceso web y el servicio de captura. Tiene prioridad sobre `SNIFF4HOUND_IPC_TOKEN`; el runtime lo usa para no pasar el secreto en la línea de comandos de `sudo`/`pkexec`, visible para cualquier usuario en `/proc/<pid>/cmdline`. | Quien pueda leer ese fichero puede hablar con el servicio de captura, que corre como root (arrancar/parar motores, cambiar interfaces). Debe pertenecer al operador, con permisos `0600`, y no estar en un directorio compartido. |
| `SNIFF4HOUND_DESKTOP_NO_SANDBOX` | sin definir | `1` arranca la ventana Electron con `--no-sandbox` en Linux aunque no se ejecute como root (como root ya se desactiva siempre). Solo para entornos donde el sandbox de Chromium no puede iniciarse. | Sin sandbox, una vulnerabilidad en el renderer de Chromium (por ejemplo a través de contenido mostrado por la UI) se ejecuta con todos los permisos del usuario del escritorio, en una ventana conectada a un runtime privilegiado. |

## Modos de activacion (Sniffer / Honeypot / Monitors)

- **Sniffer** y **Honeypot** son procesos de captura que se encienden y apagan
  desde el menu lateral o desde Configuracion.
- **Monitors** es el catalogo de reglas: solo el trafico que coincide con un
  monitor habilitado se guarda en la base de datos. Los monitores se activan
  o desactivan uno a uno en la pestaña Monitores.
- La retencion de bytes crudos la fija `SNIFF4HOUND_STORE_RAW_PACKET` al
  crear la base; no hay interruptor en la interfaz.

## Pipeline de paquetes (caché y jobs)

La captura ya no evalúa cada paquete dentro del hilo que lo lee. Cada hilo de
captura deposita el paquete en una caché acotada en memoria, y N jobs lo toman,
lo evalúan (monitores y anomalías) y persisten los que corresponden en
SniffStore.

- **Límite de retención** (`cache_limit`, 1.000-1.000.000, por defecto 20.000):
  paquetes que pueden esperar entre captura y procesamiento. Si la caché se
  llena se descartan los más antiguos y el contador `cache_dropped` lo registra.
- **Jobs** (`jobs`, 1-16, por defecto 2): workers que consumen la caché. Se
  aplica al iniciar la captura.
- **Persistencia** (`persist_mode`): `alerts` (por defecto) guarda solo lo que
  genera alerta, como antes; `all` guarda todo paquete procesado.

`GET`/`POST /api/pipeline/config` lee y guarda estos valores. `cache_limit` y
`persist_mode` se aplican a la captura en marcha; `jobs` al siguiente inicio.
El estado en vivo (`packet_pipeline` dentro del estado del sniffer) muestra:

- Caché: `cache_depth` (en espera), `cache_limit`, `cache_accepted`,
  `cache_dropped` (descartados por límite) y `cache_peak` (pico de ocupación).
- Jobs: `processed`, `persisted`, `skipped` (procesados sin alerta) y `errors`.
- `persist_mode` y `since` (desde cuándo se cuentan).

`POST /api/pipeline/reset` pone a cero los contadores (aceptados, descartados,
pico, procesados, persistidos, omitidos y errores) desde el inspector de cada
tarjeta. No cambia la configuración ni los paquetes en espera.

```bash
curl -X POST -H "X-Security-Code: $CODE" -H "Content-Type: application/json" \
  -d '{"cache_limit":40000,"jobs":4,"persist_mode":"alerts"}' \
  http://127.0.0.1:45678/api/pipeline/config
```

## Ubicacion del sensor y mapa

`GET`/`POST /api/settings/location` guarda donde esta fisicamente esta maquina.

```bash
curl -X POST -H "X-Security-Code: $CODE" -H "Content-Type: application/json" \
  -d '{"lat":23.1136,"lon":-82.3666,"label":"Oficina central"}' \
  http://127.0.0.1:45678/api/settings/location
```

Para que sirve: una direccion privada o de loopback no se puede geolocalizar
—no hay registro publico que consultar—, asi que el mapa del Radar las dibuja
todas en este punto. Las direcciones **publicas** conservan su propia
ubicacion, resuelta de los bloques asignados por los registros regionales
(libGeoIP a nivel de pais), y la ubicacion declarada nunca las sobrescribe.

Sin ubicacion declarada, los hosts locales sencillamente no se dibujan, que es
el comportamiento anterior. `{"clear": true}` la borra.

El mapa se puede fijar en proyeccion plana o de globo; el Radar arranca en
plana.

## Catalogo de bloques IP (RIR / NIC)

`sniff4hound/data/ip_registry.json` trae la asignacion de bloques a paises tal
como la publican los cinco registros regionales (AFRINIC, APNIC, ARIN, LACNIC
y RIPE NCC) en sus ficheros `delegated-*-extended-latest`. Es la fuente
autoritativa de la que derivan todas las bases GeoIP de nivel pais, y es
redistribuible.

Gracias a eso la geolocalizacion funciona sin depender de que haya libGeoIP y
una base de datos de pais instaladas en el sistema: antes, sin ellas, toda
direccion publica quedaba sin ubicar y el mapa se veia vacio. Si libGeoIP esta
presente se usa primero (algunas compilaciones traen datos de ciudad); el
catalogo empaquetado es el respaldo que siempre esta.

Cada direccion publica resuelve a codigo de pais, registro (`arin`, `ripencc`,
...) y region (`North America`, `Europe, Middle East & Central Asia`, ...). Las
direcciones privadas y de loopback no estan delegadas a nadie y no reciben pais.

Para regenerarlo tras una actualizacion de los RIR:

```bash
python scripts/build_ip_registry.py
```

## Filtro de deteccion por ambito de IP

`GET`/`POST /api/detection/scopes` controla para que trafico se ejecuta la
deteccion. Los ambitos son `loopback`, `private` y `public`; la lista vacia
(por defecto) significa detectar en todo.

```bash
curl -H "X-Security-Code: $CODE" http://127.0.0.1:45678/api/detection/scopes
curl -X POST -H "X-Security-Code: $CODE" -H "Content-Type: application/json" \
  -d '{"exclude_scopes":["loopback","private"]}' \
  http://127.0.0.1:45678/api/detection/scopes
```

Dos precisiones importantes:

- **El trafico excluido queda visible pero mudo.** Se guarda como captura y
  cuenta en las estadisticas, pero no se clasifica con rulesets, no recibe
  tags de deteccion, no pasa por monitores ni por detectores de anomalias.
  Asi el volumen real del enlace sigue visible sin generar alertas.
- **Tienen que coincidir los dos extremos.** Excluir `private` calla el
  trafico LAN-a-LAN, pero un host privado hablando con una direccion publica
  se sigue capturando y analizando: es justo lo que un analista quiere ver.

Una direccion que no se puede clasificar (por ejemplo ARP, que no lleva capa
IP) nunca silencia nada. El rango CGNAT `100.64.0.0/10` y los rangos de
documentacion cuentan como `private`, no como `public`: no son internet
routable.

## Access log

El proceso web imprime una linea por peticion servida en el formato
`combined` de nginx, con el tiempo de respuesta anadido al final
(equivalente a `$request_time`):

```text
127.0.0.1 - - [26/Aug/2026:14:27:41 -0300] "GET /api/runtime/?since=1h HTTP/1.1" 200 512 "-" "curl/8.5.0" 0.003
```

Campos, en orden: direccion del cliente, identidad (`-`), usuario (`-`),
fecha local con offset UTC, linea de peticion entre comillas, codigo de
estado, bytes del cuerpo, `Referer`, `User-Agent` y duracion en segundos.

Los handshakes de WebSocket se registran como lo que son a nivel HTTP, un
`101`, igual que hace nginx. El cierre se registra ademas como una
pseudo-peticion `WS` con el codigo de cierre y la duracion de la sesion,
para poder distinguir una conexion rechazada nada mas abrirse (por ejemplo
`close=4401`, token invalido) de una sesion sana que estuvo horas
transmitiendo:

```text
10.0.0.7 - - [26/Aug/2026:14:27:41 -0300] "GET /ws/?token=... HTTP/1.1" 101 0 "-" "Mozilla/5.0" 0.000
10.0.0.7 - - [26/Aug/2026:14:31:02 -0300] "WS /ws/ closed" 101 0 "-" "Mozilla/5.0" 201.418 close=1000
```

Antes de esto lo unico que la terminal imprimia sobre HTTP era la linea
`[http] handler error ...` de wsbuilder, que solo salta cuando una excepcion
se escapa de un handler: el trafico correcto, los 401, los 404 y todos los
upgrades de WebSocket eran invisibles.

## API de runtime

`GET /api/runtime/` devuelve un snapshot con el modo activo, los motores soportados y el estado de `sniffer` y `honeypot`.

`POST /api/runtime/` acepta combinaciones de estos campos:

- `mode`: `sniffer` o `honeypot`
- `action`: `start` o `stop`
- `interface`, `interfaces`, `sniffer_interface` o `sniffer_interfaces`

Ejemplos:

```bash
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:45678/api/runtime/

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"start"}'

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"honeypot","interfaces":["eth0"]}'
```

## Notas

- si `SNIFF4HOUND_CAPTURE_AUTO_START=0`, `start` solo devuelve estado;
- si cambias `mode`, el runtime detiene el motor anterior antes de activar el nuevo;
- `interfaces` se persistira en `runtime_config` para `sniffer`.
