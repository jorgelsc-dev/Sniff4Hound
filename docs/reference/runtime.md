# Runtime

## Variables clave

| Variable | Default | Uso |
| --- | --- | --- |
| `SNIFF4HOUND_HOST` | `127.0.0.1` | Host de escucha de la app. |
| `SNIFF4HOUND_PORT` | `45678` | Override explicito del puerto HTTP principal; sin override, Sniff4Hound intenta `45678` primero. |
| `SNIFF4HOUND_DB_PATH` | `Sniff4Hound.db` | Ruta de SQLite. |
| `SNIFF4HOUND_RUNTIME_MODE` | `sniffer` | Motor inicial. |
| `SNIFF4HOUND_MODE` | `sniffer` | Alias legado de `SNIFF4HOUND_RUNTIME_MODE`. |
| `SNIFF4HOUND_DEBUG` | `1` | Activa el modo debug de la app. |
| `SNIFF4HOUND_CAPTURE_AUTO_START` | `1` | Arranque automatico del motor. |
| `SNIFF4HOUND_CAPTURE_INTERFACES` | vacio | Interfaces activas para `sniffer`. |
| `SNIFF4HOUND_PROMISCUOUS` | `1` | Modo promiscuo en captura raw. |
| `SNIFF4HOUND_SNAPLEN` | `65535` | Tamano maximo del paquete capturado. |
| `SNIFF4HOUND_POLL_TIMEOUT` | `0.5` | Espera de polling en captura. |
| `SNIFF4HOUND_CAPTURE_BUFFER_BYTES` | `524288` | Buffer de captura. |
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

- **El trafico excluido sale del pipeline por completo.** No se clasifica con
  los rulesets, no se etiqueta, no pasa por monitores ni por los detectores de
  anomalias, y no se guarda — tampoco con la opcion de "guardar todo el
  trafico" activada. Los contadores de paquetes vistos si lo cuentan: la trama
  cruzo el cable de verdad, y ocultarla haria que las estadisticas de captura
  mintieran sobre el volumen del enlace.
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
