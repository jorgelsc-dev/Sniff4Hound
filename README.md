# Sniff4Hound

`Sniff4Hound` es un capturador y analizador de trafico en Python nativo. Usa `socket`, `threading`, `sqlite3` y `wsbuilder` para servir una UI/API local. El `sniffer` y el `honeypot` son motores independientes: puedes ejecutar ninguno, uno o los dos a la vez.

Sitio oficial: [https://sniff4hound.jorgelsc.dev](https://sniff4hound.jorgelsc.dev)<br>
Repositorio: [https://github.com/jorgelsc-dev/Sniff4Hound](https://github.com/jorgelsc-dev/Sniff4Hound)<br>
Artefacto oficial: paquete Debian `.deb` en GitHub Releases<br>
Comando: `sniff4hound`

## Autoria, licencia y proteccion

- Autor y mantenedor principal: `JorgelSC Dev`
- Licencia del codigo: `MIT`
- Aviso legal y de identidad del proyecto: [`NOTICE`](NOTICE)
- Reglas de contribucion y trazabilidad: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Politica de seguridad y manejo responsable: [`SECURITY.md`](SECURITY.md)
- Gobernanza y protecciones del repositorio: [`docs/governance.md`](docs/governance.md)

Punto importante:

- La licencia MIT concede permisos sobre el codigo del repositorio, pero no concede derechos de marca sobre el nombre `Sniff4Hound`, sus logos, ni el dominio oficial.
- Las contribuciones humanas deben llevar `Signed-off-by:` y completar la declaracion de autoria/procedencia en cada PR.
- `CODEOWNERS` y el workflow `contribution-guard` refuerzan la revision y la trazabilidad.

## Mapa rapido

`Operador -> token de sesion -> dashboard / API -> RuntimeController -> Sniffer | Honeypot -> SQLite -> charts / mapa / WebSocket`

## Lo que incluye

- Captura raw para IPv4, IPv6, ARP, TCP, UDP, ICMP y STP.
- Persistencia SQLite para sesiones, flows, packets, payloads, tags y runtime config.
- Modo `honeypot` con listeners TCP/UDP sobre puertos comunes.
- Dashboard Vue 3 + Vuetify servido por el mismo proceso.
- Autenticacion por token de sesion y JWT HS256.
- WebSocket en vivo para eventos `packet`, `stats_update`, `runtime_mode` y chat.
- Catalogos editables para reglas, probes y presets desde API o archivos JSON.

## Requisitos

- Python `3.12+`
- Linux/Unix con `AF_PACKET` para captura raw en modo `sniffer`
- privilegios de administrador o `CAP_NET_RAW` para captura live
- Node `>=22.12.0` solo si vas a trabajar en `frontend/`

## Instalacion

### Desde el paquete Debian (`.deb`)

El workflow `Package Debian` publica el `.deb` en **GitHub Releases** como asset descargable. La pestaña **Packages** puede seguir vacia: el canal soportado para distribucion binaria es **Releases**.

Cada release publica dos assets equivalentes: el `.deb` versionado
(`sniff4hound_<version>_<arch>.deb`) y una copia sin versionar,
`sniff4hound_latest.deb`. La segunda existe para que la URL de descarga **no
cambie nunca entre releases**:

```text
https://github.com/jorgelsc-dev/Sniff4Hound/releases/latest/download/sniff4hound_latest.deb
```

Ultima release Debian:

- Navegador: [github.com/jorgelsc-dev/Sniff4Hound/releases/latest](https://github.com/jorgelsc-dev/Sniff4Hound/releases/latest)
- `curl` con la URL permanente (no requiere `gh` ni consultar la API):

```bash
curl -fL -o /tmp/sniff4hound_latest.deb \
  https://github.com/jorgelsc-dev/Sniff4Hound/releases/latest/download/sniff4hound_latest.deb
sudo apt install /tmp/sniff4hound_latest.deb
sniff4hound
```

- GitHub CLI:

```bash
mkdir -p /tmp/sniff4hound-release
gh release download --repo jorgelsc-dev/sniff4hound --pattern 'sniff4hound_latest.deb' --dir /tmp/sniff4hound-release
sudo apt install /tmp/sniff4hound-release/sniff4hound_latest.deb
sniff4hound
```

Instalacion manual del artefacto descargado:

```bash
sudo apt install ./sniff4hound_<version>_<arch>.deb
```

Fallback con `dpkg` si prefieres instalar manualmente:

```bash
sudo dpkg -i ./sniff4hound_<version>_<arch>.deb
sudo apt -f install
```

### Desde el repo

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .
```

### Build local del paquete Debian

El repositorio incluye un builder reproducible para generar el `.deb` localmente.

1. Construye la SPA:

```bash
cd frontend
npm ci
npm run build
cd ..
```

2. Genera el paquete:

```bash
./scripts/build_deb.sh
```

3. Instala el artefacto resultante:

```bash
sudo apt install ./dist/sniff4hound_<version>_<arch>.deb
```

Notas del paquete:

- incluye la app Python y los assets ya compilados del frontend;
- requiere `python3 >= 3.12` en la maquina destino;
- genera un archivo `.sha256` junto al `.deb` dentro de `dist/`;
- la misma release publica el `.sha256` para verificar integridad antes de instalar.

## Inicio rapido

### 1. Arrancar el runtime

```bash
sniff4hound
```

Fallback if your shell has not refreshed the entry point yet:

```bash
python -m sniff4hound
```

Notas del launcher:

- Usa `45678` por defecto; si esta ocupado, prueba una ventana cercana de 100 puertos y avisa cual usa.
- Si faltan privilegios para captura raw y corresponde elevar, intenta relanzarse con `sudo`.
- Si solo quieres abrir la UI sin autoarranque de captura, usa `SNIFF4HOUND_CAPTURE_AUTO_START=0`.

Ejemplos utiles:

```bash
SNIFF4HOUND_CAPTURE_AUTO_START=0 sniff4hound
SNIFF4HOUND_RUNTIME_MODE=honeypot sniff4hound
SNIFF4HOUND_CAPTURE_INTERFACES="eth0,wlan0" sniff4hound
```

### 2. Copiar el token de sesion

Al arrancar, `sniff4hound` imprime un token de 8 caracteres en la terminal. La UI lo pide al abrirse, lo conserva solo en memoria del tab actual y lo reutiliza para HTTP y WebSocket mientras esa pagina siga abierta.

### 3. Abrir la interfaz

- Dashboard: `http://127.0.0.1:45678`
- Docs runtime: `http://127.0.0.1:45678/docs`
- Catalogo de endpoints: `http://127.0.0.1:45678/api/endpoints/`

### 4. Confirmar auth y runtime

```bash
curl http://127.0.0.1:45678/api/auth/session
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:45678/api/runtime/
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:45678/api/dashboard/
```

## Modos de ejecucion

### `sniffer`

- abre un socket raw por interfaz seleccionada;
- parsea Ethernet, VLAN, IPv4, IPv6, ARP, TCP, UDP, ICMP e ICMPv6;
- registra paquetes, flows y tags en SQLite;
- emite eventos `packet` y `stats_update` por WebSocket.

### `honeypot`

- levanta listeners TCP/UDP sobre puertos conocidos;
- responde con banners y payloads predefinidos;
- guarda el trafico como sesiones `honeypot:*` en la misma base;
- escribe actividad operativa en `honeypot.log`.

### Cambio de modo

El runtime se cambia por API:

```bash
curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"honeypot"}'
```

Arranque/parada del motor activo:

```bash
curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"start"}'

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"stop"}'
```

## Flujo mental

1. `manage.py` selecciona puerto, imprime token y arranca el runtime.
2. `app.py` sirve la SPA, protege la API y conecta el `RuntimeController`.
3. `Sniffer` o `HoneypotEngine` generan eventos y escriben en `SniffStore`.
4. `api/dashboard`, `api/charts/analytics`, `api/map/scan` y `WS /ws/` consumen ese estado.

## Auth y acceso

- `SNIFF4HOUND_REQUIRE_AUTH=1` por defecto.
- Se aceptan:
  - `Authorization: Bearer <token>`
  - `X-Security-Code: <token>`
  - `X-Access-Token: <token>`
  - `?security_code=<token>`, `?access_token=<token>`, `?token=<token>` o `?auth=<token>` solo en el handshake de `WS /ws/`
- `GET /api/auth/session` indica si la sesion esta autenticada.
- `sniff4hound.auth.generate_token()` crea JWT HS256 para integraciones.
- No hay secreto de firma por defecto: si `SNIFF4HOUND_JWT_SECRET` no esta
  definido, se genera uno por instalacion y se guarda con permisos `0600` en
  `SNIFF4HOUND_DATA_DIR/jwt_secret`. Rotarlo invalida todos los tokens emitidos.
- `SNIFF4HOUND_JWT_TTL` define el TTL en segundos y `SNIFF4HOUND_JWT_MAX_TTL` su techo.
- Cada `401` se registra en el log de seguridad con la IP de origen y cuenta
  contra un limitador por IP (`SNIFF4HOUND_AUTH_FAILURE_THRESHOLD` fallos en
  `SNIFF4HOUND_AUTH_FAILURE_WINDOW_SECONDS`); al superarlo la respuesta pasa a
  `429` con `Retry-After` y backoff incremental.

## Superficie HTTP y WS

Rutas mas utiles:

- `GET /`
- `GET /docs`
- `GET /docs.json`
- `GET /api/auth/session`
- `GET|POST /api/runtime/`
- `GET /api/dashboard/`
- `GET /api/charts/analytics`
- `GET /api/map/scan`
- `GET /api/soc/analysis/`
- `GET /protocols/`
- `GET /targets/`
- `POST|PUT|DELETE /target/`
- `POST /target/action/`
- `GET|DELETE /ports/` y variantes por protocolo
- `GET|DELETE /banners/`
- `GET /tags/` y variantes por protocolo
- `GET /api/catalog/*`
- `POST /api/ws/broadcast`
- `POST /api/ws/ping`
- `POST /api/ws/close`
- `GET /api/chat/messages`
- `POST /api/chat/clear`
- `GET /api/export/` y `GET /api/export/{alerts,endpoints,flows,domains}?format=csv|json`
- `WS /ws/`

## Configuracion util

Variables practicas del runtime:

- `SNIFF4HOUND_HOST`
- `SNIFF4HOUND_PORT`: override explicito del puerto HTTP. Si no se define, Sniff4Hound siempre intenta `45678` primero.
- `SNIFF4HOUND_DB_PATH`
- `SNIFF4HOUND_RUNTIME_MODE`
- `SNIFF4HOUND_CAPTURE_AUTO_START`
- `SNIFF4HOUND_CAPTURE_INTERFACES`
- `SNIFF4HOUND_PROMISCUOUS`
- `SNIFF4HOUND_CAPTURE_BUFFER_BYTES`
- `SNIFF4HOUND_POLL_TIMEOUT`
- `SNIFF4HOUND_REQUIRE_AUTH`
- `SNIFF4HOUND_JWT_SECRET` (opcional; si falta se genera uno por instalacion)
- `SNIFF4HOUND_JWT_TTL`
- `SNIFF4HOUND_JWT_MAX_TTL`
- `SNIFF4HOUND_AUTH_RATE_LIMIT`
- `SNIFF4HOUND_AUTH_FAILURE_THRESHOLD`
- `SNIFF4HOUND_AUTH_FAILURE_WINDOW_SECONDS`
- `SNIFF4HOUND_FRONTEND_DIST`

El proceso web y la base de datos corren **como tu usuario normal**:
`sniff4hound` se niega a arrancar bajo `sudo`. La captura raw de paquetes si
requiere root siempre, pero ese privilegio vive solo en el proceso hijo
`sniff4hound-capture`, que `sniff4hound` lanza por `sudo` y con el que habla por
un socket Unix local `0600`. No hay variable de entorno para omitir la captura
privilegiada: si `sudo` no esta disponible o la elevacion falla, el proceso
termina sin arrancar el servidor.

## Componentes del repo

- `sniff4hound/manage.py`: launcher (siempre requiere root) y consola interactiva.
- `sniff4hound/app.py`: SPA, API, WebSocket y runtime controller.
- `sniff4hound/sniffer.py`: captura raw y parseo de paquetes.
- `sniff4hound/honeypot.py`: listeners emulados y registro de trafico activo.
- `sniff4hound/store.py`: esquema SQLite y snapshots de dashboard.
- `sniff4hound/auth.py`: token de sesion y JWT HS256.
- `sniff4hound/logger.py`: helper NDJSON para integraciones y pruebas.
- `frontend/`: SPA Vue 3 + Vuetify.

## Logging y datos

- La base por defecto es `Sniff4Hound.db`.
- El modo honeypot escribe rotacion local en `honeypot.log`.
- `sniff4hound.logger` existe como helper de libreria; no esta cableado automaticamente al arranque del runtime principal.

## Desarrollo y validacion

Backend:

```bash
python -m sniff4hound.manage
```

Frontend:

```bash
cd frontend
npm ci
npm run dev
```

Checks:

```bash
python -m unittest discover -t . -s tests -q
pytest tests/ -q
```

Frontend:

```bash
cd frontend
npm run lint
npm run build
```

## Documentacion

- Sitio publico MkDocs: `https://sniff4hound.jorgelsc.dev/` (publicado por `docs-pages.yml` en cada push a `main` que toque `docs/`, `landing/`, `mkdocs.yml` o `requirements-docs.txt`)
- Fuente del sitio: `docs/` + `mkdocs.yml`
- Dominio custom: `docs/CNAME`
- Redirecciones legacy: `docs/404.html`

Build y preview local:

```bash
python -m pip install -r requirements-docs.txt
mkdocs serve
mkdocs build --strict
```

- Resumen rapido: [QUICKREF.md](QUICKREF.md)
- Arquitectura: [ARCHITECTURE.md](ARCHITECTURE.md)
- Ejemplos: [EXAMPLES.md](EXAMPLES.md)

## Contribucion y soporte

- Mantiene intacta la restriccion de captura nativa sin dependencias de parseo de terceros.
- Actualiza docs cuando cambie UI, API o esquema.
- La documentacion publica se construye con MkDocs Material desde `docs/`.
  El workflow `docs-pages` la publica en GitHub Pages, pero Pages hay que
  activarlo **una sola vez a mano** en *Settings -> Pages -> Build and
  deployment -> Source: GitHub Actions*: el `GITHUB_TOKEN` de Actions no
  tiene permisos de administracion para crear el sitio por API.
- Reporta vulnerabilidades por canal privado.
- Soporte y notas adicionales: `SUPPORT.md`
