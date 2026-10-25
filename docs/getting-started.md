# Empezar

## Requisitos

- Python `3.12+`
- Linux o Unix con `AF_PACKET` para captura raw en modo `sniffer`
- privilegios de administrador o `CAP_NET_RAW` para captura en vivo
- Node `22.12.0+` solo si vas a trabajar en `desktop/frontend/`

## Instalar

### Desde el paquete Debian (`.deb`)

El workflow `Package Debian` publica el `.deb` en **GitHub Releases**. Tambien puedes construirlo localmente.

Cada release publica el `.deb` versionado (`sniff4hound_<version>_<arch>.deb`)
y una copia sin versionar, `sniff4hound_latest.deb`, para que la URL de
descarga no cambie entre releases:

```bash
curl -fL -o /tmp/sniff4hound_latest.deb \
  https://github.com/jorgelsc-dev/Sniff4Hound/releases/latest/download/sniff4hound_latest.deb
sudo apt install /tmp/sniff4hound_latest.deb
sniff4hound
```

Lo mismo con `gh`:

```bash
mkdir -p /tmp/sniff4hound-release
gh release download --repo jorgelsc-dev/sniff4hound --pattern 'sniff4hound_latest.deb' --dir /tmp/sniff4hound-release
sudo apt install /tmp/sniff4hound-release/sniff4hound_latest.deb
sniff4hound
```

La pagina de la ultima release es:

```text
https://github.com/jorgelsc-dev/Sniff4Hound/releases/latest
```

Instalacion manual del artefacto descargado:

```bash
sudo apt install ./sniff4hound_<version>_<arch>.deb
```

Fallback con `dpkg`:

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

La instalación editable resuelve `wsbuilder[tls,mdns]==1.3.0` desde PyPI, la
versión exacta fijada por `pyproject.toml`. Esa release publicada incluye el
stack QUIC/HTTP3, TLS (`[tls]`) y mDNS/DNS-SD (`[mdns]`) que usa el runtime.
La consola Electron usa HTTPS/TCP por defecto: el HTTP/3 de escritorio se
activa de forma explícita con `SNIFF4HOUND_DESKTOP_HTTP3=1` hasta que
`wsbuilder` publique una corrección para retransmisiones QUIC.

### Build local del paquete Debian

Construye la SPA y luego genera el artefacto:

```bash
cd desktop/frontend
npm ci
npm run build
cd ../..
./scripts/build_deb.sh
sudo apt install ./dist/sniff4hound_<version>_<arch>.deb
```

## Limpiar artefactos locales

La limpieza de build/cache está separada de la limpieza de datos. El script es
dry-run por defecto y nunca apunta a bases de datos, capturas, logs,
certificados ni claves del runtime:

```bash
./scripts/clean_build_artifacts.sh --dry-run
./scripts/clean_build_artifacts.sh --yes
```

`--dry-run` solo lista `dist/`, `build/`, `QA/`, `__pycache__/`,
`.pytest_cache/` y `*.egg-info/`; `--yes` elimina únicamente esos directorios.

## Arranque rapido

```bash
sniff4hound
```

Fallback if your shell has not refreshed the entry point yet:

```bash
python -m sniff4hound
```

Notas del launcher:

- usa `45678` por defecto; si esta ocupado, prueba una ventana cercana de 100 puertos y avisa cual usa;
- si faltan privilegios para captura raw y corresponde elevar, intenta relanzarse con `sudo`;
- si solo quieres abrir la UI sin autoarranque de captura, usa `SNIFF4HOUND_CAPTURE_AUTO_START=0`.

Ejemplos utiles:

```bash
SNIFF4HOUND_CAPTURE_AUTO_START=0 sniff4hound
SNIFF4HOUND_RUNTIME_MODE=honeypot sniff4hound
SNIFF4HOUND_CAPTURE_INTERFACES="eth0,wlan0" sniff4hound
```

## Acceso

- UI: abre la app de escritorio Electron (`sniff4hound-desktop`, o el icono del launcher) - no hay dashboard servido por navegador.
- Docs runtime: `http://127.0.0.1:45678/docs`
- Catalogo de endpoints: `http://127.0.0.1:45678/api/endpoints/`
- La UI pide el codigo de seguridad al abrirse y lo conserva solo en memoria de esa sesion.

## Documentacion local

El sitio publico se compila con MkDocs Material desde `mkdocs.yml`.

```bash
python -m pip install -r requirements-docs.txt
mkdocs serve
```

Abre `http://127.0.0.1:8000` para previsualizar la documentacion y `mkdocs build --strict` para validar el sitio antes de enviar un PR.
