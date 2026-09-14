# Sniff4Hound Desktop

Linux desktop shell for Sniff4Hound. It runs the Vue console inside Electron,
starts the Python backend from an isolated venv, and elevates only the capture
process with `pkexec`/`sudo`.

The launcher supports two connection modes:

- Local sensor: starts the bundled backend from the packaged venv. Capture
  engines start stopped; start sniffer or honeypot from the console UI.
- Remote sensor: connects to an existing Sniff4Hound backend by host/IP, port,
  and security code, useful when a sensor is exposed through a tunnel.

## Development

From the repository root:

```bash
cd frontend && npm ci && npm run build
python3 -m venv --copies build/desktop/runtime/python-venv
build/desktop/runtime/python-venv/bin/python -m pip install -e .
cd desktop && npm install && npm run dev
```

## Release Build

Use the repository script:

```bash
scripts/build_desktop_linux.sh
```

Artifacts are written to `dist/desktop/`.
