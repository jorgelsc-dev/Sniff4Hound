# Sniff4Hound Desktop

Linux desktop shell for Sniff4Hound. It runs the Vue console inside Electron
and starts the Python backend as a child process. The Electron window itself
stays an unprivileged process, but the backend it starts requires root the
same way the `sniff4hound` CLI command does - see `sniff4hound/manage.py`'s
`_ensure_running_as_root()` - and self-elevates with `pkexec` (falling back to
`sudo`) on first start.

When installed from the project's `.deb` (`scripts/build_deb.sh`), this app
is not a separate package: it ships inside the same `sniff4hound` `.deb` as
the CLI, installed only when the target machine has a graphical environment
(detected in `scripts/deb_postinst.sh`), and shares that install's Python
runtime under `/usr/lib/sniff4hound/vendor` instead of bundling its own copy
(see `usingSharedVendorRuntime()` in `main.js`).

The launcher supports two connection modes:

- Local sensor: starts the bundled backend from the packaged venv. Capture
  engines start stopped; start sniffer or honeypot from the console UI.
- Remote sensor: connects to an existing Sniff4Hound backend by host/IP, port,
  and security code, useful when a sensor is exposed through a tunnel.

The connection screen uses responsive local and remote sensor cards, keyboard-visible
focus states, and a live connection status indicator. On narrow windows, the cards
stack vertically and the screen scrolls to keep all controls accessible.

## Development

From the repository root:

```bash
cd frontend && npm ci && npm run build
python3 -m venv --copies build/desktop/runtime/python-venv
build/desktop/runtime/python-venv/bin/python -m pip install -e .
cd desktop && npm install && npm run dev
```

## Release Build

The desktop app is no longer packaged on its own - `scripts/build_deb.sh`
(run from the repository root) builds it as part of the single combined
`.deb` alongside the CLI. `scripts/build_desktop_linux.sh` still exists as a
local-dev convenience for running the Electron shell against a throwaway venv
without installing that package; its output under `dist/desktop/` is not what
gets shipped in a release.
