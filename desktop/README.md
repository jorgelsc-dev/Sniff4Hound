# Sniff4Hound Desktop

Linux desktop shell for Sniff4Hound. It runs the Vue console inside Electron
and starts the Python backend as a child process.

The whole app runs as root, in one process tree: Sniff4Hound needs root for raw
capture and low-port honeypot listeners, and the shell is part of that tree. An
unprivileged launch (`npm run dev`, the desktop entry, the AppImage) therefore
opens no window of its own: it relaunches itself through `sudo` and waits for
that root copy, which starts the backend. The backend sees it is already root
and does not ask a second time, and it runs the web server, the sniffer and the
honeypot in a single process. `sudo` prompts in the terminal when there is one
(so a fingerprint reader works) and otherwise through a graphical askpass
(`zenity`, or `ssh-askpass`); with no usable `sudo` it falls back to `pkexec`.
Cancelling the prompt closes the app. The command is built in `lib/elevation.js`.

What carries over to the root copy: the display (`DISPLAY`, `XAUTHORITY`,
`WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`), the operator's own `HOME` (so the same
configuration and database are used, not a fresh set under `/root`), `PATH`,
`VIRTUAL_ENV`, `PYTHONPATH` and every `SNIFF4HOUND_*` variable except the IPC
token and the JWT secret. Files the root copy writes into the configuration
directory are handed back to the operator when it exits.

For X11, the launcher also forwards the operator's readable `~/.Xauthority`
explicitly when `XAUTHORITY` is unset; relative authority paths are resolved
before elevation. When `dbus-daemon` is installed, the elevated app starts
its own temporary session bus rather than connecting as root to the operator's
bus, and stops it on normal exit or a termination signal. Terminal stderr uses
CRLF while attached to a tty so sudo's password/fingerprint prompt cannot leave
the logs staircasing.

On Linux, the elevated shell and the waiting launcher use
[software rendering](https://www.electronjs.org/docs/latest/api/app#appdisablehardwareacceleration).
This avoids GPU initialization retries and `libGLESv2.so: Permission denied`
errors when the application lives inside a private home directory. The
unprivileged shell (`SNIFF4HOUND_DESKTOP_ELEVATE=0`) keeps hardware acceleration.

Trade-off, chosen deliberately: the renderer now runs as root too, and Chromium
runs without its sandbox (it refuses to start as root otherwise, and the shell
already ran without it, since the `.deb` cannot ship a setuid helper). The window
only loads the app bundled on disk and the backend it started, never arbitrary
pages; the opt-in debug port (`SNIFF4HOUND_DESKTOP_DEBUG_PORT`) is a different
matter - anything local that can reach it controls a root window - so leave it
off outside a session where you want it. `SNIFF4HOUND_DESKTOP_ELEVATE=0` keeps
the shell unprivileged, with the backend asking for privileges on its own as it
did before.

mDNS: `wsbuilder[tls,mdns]` publishes a `_sniff4hound._tcp.local.` service for
the runtime on its bound interface and a separate service for the mobile stream
on the operator-selected interface. Names are stable per machine:
`sniff4hound-runtime-<id>.local` and `sniff4hound-<id>.local`. Override them with
`SNIFF4HOUND_MDNS_HOST` and `SNIFF4HOUND_MOBILE_HOST`; both must be valid `.local`
names. No pairing codes, session tokens or TLS secrets are published in TXT
records. Stopping a service withdraws its announcements.

Before Chromium starts, `python -m sniff4hound.desktop_prepare` supplies the
runtime name, its bound address, a port free on TCP and UDP, and the public-key
hash of its server key. Chromium maps only that exact name to the local
interface, so Electron needs no system mDNS daemon. Before connecting, the shell
uses wsbuilder to resolve the exact service its child announced and checks its
name, role, address and port against the prepared endpoint. API requests and the
realtime stream then use the `.local` origin, with the existing TLS pinning and
HTTP/3 (QUIC on the same port number, over UDP). The mobile QR and links also use
the stream's `.local` name; the phone's OS must support mDNS and the selected
network must allow multicast. `SNIFF4HOUND_MDNS=0` explicitly keeps IP origins.

Chromium is told to trust the runtime's server key and use QUIC for that one
origin (`lib/quic-pin.js`). The key and the
CA that signs for it are kept between launches (`SNIFF4HOUND_DATA_DIR/tls`, mode
0600) - that is what makes the pin stable; only the certificate is new each time.
A forced QUIC origin has no TCP fallback, so if the runtime reports it has no
UDP listener the shell says so instead of showing a dead window. A remote sensor
is unaffected and stays on HTTPS over TCP. `SNIFF4HOUND_DESKTOP_HTTP3=0` turns it
off.

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

The console uses shared surface, spacing, corner and focus styles for tables,
charts, menus and forms. The capture pipeline starts as a compact status strip
so telemetry is immediately visible. Expanding or collapsing it saves the
preference for subsequent views and sessions. An amber dot means connected with
capture stopped; green means a capture engine is running, and red means disconnected.
Dashboard metrics use six, three, two or one column as the window narrows. Chart
bars move beneath their labels when the card itself is narrow. Keyboard focus and
field validation remain visible, and motion follows the system's reduced-motion preference.

## Development

From the repository root:

```bash
cd desktop/frontend && npm ci && npm run build
python3 -m venv --copies build/desktop/runtime/python-venv
build/desktop/runtime/python-venv/bin/python -m pip install -e .
cd desktop && npm install && npm run dev
```

If npm prints `DEP0169` before starting Electron, run
`NODE_OPTIONS=--trace-deprecation npm run` to locate the deprecated call.
A stack under `/usr/share/nodejs/nopt` or `@npmcli/config` comes from the
system npm installation, not the desktop app; update that npm installation
separately. Unset `ELECTRON_RUN_AS_NODE` before launching Electron if your
development shell sets it.

## AI/Automation Access

Chrome DevTools Protocol access is **off by default**. Set
`SNIFF4HOUND_DESKTOP_DEBUG_PORT=9223` deliberately for a dedicated test launch;
leaving it unset or setting it to `0` keeps the port closed.
See `AGENTS.md`'s "Desktop App: AI/Automation Access" for how to attach and a couple of gotchas
(notably `ELECTRON_RUN_AS_NODE`).

After building the frontend, audit the production bundle in an isolated Electron
session with synthetic data:

```bash
SNIFF4HOUND_DESKTOP_DEBUG_PORT=9223 node scripts/qa_desktop_styles.js
NODE_PATH=/path/to/playwright/node_modules QA_STYLE_FIXTURE_STATES=1 \
  SNIFF4HOUND_DESKTOP_DEBUG_PORT=9223 node scripts/qa_desktop_states.js
```

Run these commands from the repository root. The state audit needs Playwright and
must only target a fixture session. Both scripts accept `QA_STYLE_VIEWPORTS` as a
JSON array of `[width, height]` pairs and `QA_STYLE_OUTPUT` for their report and
screenshots. The layout audit accepts `QA_STYLE_ROUTES` as a comma-separated list.

## Release Build

The desktop app is no longer packaged on its own - `scripts/build_deb.sh`
(run from the repository root) builds it as part of the single combined
`.deb` alongside the CLI. `scripts/build_desktop_linux.sh` still exists as a
local-dev convenience for running the Electron shell against a throwaway venv
without installing that package; its output under `dist/desktop/` is not what
gets shipped in a release.
