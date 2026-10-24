# Sniff4Hound Desktop

Linux desktop shell for Sniff4Hound. It runs the Vue console inside Electron
and starts the Python backend as a child process.

`npm run dev` opens Electron in the operator's graphical session, then
immediately requests root authorization through the desktop's **native Polkit
prompt**. The app uses `pkexec --disable-internal-agent`, so GNOME, KDE or the
installed desktop authentication agent owns the password/fingerprint UI. There
is no custom approval/password dialog or terminal authentication fallback.
Install `pkexec` (Polkit) and have a desktop authentication agent running.

Electron and its renderer retain the operator's uid, display credentials and
session bus. Only the Python runtime (web server, database, sniffer and honeypot)
runs as root. Capture engines start paused. This avoids blank root Chromium
windows and display/library permission failures in private home and Wayland
sessions. `lib/elevation.js` builds the native authorization command; passwords
never enter the renderer, application IPC or logs.

Local startup reports success only after the READY payload, mDNS endpoint and
required HTTP/3 listener have been verified. A startup failure closes that
attempt's lifetime pipe and releases the connection controls for a retry or a
remote connection; late events from that child cannot replace a newer session.
Cancelling the native prompt also releases the connection controls. A saved remote
connection skips the automatic root request. For automation,
`SNIFF4HOUND_DESKTOP_ELEVATE=0` skips that initial request; explicitly starting a
local sensor still requires root. It no longer controls Electron's uid.

`python -m sniff4hound.desktop_runtime` runs the server with a lifetime pipe
from Electron. Closing the window, disconnecting the local sensor or crashing
the shell closes that pipe and makes the root runtime terminate itself. This
also works after Polkit switches uid, when Electron cannot signal root directly.

The privileged runtime receives the operator's data location, Python environment
and `SNIFF4HOUND_*` settings, except the IPC token and JWT secret, which never
travel on the command line. The runtime hands its database and desktop security
code back to the operator. Electron retains its normal graphics acceleration.
A manually root-launched shell still uses software rendering as a fallback;
normal launches should run without `sudo`.

The renderer and preload use Chromium's sandbox, context isolation and no Node
integration. Both the chooser and console enforce `script-src 'self'`; console
connections are restricted to its selected runtime origin and WebSocket origin.
Unused browser permissions are denied. On Linux the normal operator launch uses
the platform sandbox; `SNIFF4HOUND_DESKTOP_NO_SANDBOX=1` is an explicit compatibility
opt-out for systems without working Chromium sandbox support. Manually running
Electron as root also requires that fallback. The debug port
(`SNIFF4HOUND_DESKTOP_DEBUG_PORT`) remains opt-in.

For headless GNOME/Wayland checks, use an isolated data/config directory and force
X11 as well as Xvfb: `xvfb-run -a env -u WAYLAND_DISPLAY XDG_SESSION_TYPE=x11
SNIFF4HOUND_DESKTOP_ELEVATE=0 npm run dev -- --ozone-platform=x11`.

Authenticated desktop consoles may control a remote sensor without setting
`SNIFF4HOUND_DESKTOP` on the server. Foreign HTTP(S) origins remain rejected.
The disconnected banner offers **Reconectar / Cambiar sensor**. Pipeline values
remain unknown until a response arrives and become stale on an error or outage.

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
HTTP/3 (QUIC on the same port number, over UDP). The mobile QR uses the selected
LAN IP so it also works in browsers without `.local` resolution; the separately
shown mDNS URL remains available for systems that support it. Both names are
present in the stream certificate.

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

The power button starts a visible three-second countdown without confirmation.
Cleanup begins immediately: the UI closes realtime feeds and stops polling and
refresh timers, while Electron closes the local runtime's lifetime pipe and its
HTTP streams. The runtime requests graceful SIGINT shutdown, stops capture
engines and jobs, joins snapshot delivery, and closes its stores. Electron keeps
the countdown visible even if the runtime exits early, then closes at three
seconds. Closing a remote console leaves the remote sensor running.

The console uses shared surface, spacing, corner and focus styles for tables,
charts, menus and forms. The capture pipeline starts as a compact status strip
so telemetry is immediately visible. Expanding or collapsing it saves the
preference for subsequent views and sessions. An amber dot means connected with
capture stopped; green means a capture engine is running, and red means disconnected.
Dashboard metrics use six, three, two or one column as the window narrows. Chart
bars move beneath their labels when the card itself is narrow. Keyboard focus and
field validation remain visible, and motion follows the system's reduced-motion preference.

ARP and DNS have separate sidebar entries and command-palette destinations.
ARP (`/#/arp`) shows IP/MAC bindings, devices and recorded address changes.
Every global MAC is matched offline against the bundled IEEE MA-L, MA-M, MA-S
and legacy IAB public assignments; the manufacturer and exact assignment class
appear in bindings, devices and changes, and manufacturer names are searchable.
Locally administered or randomized MAC addresses are identified explicitly.
DNS (`/#/dns`) shows domain and record-type charts, answers, errors, clients and
resolvers. Both have search, time filters, live refresh and table export; their
"Ver paquetes" button opens the corresponding Protocols traffic view. Settings
continues to manage their history retention and recording. The previous
`/#/history/arp` and `/#/history/dns` links redirect to these views.

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
separately. The desktop `dev` script clears `ELECTRON_RUN_AS_NODE` automatically,
so `cd desktop && npm run dev` always launches Electron.

## AI/Automation Access

Chrome DevTools Protocol access is **off by default**. Set
`SNIFF4HOUND_DESKTOP_DEBUG_PORT=9223` deliberately for a dedicated test launch;
leaving it unset or setting it to `0` keeps the port closed.
See `AGENTS.md`'s "Desktop App: AI/Automation Access" for how to attach and verify
the actual Electron app.

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
