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
