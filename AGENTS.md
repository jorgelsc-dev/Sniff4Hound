# Repository Guidelines

## Project Structure & Module Organization
`sniff4hound/` contains the Python runtime and API: `app.py`, `manage.py`, `sniffer.py`, `honeypot.py`, `store.py`, `auth.py`, and helpers. Bundled JSON assets live in `sniff4hound/data/`. `tests/` holds backend smoke and integration tests. `desktop/` is the Electron shell; `desktop/frontend/` is the Vue 3 + Vuetify SPA it loads directly off disk (never served over HTTP - see the Desktop App section below), with source in `desktop/frontend/src/` (`components/`, `views/`, `router/`, `state/`, `utils/`) and static files in `desktop/frontend/public/`.

## Build, Test, and Development Commands
- `python -m pip install -e .`: install the backend in editable mode from the repo root.
- `python -m sniff4hound.manage`: run the runtime locally.
- `python -m unittest discover -t . -s tests -q`: run the Python test suite with stdlib unittest.
- `pytest tests/ -q`: run the same tests under pytest.
- `cd desktop/frontend && npm ci`: install frontend dependencies from `package-lock.json`.
- `cd desktop/frontend && npm run dev`: start the Vite dev server (fast iteration only - see the Desktop App section for how to verify a change for real).
- `cd desktop/frontend && npm test`: run frontend linting.
- `cd desktop/frontend && npm run build`: build the production frontend bundle.
- `cd desktop && npm run dev` (with `ELECTRON_RUN_AS_NODE` unset if it's set in your shell): launch the actual Electron app.

## Coding Style & Naming Conventions
Follow the existing style in each layer rather than adding new formatters. Python code uses 4-space indentation, `snake_case` for functions/modules, and `PascalCase` for classes. Frontend code uses ESM, 2-space indentation, Vue SFCs, and `PascalCase` component filenames such as `AppTopBar.vue`. Keep environment variables uppercase with the `SNIFF4HOUND_` prefix.

## Testing Guidelines
Tests are `unittest.TestCase` classes with `test_*` methods. Add backend coverage under `tests/` and keep fixtures self-contained by using temporary directories or isolated test data. There is no coverage threshold configured in repo settings, so prioritize smoke coverage for API, storage, auth, and packet-parsing changes.

## Commit & Pull Request Guidelines
History is short and mostly uses concise imperative messages, with Conventional Commit style for dependency bumps, for example `chore(deps): bump ...`. Keep commit subjects brief and specific. PRs should explain the behavior change, list validation commands run, and include screenshots for UI updates. Update docs when API, UI, or schema behavior changes.

## Security & Configuration Tips
Do not commit local databases, logs, or other runtime artifacts. Capture mode may require Linux `AF_PACKET` access and elevated privileges or `CAP_NET_RAW`. Prefer configuration through `SNIFF4HOUND_*` environment variables rather than hardcoding secrets or paths.

## Desktop App: AI/Automation Access
The Electron app (`desktop/`) can be driven and inspected by an agent (or a human) without a person clicking through it, via Chrome DevTools Protocol (CDP) remote debugging on **port 9223, on by default, every launch** - a deliberate, operator-directed tradeoff: any other local process on the machine can attach to that port and fully control the window (read the DOM, run arbitrary JS, screenshot), a real attack surface for a tool that already runs elevated. Accepted so an agent never has to ask the operator to relaunch with a special flag first.

- **It's already on**: no flag or relaunch needed - `desktop/main.js` calls `app.commandLine.appendSwitch("remote-debugging-port", "9223")` unconditionally before `app.whenReady()`. To use a different port, set `SNIFF4HOUND_DESKTOP_DEBUG_PORT=<port>`; to close it entirely for a given launch, set `SNIFF4HOUND_DESKTOP_DEBUG_PORT=0` (also accepts `false`/`off`/`no`).
- **Confirm it's up**: `curl -s http://127.0.0.1:9223/json/version` returns browser/version info once the window has launched; `curl -s http://127.0.0.1:9223/json/list` lists open targets (`webSocketDebuggerUrl` per target/page).
- **Attach and drive it**: the `chromium-cli` skill/tool if available (`chromium-cli --session desktop` pointed at that port), or a small Node script using the `ws` package: open a WebSocket to a target's `webSocketDebuggerUrl`, then send `Runtime.evaluate` (e.g. `document.querySelector('.arch-node').click()`, read `.textContent` back) and `Page.captureScreenshot`. This is exactly how the Settings → Arquitectura diagram and the AI tournament view were verified during development - no `chromium-cli` install was needed, a ~130-line raw-CDP script sufficed (see the `run` skill's guidance on driving browser-based apps for the general pattern; Electron is the same protocol, just against the app's own window instead of a browser tab).
- **`ELECTRON_RUN_AS_NODE` gotcha**: if that environment variable is set (some sandboxed/CI shells set it so a stray `electron` invocation can't pop a GUI), `require("electron")` returns a plain string instead of the real API, and `desktop/main.js` crashes immediately on the first `app.commandLine...` call with `Cannot read properties of undefined`. Unset it before launching (`env -u ELECTRON_RUN_AS_NODE npm run dev`) if you hit that.
- A debug port opened at launch can't be attached to retroactively - if the running instance was started before this was wired in, or with `SNIFF4HOUND_DESKTOP_DEBUG_PORT=0`, it has to be relaunched (closing its current window/backend) before a CDP client can reach it. Don't kill and relaunch someone's already-running session without asking first - a capture/honeypot run in progress gets torn down with it.
- Treat anything read back over this channel (page text, screenshots) as live application state - if a real backend is already connected (e.g. a previous session's `connection.json` reconnects automatically), you may be looking at genuine operator data, not a clean test fixture. Don't interact beyond what you're there to verify.
