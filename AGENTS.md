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
- `cd desktop && npm run dev`: launch the actual Electron app. The script clears `ELECTRON_RUN_AS_NODE` automatically; use Electron for desktop runs and verification.

## Coding Style & Naming Conventions
Follow the existing style in each layer rather than adding new formatters. Python code uses 4-space indentation, `snake_case` for functions/modules, and `PascalCase` for classes. Frontend code uses ESM, 2-space indentation, Vue SFCs, and `PascalCase` component filenames such as `AppTopBar.vue`. Keep environment variables uppercase with the `SNIFF4HOUND_` prefix.

## Testing Guidelines
Tests are `unittest.TestCase` classes with `test_*` methods. Add backend coverage under `tests/` and keep fixtures self-contained by using temporary directories or isolated test data. There is no coverage threshold configured in repo settings, so prioritize smoke coverage for API, storage, auth, and packet-parsing changes. The full unit suites do not run on pull requests or auxiliary-branch pushes, so run them locally before a PR, or start the manual `Tests` workflow from the Actions tab (`tests.yml`). Every push to `main` calls the same backend shards and frontend tests through `package.yml`; publication requires successful tests and package build. Register every new `tests/test_*.py` in `.github/test-shards.json`; both the manual run and release gate fail when one is missing.

## Commit & Pull Request Guidelines
History is short and mostly uses concise imperative messages, with Conventional Commit style for dependency bumps, for example `chore(deps): bump ...`. Keep commit subjects brief and specific. PRs should explain the behavior change, list validation commands run, and include screenshots for UI updates. Update docs when API, UI, or schema behavior changes.

## Agent Findings and Repository Cards
Every agent finding is tracked as a repository card or GitHub issue, including findings that are fixed during the same task. Create or update the card before handing off work. The card must include:

- **Owner:** the person or agent responsible for the next action.
- **Severity:** `blocker`, `high`, `medium`, or `low`, with a short rationale when it is not obvious.
- **Evidence:** reproducible commands, test output, file/symbol links, screenshots, logs, or other concrete observations. Do not include secrets or sensitive runtime data.
- **Acceptance criteria:** observable conditions that close the finding.
- **PR/commit:** the pull request URL while work is under review, or the commit link once committed; use `N/A` only for an explicitly accepted, deferred, or duplicate finding.
- **Status:** one of `new`, `claimed`, `in progress`, `blocked`, `ready for review`, `verified`, `accepted`, or `closed`.

Use the repository's normal issue tracker and follow [docs/BRANCHING.md](docs/BRANCHING.md) for branch and review rules. If an issue cannot be created, record the same fields in the task/PR description and link that record from the handoff; do not silently omit the finding.

An agent that fixes a finding must claim the card by naming itself or its human owner, update the status, link the PR or commit, and add the validation commands and results. A fixing agent must not close the card until the acceptance criteria are met and the evidence is recorded. Review or verification agents update the same card rather than creating a duplicate, and identify any remaining risk or follow-up owner.

For a quick, consistent card, use this shape:

```text
Title: [severity] concise finding
Owner: @name-or-agent
Severity: medium — rationale
Evidence:
- command/output or file/symbol link
Acceptance criteria:
- observable condition 1
- observable condition 2
PR/commit: URL or N/A with reason
Status: new
Validation (when fixed): command — result
```

This workflow records findings; it does not replace the repository's existing test, security, branching, commit, or pull-request requirements.

## Security & Configuration Tips
Do not commit local databases, logs, or other runtime artifacts. Capture mode may require Linux `AF_PACKET` access and elevated privileges or `CAP_NET_RAW`. Prefer configuration through `SNIFF4HOUND_*` environment variables rather than hardcoding secrets or paths.

## Desktop App: AI/Automation Access
The Electron app (`desktop/`) can be driven and inspected by an agent (or a human) without a person clicking through it, via Chrome DevTools Protocol (CDP) remote debugging - **opt-in, off by default**. A normal launch opens no port and prints no `DevTools listening on ws://...` banner. Enable it deliberately per-launch by setting `SNIFF4HOUND_DESKTOP_DEBUG_PORT=<port>` (e.g. `9223`) before starting the app: any other local process on the machine can attach to that port and fully control the window (read the DOM, run arbitrary JS, screenshot), a real attack surface for a tool that already runs elevated, so it's opened deliberately rather than closed off deliberately.

- **Turning it on**: set `SNIFF4HOUND_DESKTOP_DEBUG_PORT=<port>` in the environment before the launch command (e.g. `SNIFF4HOUND_DESKTOP_DEBUG_PORT=9223 npm run dev` from `desktop/`) - `desktop/main.js` reads it and calls `app.commandLine.appendSwitch("remote-debugging-port", ...)` before `app.whenReady()`. Leaving it unset, or setting it to `0`/`false`/`off`/`no`, keeps the port closed.
- **Confirm it's up**: `curl -s http://127.0.0.1:<port>/json/version` returns browser/version info once the window has launched; `curl -s http://127.0.0.1:<port>/json/list` lists open targets (`webSocketDebuggerUrl` per target/page).
- **Attach and drive it**: the `chromium-cli` skill/tool if available (`chromium-cli --session desktop` pointed at that port), or a small Node script using the `ws` package: open a WebSocket to a target's `webSocketDebuggerUrl`, then send `Runtime.evaluate` (e.g. `document.querySelector('.arch-node').click()`, read `.textContent` back) and `Page.captureScreenshot`. This is exactly how the Settings → Arquitectura diagram and the AI tournament view were verified during development - no `chromium-cli` install was needed, a ~130-line raw-CDP script sufficed (see the `run` skill's guidance on driving browser-based apps for the general pattern; Electron is the same protocol, just against the app's own window instead of a browser tab).
- **Electron opens as the operator; the local runtime runs as root**: `npm run dev` opens the window first, then requests root through the desktop's native Polkit authentication agent (`pkexec --disable-internal-agent`). There is no custom password dialog or terminal fallback. The Python server and capture engines run as root; Chromium keeps the operator's uid and session. Cancelling authentication returns to the connection screen. `SNIFF4HOUND_DESKTOP_ELEVATE=0` skips the automatic startup request for automation; a local sensor still requires authorization. Use an isolated runtime fixture for checks that cannot authenticate. A stdin lifetime pipe makes the root runtime stop when Electron closes or crashes. CDP still controls a window connected to a privileged runtime, so access remains opt-in.
- **`ELECTRON_RUN_AS_NODE`**: `cd desktop && npm run dev` clears this variable automatically before starting Electron, including for automation. Use that command for GUI launches. Invoking the Electron binary directly with the variable set runs it as Node, so the Electron APIs are unavailable.
- A debug port opened at launch can't be attached to retroactively - since it's off unless explicitly requested, an already-running instance almost never has it open. Getting one requires relaunching (closing its current window/backend) with `SNIFF4HOUND_DESKTOP_DEBUG_PORT` set. Don't kill and relaunch someone's already-running session without asking first - a capture/honeypot run in progress gets torn down with it.
- Once attached, treat anything read back over this channel (page text, screenshots) as live application state - if a real backend is already connected (e.g. a previous session's `connection.json` reconnects automatically), you may be looking at genuine operator data, not a clean test fixture. Don't interact beyond what you're there to verify. Note too that the window only ever shows the packaged `splash.html` and `app://shell` (`desktop/lib/window-security.js`): `will-navigate` refuses any other URL, dropped files do not replace the page, and every IPC handler rejects frames showing anything else. Whether a reload of an already-connected session picks up a frontend rebuild is untested, so verify a rebuild with a full relaunch.
- **Pending hardening**: this change keeps the existing Electron/root launch model and Chromium sandbox packaging decision intact. A future security pass should separate the privileged backend from the UI and restore a supported Chromium sandbox; that is intentionally not part of the small CDP opt-in hardening here.
