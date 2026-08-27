# Repository Guidelines

## Project Structure & Module Organization
`sniff4hound/` contains the Python runtime and API: `app.py`, `manage.py`, `sniffer.py`, `honeypot.py`, `store.py`, `auth.py`, and helpers. Bundled JSON assets live in `sniff4hound/data/`. `tests/` holds backend smoke and integration tests. `frontend/` is the Vue 3 + Vuetify SPA; source code is in `frontend/src/` (`components/`, `views/`, `router/`, `state/`, `utils/`), with static files in `frontend/public/`.

## Build, Test, and Development Commands
- `python -m pip install -e .`: install the backend in editable mode from the repo root.
- `python -m sniff4hound.manage`: run the runtime locally.
- `python -m unittest discover -t . -s tests -q`: run the Python test suite with stdlib unittest.
- `pytest tests/ -q`: run the same tests under pytest.
- `cd frontend && npm ci`: install frontend dependencies from `package-lock.json`.
- `cd frontend && npm run dev`: start the Vite dev server.
- `cd frontend && npm test`: run frontend linting.
- `cd frontend && npm run build`: build the production frontend bundle.

## Coding Style & Naming Conventions
Follow the existing style in each layer rather than adding new formatters. Python code uses 4-space indentation, `snake_case` for functions/modules, and `PascalCase` for classes. Frontend code uses ESM, 2-space indentation, Vue SFCs, and `PascalCase` component filenames such as `AppTopBar.vue`. Keep environment variables uppercase with the `SNIFF4HOUND_` prefix.

## Testing Guidelines
Tests are `unittest.TestCase` classes with `test_*` methods. Add backend coverage under `tests/` and keep fixtures self-contained by using temporary directories or isolated test data. There is no coverage threshold configured in repo settings, so prioritize smoke coverage for API, storage, auth, and packet-parsing changes.

## Commit & Pull Request Guidelines
History is short and mostly uses concise imperative messages, with Conventional Commit style for dependency bumps, for example `chore(deps): bump ...`. Keep commit subjects brief and specific. PRs should explain the behavior change, list validation commands run, and include screenshots for UI updates. Update docs when API, UI, or schema behavior changes.

## Security & Configuration Tips
Do not commit local databases, logs, or other runtime artifacts. Capture mode may require Linux `AF_PACKET` access and elevated privileges or `CAP_NET_RAW`. Prefer configuration through `SNIFF4HOUND_*` environment variables rather than hardcoding secrets or paths.
