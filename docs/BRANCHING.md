# Branching model

`main` is the only long-lived branch. It is protected, always releasable, and
never committed to directly — every change arrives through a pull request from
a short-lived auxiliary branch.

## Auxiliary branches

Branch off `main`, do the work, open a PR, delete the branch on merge.

| Prefix | For | Example |
| --- | --- | --- |
| `feat/` | New capability | `feat/quic-decoder` |
| `fix/` | Bug fix | `fix/capture-db-lock` |
| `sec/` | Security fix or hardening | `sec/jwt-key-rotation` |
| `docs/` | Documentation only | `docs/protocol-catalog` |
| `chore/` | Tooling, deps, CI, packaging | `chore/bump-vite` |
| `refactor/` | Behaviour-preserving cleanup | `refactor/store-transactions` |
| `test/` | Test-only changes | `test/decoder-fuzzing` |

Keep one concern per branch. A branch that fixes a bug *and* renames a module
is two reviews wearing one hat, and the bug fix is the one that gets rushed.

## Rules on `main`

- No direct pushes, including by the owner. Use a PR.
- No force pushes and no deletion.
- A pull request must be up to date with `main` and green on every required
  check before it can merge.
- Every commit needs a DCO sign-off (`git commit -s`). CI enforces this.
- `CODEOWNERS` review is required; the owner owns every path.

## Required checks

These must pass before merge (see
[`.github/workflows/`](https://github.com/jorgelsc-dev/Sniff4Hound/tree/main/.github/workflows)).
They are listed below by the job name GitHub reports, which is what branch
protection matches on — not by workflow name:

- `Backend tests (Python 3.12)` — unit suite, `compileall`, package install,
  frontend build. The name carries the matrix value, so changing the Python
  version in `ci.yml` also renames this check and it has to be re-selected in
  the branch protection settings.
- `Frontend lint + build` — ESLint with `--max-warnings=0`, production build
  of `frontend/`
- `Landing lint + build` — the same for `landing/`. `docs-pages.yml` only runs
  on push to `main`, so without this check a broken landing page would reach
  the published site before anything caught it.
- `Authorship and provenance` — DCO sign-off and the provenance checklist
- `Analyze (python)` and `Analyze (javascript)` — CodeQL static analysis.
  Both jobs carry `if: visibility == 'public'`; on a private repo they are
  skipped rather than run.
- `dependency-review` — blocks pulling in vulnerable dependencies. It needs
  the repository dependency graph enabled.

## Releases

Releases are automatic: every push to `main` runs `package.yml`, which builds
the Debian package and creates the `vMAJOR.MINOR.PATCH` tag and its GitHub
release, marking it `--latest`. Nothing is tagged by hand.

The version is derived by `sniff4hound/versioning.py` from the Conventional
Commit subjects since the newest `v*` tag, so write commit subjects
accordingly (`feat:`, `fix:`, `feat!:` / `BREAKING CHANGE:`). Note that `chore`
counts as a patch bump, so a dependency merge cuts a release too — batch
dependency updates into one pull request rather than merging them one by one.

The bumped version is only written inside the workflow run; `pyproject.toml`
and `sniff4hound/__init__.py` stay at their committed value in the repository.

## Security issues

Do not open a public pull request for an unfixed vulnerability. Follow
[SECURITY.md](https://github.com/jorgelsc-dev/Sniff4Hound/blob/main/SECURITY.md) and report it privately first.
