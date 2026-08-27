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
[`.github/workflows/`](https://github.com/jorgelsc-dev/Sniff4Hound/tree/main/.github/workflows)):

- `ci` — backend test suite, `compileall`, package install, frontend build
- `frontend-checks` — ESLint with `--max-warnings=0`, production build
- `contribution-guard` — DCO sign-off and the provenance checklist
- `CodeQL` — static analysis for Python and JavaScript
- `dependency-review` — blocks pulling in vulnerable dependencies

## Releases

Tag `main` as `vMAJOR.MINOR.PATCH`. Version numbers are derived from
Conventional Commit subjects by `sniff4hound/versioning.py`, so write commit
subjects accordingly (`feat:`, `fix:`, `feat!:` / `BREAKING CHANGE:`).

## Security issues

Do not open a public pull request for an unfixed vulnerability. Follow
[SECURITY.md](https://github.com/jorgelsc-dev/Sniff4Hound/blob/main/SECURITY.md) and report it privately first.
