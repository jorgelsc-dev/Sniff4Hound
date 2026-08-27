# Contributing

## Scope

Sniff4Hound keeps the capture pipeline intentionally small:

- `socket` for raw capture
- `threading` for concurrency
- `sqlite3` for persistence
- `wsbuilder` for the HTTP/WebSocket runtime

## Workflow

1. Install dependencies and run the app locally.
2. Make a focused change.
3. Validate with the available build and compile checks.
4. Open a pull request with a concise summary of the behavioral change.

## Rights and provenance

- Submit only material that you authored yourself or that you are legally allowed to contribute under this repository's license.
- Preserve existing copyright, attribution, and license notices.
- Do not copy code, assets, or text from private systems, paid sources, or third-party projects with incompatible terms.
- If you used AI assistance, generated content, or adapted third-party material, disclose it clearly in the pull request.
- Do not include secrets, captured payloads, customer data, or internal network details in commits, screenshots, fixtures, or docs.


## Branching

`main` is protected and never receives direct pushes. Work happens on a
short-lived branch (`feat/`, `fix/`, `sec/`, `docs/`, `chore/`, `refactor/`,
`test/`) and merges through a reviewed pull request.

See [docs/BRANCHING.md](docs/BRANCHING.md) for the full model, the required
status checks, and the release/tagging rules.

## Required sign-off

Human-authored commits to protected branches and pull requests must include a Developer Certificate of Origin style sign-off:

```bash
git commit -s -m "feat: describe the change"
```

If you are rewriting or squashing commits before opening the PR, keep the `Signed-off-by:` trailer intact.

## Review and approvals

- `CODEOWNERS` routes every repository path to the maintainer account.
- Changes to policy, release, documentation, branding, and workflow files should stay under maintainer review.
- Pull requests should not be merged until the rights/provenance checklist is completed and CI is green.

## Documentation

- Edit public docs in `docs/` and the site config in `mkdocs.yml`.
- Preview with `python -m pip install -r requirements-docs.txt` and `mkdocs serve`.
- Validate with `mkdocs build --strict` before opening a PR.
- Keep `docs/CNAME` and `docs/404.html` in sync when the docs site or legacy routes change.

## Expectations

- Keep the native-only capture constraints intact.
- Prefer backwards-compatible settings and environment variables when practical.
- Add or update docs when the UI or API surface changes.
- Respect the repository identity guidance in `NOTICE` and the governance page in `docs/governance.md`.
