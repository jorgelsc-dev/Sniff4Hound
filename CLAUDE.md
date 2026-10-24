# Agent Workflow

This file complements [AGENTS.md](AGENTS.md). Follow the repository guidance there first, including its project structure, validation commands, security rules, and branching/PR requirements.

## Record every finding

Every agent finding must be recorded as a repository card or GitHub issue, even when the finding is fixed immediately. Each card must contain:

- owner;
- severity: `blocker`, `high`, `medium`, or `low`;
- concrete evidence, such as commands, output, file/symbol links, or screenshots;
- observable acceptance criteria;
- the PR URL or commit link, or `N/A` with a reason when no link applies; and
- status: `new`, `claimed`, `in progress`, `blocked`, `ready for review`, `verified`, `accepted`, or `closed`.

Use the normal repository issue tracker and keep the card linked from the relevant PR or handoff. If the tracker is unavailable, put the same fields in the task or PR description and link that record. Never drop a finding because it is small, already known, or fixed in the current change; update the existing card instead of duplicating it.

## Fixing and verification

The agent making a fix must claim the card, set the owner and status, link the PR or commit, and record validation commands with their results. Keep the card open until its acceptance criteria are met and evidence is attached. A review or verification agent updates the same card, records remaining risk or follow-up ownership, and only then marks it `verified` or `closed`.

Use this compact card format when creating one:

```text
Title: [severity] concise finding
Owner: @name-or-agent
Severity: medium — rationale
Evidence:
- command/output or file/symbol link
Acceptance criteria:
- observable condition
PR/commit: URL or N/A with reason
Status: new
Validation (when fixed): command — result
```

This is a tracking requirement, not a replacement for tests, security review, or the repository's normal branch and pull-request process.
