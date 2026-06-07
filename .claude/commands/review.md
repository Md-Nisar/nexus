---
description: Phase 6 — Code review on the current diff using a fresh-context sub-agent.
argument-hint: <FEATURE-ID>
---

Use the **code-reviewer** sub-agent (fresh context — unbiased review) to review the diff for feature `$1`.

Steps:

1. Determine the diff scope. Default: changes since the feature branch was created. Run:
   ```bash
   git diff origin/main...HEAD
   ```
   If the user is on a different base branch, ask.

2. Cross-reference against:
   - `docs/features/$1/03-design.md`
   - `CLAUDE.md`
   - `docs/coding-standards.md` (if present)

3. Produce a structured review per the code-reviewer agent's output format. Save to `docs/features/$1/06-code-review.md`.

4. Print the summary section to chat: counts by severity + verdict (`APPROVE` / `APPROVE WITH NITS` / `CHANGES REQUESTED`).

5. If `CHANGES REQUESTED`, list the Blocker and High findings inline so the user can decide what to fix immediately.

Do not modify code in this phase — review only.
