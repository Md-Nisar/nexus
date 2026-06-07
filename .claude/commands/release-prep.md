---
description: Phase 10 — Release readiness artifacts and production-readiness gate.
argument-hint: <FEATURE-ID>
---

Use the **release-manager** sub-agent to produce release artifacts for feature `$1`.

Prerequisites — all of these must exist:
- `docs/features/$1/06-code-review.md` with verdict `APPROVE` or `APPROVE WITH NITS`
- `docs/features/$1/07-security-review.md` with no unresolved Blockers
- `docs/features/$1/08-test-audit.md` showing green test runs

Steps:

1. Generate the five release artifacts under `docs/features/$1/10-release/`:
   - `deployment-checklist.md`
   - `rollback-checklist.md`
   - `smoke-test-checklist.md`
   - `monitoring-checklist.md`
   - `production-readiness-report.md`

2. Each checklist item must have an owner. Where the user hasn't named one, leave `[ASSIGN: <role>]` so it's obvious.

3. In `production-readiness-report.md`, answer every question in the agent spec and conclude with a verdict: **READY / READY WITH CAVEATS / NOT READY**.

4. Print to chat:
   - Verdict
   - Any caveats
   - Top 3 things the deploy team must not miss

If verdict is `NOT READY`, list the blockers and stop.
