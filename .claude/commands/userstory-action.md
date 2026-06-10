---
description: Batch action workflow (Phases 5–10) for an approved feature.
argument-hint: <FEATURE-ID>
---

Run the **action half** of the operating model for feature `$1`: implement → review → security → test audit → docs → release prep.

Preconditions — these approved plan artifacts must exist (numbered convention, see `docs/README.md`):
`01-requirements.md`, `02-impact.md`, `03-design.md`, `03b-threat-model.md`, `04-tasks.md`. If any are missing, stop and run `/userstory-plan $1` (or `/new-feature $1`) first.

Delegate to the phase commands in order:

1. `/implement $1 <TASK-ID>` — once per task in `04-tasks.md`, test-first, plan-mode gate per task (backend-engineer / frontend-engineer)
2. `/review $1` → `06-code-review.md` (code-reviewer) — must reach `APPROVE` / `APPROVE WITH NITS`
3. `/security-review $1` → `07-security-review.md` (security-reviewer) — no unresolved Blockers
4. `/test-validate $1` → `08-test-audit.md` (qa-engineer) — coverage gates green
5. `/docs $1` → `09-technical.md`
6. `/release-prep $1` → `10-release/` (release-manager) — verdict must be `READY`

Rules:
- Run `/pre-pr-check` before opening the PR — it runs the same gates CI enforces.
- Schema changes are append-only Flyway migrations (`ddl-auto=validate`, ADR 0003).
- A feature is not done until: all tasks complete, all gates green, code + security reviews passed, docs updated, release plan `READY`.
