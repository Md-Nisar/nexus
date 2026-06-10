---
description: Canonical front door to the Nexus operating model — discovery → analysis → design → breakdown, with approval gates.
argument-hint: <FEATURE-ID> [short description]
---

Kick off feature **`$1`** through the mandatory operating model (full reference: `DEVELOPMENT_GUIDE.md` → Operating Model). This is the single entry point; it walks the plan half with hard approval gates, then hands off to implementation.

## Step 0 — Discovery (use the `feature-discovery` skill)
Apply the **feature-discovery** skill: frame the problem, do the reuse-first survey, build the impact map, flag NFR/security/observability concerns, list open questions. Create `docs/features/$1/` if absent.

## Step 1 — Requirements → **Gate 1**
Run `/analyze-story $1` (business-analyst) → `docs/features/$1/01-requirements.md`. Present open questions. **Stop for approval.**

## Step 2 — Impact analysis
Run `/impact-analysis $1` (architect) → `docs/features/$1/02-impact.md`.

## Step 3 — Design + API + DB + threat model → **Gate 2**
Run `/design $1` (architect + security-reviewer) → `docs/features/$1/03-design.md` and `03b-threat-model.md`. Design must cover, and be reviewed against the relevant skills:
- **API**: `api-design` skill — URLs, status codes, error shape, versioning, pagination.
- **DB**: Flyway migration plan, additive vs expand/contract (ADR 0003); indexes; audit columns.
- **Security**: STRIDE threat model; every threat gets a mitigation that becomes a task.
- **Frontend**: routes, components (smart/dumb), signals state, guards (`angular-standards`).
**Stop for approval.**

## Step 4 — Task breakdown → **Gate 3**
Run `/breakdown $1` (architect + engineers + qa-engineer) → `docs/features/$1/04-tasks.md`: sequenced tasks with dependencies, acceptance criteria, test plan, risk. **Stop for approval.**

## Handoff
After Gate 3, direct the user to implementation: `/implement $1 <TASK-ID>` per task (test-first, plan-mode gate), then `/review`, `/security-review`, `/test-validate`, `/pre-pr-check` before the PR. `/userstory-action $1` runs that half as a batch.

## Rules
- **No code, migrations, or frontend in the plan half.** Discovery/analysis/design/planning only.
- Never cross a gate without explicit user approval.
- Artifacts use the numbered convention (`docs/README.md`).
