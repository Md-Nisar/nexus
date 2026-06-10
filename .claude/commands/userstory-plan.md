---
description: Batch plan workflow (Phases 1–4) for a Jira story. Prefer /new-feature.
argument-hint: <FEATURE-ID>
---

Run the **plan half** of the operating model end to end for feature `$1`: requirements → impact → design (+ threat model) → task breakdown, stopping at each approval gate.

This is the batch entry point. For the guided, single front-door experience use **`/new-feature $1`** — it is the canonical entry to the operating model documented in `DEVELOPMENT_GUIDE.md`.

Delegate to the phase commands in order, honoring their approval gates:

1. `/analyze-story $1` → `docs/features/$1/01-requirements.md` (business-analyst) — **Gate 1**
2. `/impact-analysis $1` → `docs/features/$1/02-impact.md` (architect)
3. `/design $1` → `docs/features/$1/03-design.md` + `03b-threat-model.md` (architect + security-reviewer) — **Gate 2**
4. `/breakdown $1` → `docs/features/$1/04-tasks.md` (architect + engineers + qa-engineer) — **Gate 3**

Rules:
- Artifacts use the **numbered convention** (`docs/README.md` → Feature documentation). No code, no migrations, no frontend in this half.
- Do not cross an approval gate without explicit user approval.
- After Gate 3, stop and direct the user to the action half: `/userstory-action $1` or per-task `/implement $1 <TASK-ID>`.
