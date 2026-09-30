---
description: Phase 4 — Task breakdown from approved design.
argument-hint: <FEATURE-ID>
---

Break the approved design for `$1` into implementation tasks.

Prerequisites:
- `docs/features/$1/03-design.md` (approved)
- `docs/features/$1/03b-threat-model.md` (approved, required mitigations folded in)

Steps:

1. Read both prerequisites.

2. Slice the design into **vertical slices** — one task each. A slice is one coherent behaviour, delivered test-first **with its own unit and integration tests**, that leaves the build green and is reviewable as one commit.

   **Size by agent capability, not by layer or file:**
   - ~300–600 lines of production code (plus its tests), one plan → implement → verify loop, one clear acceptance check traceable to `01-requirements.md` ACs.
   - Task count follows from size: estimated production lines in `03-design.md` ÷ ~400, plus a slice only where a risk genuinely needs isolating. A typical story is **2–6 tasks**; a small one is 1. More than 8 needs a one-line justification at the top of the file.

   **Never a task on its own:**
   - A single class, port, DTO, exception, or constant — it belongs to the slice that uses it.
   - Tests without the code they test (breaks test-first). Cross-cutting ITs go with the slice they prove.
   - Docs, runbooks, `monitoring.md`, story/epic text fixes — Phase 9 (`/docs`) or the Definition of Done.
   - Tracking or follow-up items — backlog, not `04-tasks.md`.
   - A threat-model condition — fold its mitigation into the slice it protects.

   For each task:
   - **ID** (T-001, T-002, ...) and **Title** (the behaviour, e.g. "Assign role with last-admin protection")
   - **Description** and **ACs covered**
   - **Dependencies** (which task IDs must complete first)
   - **Files impacted** (existing) and **files created** (new)
   - **Complexity:** S / M / L
   - **Risks** — name authorization, locking/concurrency, or cryptography explicitly when present (drives model escalation in `/implement`)
   - **Tests** — the unit / integration / e2e cases written first for this slice
   - **Definition of Done**

3. End the file with two traceability tables so nothing is lost by slicing coarser:
   - **Threat → task:** every required mitigation in `03b-threat-model.md` → the task that implements it.
   - **AC → task:** every acceptance criterion in `01-requirements.md` → the task(s) that prove it.

4. If `01-requirements.md` marks the feature a hot path (peak > 10 RPS or on every request), add a load test to the **Tests** of the slice that owns the hot path, asserting its p95 latency budget. If it states no budget, send that back as a Gate 1 gap rather than inventing one.

5. Save to `docs/features/$1/04-tasks.md`.

6. If the Atlassian MCP is connected, offer to create matching Jira sub-tasks under `$1`. Ask before creating.

Approval gate before `/implement $1 T-001`.
