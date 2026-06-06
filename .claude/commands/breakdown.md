---
description: Phase 4 — Task breakdown from approved design.
argument-hint: <JIRA-ID>
---

Break the approved design for `$1` into implementation tasks.

Prerequisites:
- `docs/features/$1/03-design.md` (approved)
- `docs/features/$1/03b-threat-model.md` (approved, required mitigations folded in)

Steps:

1. Read both prerequisites.

2. Produce a task list with this structure for each task:
   - **ID** (T-001, T-002, ...)
   - **Title**
   - **Description**
   - **Dependencies** (which task IDs must complete first)
   - **Files impacted** (existing) and **files created** (new)
   - **Complexity:** S / M / L
   - **Risks**
   - **Testing requirements** — unit, integration, e2e
   - **Definition of Done**

3. Group as:
   ```
   Epic: $1
   ├─ Database (migrations / schema)
   ├─ Backend
   │   ├─ Domain
   │   ├─ Application
   │   ├─ Infrastructure
   │   └─ Interfaces (controllers)
   ├─ Frontend
   │   ├─ Services / state
   │   └─ Components / routes
   ├─ Cross-cutting (security mitigations, feature flag, observability)
   ├─ Tests (load scenarios, e2e)
   └─ Documentation
   ```

4. Save to `docs/features/$1/04-tasks.md`.

5. If the Atlassian MCP is connected, offer to create matching Jira sub-tasks under `$1`. Ask before creating.

Approval gate before `/implement $1 T-001`.
