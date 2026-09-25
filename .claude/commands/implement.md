---
description: Phase 5 — Implement a single task, test-first, with plan approval.
argument-hint: <FEATURE-ID> <TASK-ID>
---

Implement exactly one task: **`$2`** for feature **`$1`**.

Prerequisites:
- `docs/features/$1/04-tasks.md` (approved)

Routing:
- If the task is backend, use the **backend-engineer** sub-agent.
- If frontend, use **frontend-engineer**.
- If it spans both, do backend first, then frontend, in separate sub-agent invocations.

## Workflow

### Step 1 — Plan (mandatory)

Sub-agents cannot enter plan mode or wait for the user, so the gate is held by **this** session. Invoke the engineer agent with *"plan only — do not edit files"*; it returns:
- List of files to create / modify (with paths)
- Order of operations
- **Test cases to write FIRST** (specific test names)
- Any clarifications needed
- Dependencies on other tasks

Present the plan to the user. **Stop and wait for explicit user approval.** Do not invoke the agent for implementation until approved.

### Step 2 — Implementation (after approval)

Re-invoke the engineer agent with the approved plan included verbatim. Rules:
- Write the failing tests FIRST.
- Then implement to make them pass.
- Follow conventions in `PROJECT.md`, the standards skills, and the engineer agent's spec.
- Production-quality only — no placeholders, no `TODO`, no `FIXME`.
- Structured logging at boundaries.
- Explicit error handling.
- Use the feature flag named in the design doc.
- Run tests after each meaningful change.
- Stop and ask if blocked or if scope creeps beyond `$2`.

### Step 3 — Verification

- Run the full test suite for the affected side: `./mvnw verify -DskipITs` and/or `npm run test:ci`.
- Run `npm run build` if frontend changes — confirm no strict-template errors.
- Print diff summary to chat.
- Print test results.

### Step 4 — Suggest next steps

- If more tasks remain: remind user of the next task ID.
- If task `$2` was the last implementation task: suggest `/review $1`.

## Hard rules

- **One task per invocation.** Do not slide into the next task.
- **No green-lighting on red tests.**
- **No bypassing the plan-approval gate.**
