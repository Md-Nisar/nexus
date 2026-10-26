---
name: critical-decisions
description: Use in Phase 3 design when 01-requirements.md lists fired design triggers (T1–T9), and in Phase 5 when an implementation task hits a trigger the design did not cover. Records each guarantee as invariant → mechanism → proof test, choosing the simplest mechanism that holds. Not for stories whose design triggers are `none`.
---

# Critical Decisions

Most stories need no system-design or algorithmic analysis. This skill is for the few decisions where a design claim tends to break at runtime: concurrency, cross-row invariants, transaction boundaries, unbounded growth, hot paths, shared infrastructure, staleness promises and large data. For each one, record the decision in the smallest form that can be checked, and name the test that proves it.

## 1. Inputs and the "none" path

- Read the `Design triggers:` line in `01-requirements.md`. The triggers are defined in `feature-discovery` §4a.
- **If it says `none`**, write one line in `03-design.md` and stop:

  > **Critical decisions:** none — no design trigger fired.

- **If the line is missing**, treat it as a Gate 1 gap.
  - Evaluate the T1–T9 table yourself.
  - Record the result at the top of the *Critical decisions* section. Don't edit the approved `01-requirements.md`.
  - Flag the gap in chat.

## 2. The table

Put a `## Critical decisions` section in `03-design.md`. Every fired trigger must be covered by at least one row; one row may cover several triggers.

| Invariant | Trigger | Mechanism | Simplest that holds | Rejected alternative | Proof test |
|---|---|---|---|---|---|
| A refresh token rotates at most once, and a revoked token never rotates | T1 | `UPDATE refresh_tokens SET revoked_at=?, version=version+1 WHERE id=? AND revoked_at IS NULL`; 0 rows → `AUTH_004`; the successor is inserted only after 1 row changed | One statement; it re-checks the very state that revocation changes | `@Version` + `save()`: the conflict only surfaces at commit, outside the `catch`, and bulk revokes don't bump the version | `RefreshTokenRotationIT.should_rotateExactlyOnce_when_twoRefreshesRace`: exactly one 200, one 401 `AUTH_004`, one active token in the family, no `TOKEN_REFRESH_SUCCESS` row for the loser |

**What each column must contain:**
- **Invariant:** an observable statement a test can check. "Handles concurrency" is not one.
- **Mechanism:** the concrete statement, constraint, lock, data structure or bound, and where it runs relative to the transaction boundary.
- **Simplest that holds:** why nothing lighter on the ladder (§3) would do.
- **Rejected alternative:** at least one, with the reason. If you are proposing something heavier than the ladder suggests, say which requirement forces it.
- **Proof test:** the test class, method and exact assertion. It must meet `docs/TESTING.md` → *Tests that prove a guarantee*.

**One-line rows are fine** when you reuse a proven pattern unchanged. Cite the pattern and the existing test that already proves it. Example:

> T3 — permission check is an O(1) claim-set lookup, no DB call; reuses `TenantAwarePermissionEvaluator`, proven by `RequiresPermissionWebTest`.

## 3. Simplest-that-holds ladder

Prefer the lowest rung that keeps the invariant:

1. **A database constraint** (unique, FK, CHECK, generated column + unique index). The database enforces it for every writer.
2. **A single conditional statement:** `UPDATE … WHERE <expected state>`, using the affected-row count; or `SET n = n + 1`.
3. **A locking read or a single lock row** on a predicate that an index serves exactly.
4. **In-process coordination** (bounded structures, single-flight). Only for per-instance concerns.
5. **New shared infrastructure** (cache, Redis structure, queue, scheduler). Only for a need stated in `01-requirements.md` (RPS, latency budget, cross-instance correctness) that rungs 1–4 cannot meet. State the failure mode when it is down (`spring-boot-standards` → Resilience).

Before you climb a rung, ask what it adds and what breaks without it. The Redis permission cache is the cautionary example: it sits on a path that runs only at login and refresh, it costs more round trips than it saves, and its multi-command writes can leave entries with no TTL.

## 4. Data structures and complexity (only for T3, T4, T8)

- State **n**: its bound or expected size, from requirements or a cap in the code.
- State the per-operation cost on the hot path.
- Below about 10³ elements, choose the most readable structure. No bitsets or custom indexes.
- Above that, use `references/data-structure-choices.md`.

## 5. Capacity and transactions (only for T3, T6)

Add one capacity line per hot or transactional flow:

> Connections held per request: N (held during …) · Outbound calls inside the transaction: none / … · What bounds concurrency: …

The arithmetic is in `references/capacity-model.md`. Virtual threads mean the thread pool no longer bounds request concurrency.

## 6. Concurrency mechanisms (only for T1, T2)

Pick from `references/concurrency-patterns.md`. Each pattern there cites the class in this codebase that already does it right, and the proof-test shape to use.

## 7. Implementation time (Phase 5)

If a task hits a trigger that has no row in `03-design.md`:
1. **Stop.** Don't improvise a mechanism.
2. Put a proposed row in the task plan. The per-task plan gate decides on it.
3. If the row changes the design materially (a new constraint, new infrastructure, or a different transaction boundary), send it back to the architect to `Edit` `03-design.md`.

## Anti-patterns (each one has happened here)

- **Claiming a requirement is satisfied without a proof test.** US-004's design declared its AC-3 grace window met "at three layers"; the code has no grace window.
- **Load assumptions without numbers.** ADR 0009 called the cost of a second connection "negligible for the expected RPS", which stopped being true under virtual threads.
- **Adding infrastructure to save work on a path that rarely runs.**
- **Several definitions of one domain concept** across stories. "Administrator" ended up with four definitions across US-016 to US-018. Define it once, in the epic.
- **A critical-decisions table for a story whose triggers are `none`.** Or one restating requirements instead of mechanisms.
