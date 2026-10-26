# Concurrency patterns (T1, T2)

The default isolation level is MySQL InnoDB REPEATABLE READ. Pick the lowest pattern that keeps the invariant. Then prove it per `docs/TESTING.md` → *Tests that prove a guarantee*, using real concurrency on Testcontainers MySQL.

## Summary

| # | Pattern | Use when | Model in this codebase |
|---|---|---|---|
| 1 | Unique constraint as the guard | "At most one X per key" | `user_roles.active_key` (V5) + `JpaUserRoleAssignmentAdapter` |
| 2 | Conditional UPDATE + row count | One-way state transitions, single-use consumption, counters | RBAC revoke in `JpaUserRoleRepository` |
| 3 | `@Version` with flush inside the `try` | You need the loaded entity anyway, and one row is involved | `VerifyEmailUseCase` (`authTokenPort.flush()`) |
| 4 | Locking read (`FOR UPDATE` / `FOR SHARE`) | The decision depends on a few current rows | `JpaUserRoleRepository` M5/M11 (mind the footprint) |
| 5 | Single lock row (per-scope mutex) | An invariant spans many rows or tables (write skew) | Not yet in the codebase; recommended for last-admin |
| 6 | Write that survives rollback | Failure-path audit or counter | `SecureEventService` (`REQUIRES_NEW`) |
| 7 | Client single-flight + server grace | Rotating credentials refreshed by several callers or tabs | `authInterceptor` `shareReplay` (single tab only) |

## 1. Unique constraint as the guard

- **Mechanism:**
  - Rely on a unique index rather than check-then-insert.
  - MySQL has no partial indexes, so use a STORED generated column that is `NULL` for inactive rows, with a unique index on it.
- **Code:**
  - `saveAndFlush` inside a `try`.
  - Map `DataIntegrityViolationException` (constraint name) to the domain outcome, such as 409 or the duplicate path.
- **Pitfall:** without the flush, the violation fires at commit and escapes as a 500. `RegisterUserUseCase` does this today.
- **Proof:** two threads insert the same key. Exactly one row exists; one caller gets success and the other the mapped outcome. A 500 is never acceptable.

## 2. Conditional UPDATE with row count

- **Mechanism:**
  - State transition: `UPDATE t SET state=? WHERE id=? AND state=<expected>`.
  - Counter: `SET n = n + 1`, or `SET n = IF(<window expired>, 1, n + 1)`.
- **Row count:** 0 rows means you lost the race, or the state had already moved. Map it to the domain outcome. Read back the counter if the result drives a decision (e.g. a lockout threshold).
- **Why prefer it:**
  - One round trip; no lost updates.
  - It re-checks exactly the state that other writers change.
  - It also fences bulk revocations, which bypass `@Version`.
- **Proof:** N threads (N ≥ 2) race on the same row. Exactly one transition, or exactly N increments.

## 3. `@Version` with an explicit flush

- **Mechanism:**
  - Load the entity, mutate it, then call `flush()` / `saveAndFlush()` **inside** the `try` that catches `OptimisticLockingFailureException`.
  - Every bulk JPQL update on the same table must also run `version = version + 1`.
- **Pitfall:** a plain `save()` on a managed entity issues no SQL. The conflict surfaces at commit, outside your `catch`.
- **Proof:** two transactions load the same version and both commit. One wins; the other gets the mapped domain error, not a 500.

## 4. Locking read

- **Mechanism:** `SELECT … FOR UPDATE` (exclusive) or `FOR SHARE` on the rows the decision depends on, before you decide. Take locks in a deterministic order (e.g. by id) to avoid deadlocks.
- **Footprint:** under REPEATABLE READ, InnoDB locks every index record the scan touches, including historical or revoked rows and gaps.
  - The index must match the full predicate (e.g. `(role_id, revoked_at, user_id)`, not just `role_id`).
  - Select ids only, not `SELECT *`.
- **Pitfall:**
  - Any plain (snapshot) read made **before** the lock can be stale when you decide. Make every read the decision depends on after the lock, as a locking read.
  - If that read set is large or spread out, use pattern 5.
- **Proof:** the racing writer blocks, then sees the committed state. Assert the invariant after both commit.

## 5. Single lock row (per-scope mutex)

- **Mechanism:**
  - Keep one row per scope, e.g. `rbac_tenant_lock(tenant_id PK)`.
  - Every mutation that can affect the invariant runs `SELECT … FOR UPDATE` on that row as its **first** statement. All later reads in the transaction then see a consistent state.
- **Use for:** write skew, where two transactions each read the invariant as holding, change different rows, and together break it. Example: revoking an admin while detaching a permission from another admin role.
- **Cost:** it serialises mutations within one scope. That is fine for low-rate admin operations; don't use it on per-request paths.
- **Proof:** run both racing operations, whose rows don't overlap. Assert that after both commit the invariant still holds (e.g. at least one qualifying admin).

## 6. Writes that must survive rollback

- **Options, in preferred order:**
  1. Record after rollback with a `TransactionSynchronization.afterCompletion(STATUS_ROLLED_BACK)` callback. This holds no extra connection.
  2. Use `REQUIRES_NEW`.
- **Costs of `REQUIRES_NEW`:**
  - It takes a second pooled connection while the first is held.
  - Never call it while holding row locks.
  - Never use it for success-path events; those belong in the outer transaction.
  - Size the pool per `capacity-model.md`.
- **Best-effort writes:** a write that must never fail the caller needs its own `TransactionTemplate`, with the `try/catch` around `execute`. Catching inside an outer transaction is too late, because the outer transaction is already rollback-only.
- **Proof:** make the business operation fail. In a new transaction, read the row back and assert it exists.

## 7. Client single-flight and server grace window

- **Client side:**
  - One refresh observable, owned by one service and shared by guards and interceptors.
  - Use `shareReplay` without `refCount`, so it can't be cancelled by one subscriber leaving.
  - Bound it with `timeout()`.
  - Calls made from inside the flow bypass the interceptor (`HttpContextToken`).
  - Across tabs, use `navigator.locks.request(...)` and broadcast the result.
- **Server side:** presenting the immediately previous token within N seconds of its rotation returns "already rotated" without revoking the family.
- **Proof:**
  - Run the real service and interceptor. Assert the downstream request was sent and completed.
  - Fire two concurrent refreshes, and assert the family is not revoked.
