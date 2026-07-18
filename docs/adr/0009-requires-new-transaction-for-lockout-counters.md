# ADR 0009 — REQUIRES_NEW + Bulk UPDATE for Lockout Counter Writes

**Status:** Accepted; the "Redis atomic increment" alternative below is superseded/adopted by
**ADR 0016** (Redis adopted as an infrastructure dependency) as an additive fast path in front of
this ADR's MySQL mechanism, which otherwise remains authoritative and unchanged.
**Date:** 2026-06-30
**Feature:** US-006 (Brute-force lockout)

---

## Context

The login flow runs inside an `@Transactional` method on `LoginUseCase`. On a failed login, the outer transaction is rolled back when `AuthenticationException` is thrown. Failure-counter increments and account-lock writes must persist to MySQL even when the surrounding transaction rolls back — otherwise the lockout mechanism is silently disabled.

Two related constraints interact:

1. **Counter writes must survive outer TX rollback** — counter increments need their own transaction that commits independently.

2. **Reset writes must not collide with `@Version`** — on successful login, `LoginUseCase` calls `user.unlockIfExpired()` in-memory, mutating the entity at `version = V`. If `persistResetAttempts` then runs in REQUIRES_NEW and saves the same entity with `findById + save`, it commits at `version = V+1`. When the outer session later flushes its in-memory entity (still at `version = V`), Hibernate throws `ObjectOptimisticLockingFailureException`, producing an HTTP 500 on a successful login (M-OL-1).

---

## Decision

### For failure-counter writes (`persistFailedAttempt`)

Use `@Transactional(propagation = REQUIRES_NEW)` with a standard `findById → mutate → save` pattern. This re-reads the entity in a fresh TX, increments the counter, and commits atomically. `ObjectOptimisticLockingFailureException` (two concurrent failures racing) is swallowed as a benign lost increment. All other exceptions are caught, logged at WARN with `userId` only, emit an `ACCOUNT_LOCKED_WRITE_FAILED` audit event, and are NOT rethrown — the caller always throws AUTH_001, never a 500.

### For reset writes (`persistResetAttempts`)

Use a JPQL bulk UPDATE that bypasses the `@Version` check entirely:

```java
@Modifying(clearAutomatically = true)
@Query("UPDATE User u SET u.failedAttemptCount = 0, u.lockedUntil = NULL WHERE u.id = :userId")
int resetFailedAttemptsDirect(@Param("userId") UUID userId);
```

`clearAutomatically = true` flushes the first-level cache after the bulk UPDATE so any subsequent reads in the same session reflect the reset state. The outer session's in-memory entity (which `unlockIfExpired()` already mutated in memory) is flushed at `version = V` without collision.

---

## Consequences

**Benefits:**
- Failure counters always commit, even when the outer login TX rolls back — lockout is reliable.
- Successful logins always complete without `ObjectOptimisticLockingFailureException` — no HTTP 500 on unlock.
- The catch policy in `persistFailedAttempt` makes the lockout system fail-safe: a write failure causes a logged/observable signal but never exposes a 500 to the unauthenticated caller.

**Trade-offs:**
- REQUIRES_NEW opens a second DB connection briefly. Connection pool must be sized `>= 2 × max_concurrent_login_threads`. In practice this is negligible for the expected RPS.
- The bulk UPDATE bypasses `@Version` — if the counter row is otherwise modified concurrently, the bulk UPDATE silently wins. This is safe because `resetFailedAttemptsDirect` only clears to `0`, and a concurrent `persistFailedAttempt` in REQUIRES_NEW would immediately set a new count in its own TX.
- Future features that need similar "commit even on outer TX rollback" semantics must follow the same REQUIRES_NEW pattern on `SecureEventService` or an equivalent service. Do **not** put REQUIRES_NEW on infrastructure adapters — transaction demarcation stays at the application layer.

**Rule for future work:** Any write that must survive an outer transaction rollback belongs in a `SecureEventService` method (or equivalent application-layer service) with `@Transactional(propagation = REQUIRES_NEW)`. If that write touches an entity that the outer session has already mutated in memory, use a JPQL bulk UPDATE (bypassing `@Version`) rather than `findById + save`.

---

## Alternatives Considered

| Option | Rejected because |
|--------|-----------------|
| Write counters in the same outer TX | Rolled back on failure — lockout is disabled |
| `SELECT FOR UPDATE` + pessimistic lock | Serialises all concurrent logins; unacceptable latency |
| Atomic `UPDATE count = count + 1` for all counter writes | Would also fix the concurrency race (DF-3) but requires native SQL or a more complex JPQL update; deferred to a future improvement (the current approach is correct for the threshold-based check) |
| Redis atomic increment | Eliminates per-JVM state and solves DF-3; deferred to when Redis is added as a dependency (future story) — **adopted per ADR 0016**: `INCR`/`EXPIRE` Lua fast path layered in front of this ADR's unchanged MySQL write path, fail-closed to the mechanism above on Redis outage |
