# US-006 Technical Documentation — Enforce Password Policy & Brute-Force Lockout

> Design: [03-design.md](03-design.md) · Threat model: [03b-threat-model.md](03b-threat-model.md)
> Security review: [07-security-review.md](07-security-review.md) · Test audit: [08-test-audit.md](08-test-audit.md)

## 1. Overview

US-006 adds two complementary brute-force defences to the login path:

1. **DB-backed account lockout** — after 5 consecutive failed login attempts, a user account transitions to `LOCKED` status for 15 minutes. The lock is global (not per-IP) and is durably stored in MySQL, making it effective against distributed attacks from rotating source IPs.

2. **Rate-limit config split** — the previously monolithic `max-attempts` / `window-seconds` config is split into five distinct parameters (IP login bucket, user login bucket, refresh IP bucket) to allow independent tuning of each throttle layer.

The feature also splits `PasswordPolicyService` error codes (`AUTH_PWD_001` for length, `AUTH_PWD_002` for denylist) and adds a frontend error message for `AUTH_LCK_001`.

---

## 2. Architecture

### 2.1 Login flow (9-step sequence)

```
POST /api/v1/auth/login
  │
  ▼  [Servlet — pre-MVC]
LoginRateLimitFilter
  ├─ IP bucket (10/60 s)          ──→ 429 RATE_001 if exceeded
  └─ USER-HMAC bucket (5/900 s)   ──→ 429 RATE_001 if exceeded
  │
  ▼  [Spring MVC → Application layer]
LoginUseCase.execute()
  Step 1  findByTenantAndEmailHmac  (found flag only — no branch)
  Step 2  Argon2id verify           ALWAYS RUNS (T-2.2 / T-LCK-5)
  Step 3  unlockIfExpired(now)       in-memory only; commit deferred to Step 8b
  Step 4  LOCKED pre-check          ──→ 423 AUTH_LCK_001 if LOCKED
  Step 5  credential gate           ──→ 401 AUTH_001 if !found || !passwordMatch
  Step 6  status allowlist          ──→ 403 AUTH_002 (PENDING) or 401 (DISABLED+)
  Step 7  issue access JWT
  Step 8  persist refresh token
  Step 8b persistResetAttempts      only if failedAttemptCount > 0 || justUnlocked
  Step 9  record LOGIN_SUCCESS
```

### 2.2 Failure counter path (REQUIRES_NEW)

When Step 5 fires (credential failure), `SecureEventService.persistFailedAttempt` is called in a **new, independent transaction** (`@Transactional(propagation = REQUIRES_NEW)`). This is critical because the outer `LoginUseCase` transaction rolls back on `AuthenticationException`, which would silently discard any counter writes in the same TX.

Inside `persistFailedAttempt`:
1. Re-read the `User` in the new TX (latest counter from DB).
2. Call `user.recordFailedAttempt()`.
3. If `count >= LOCKOUT_THRESHOLD`, call `user.lockAccount(now + 900s)` and emit `ACCOUNT_LOCKED`.
4. Call `userRegistrationPort.save(user)` — normal JPA save here (increments `@Version`).
5. `ObjectOptimisticLockingFailureException` → swallowed as a benign lost increment (concurrent race).
6. Any other exception → WARN log + `ACCOUNT_LOCKED_WRITE_FAILED` audit event + NOT rethrown.

### 2.3 Reset counter path (JPQL bulk UPDATE — M-OL-1 fix)

On successful login, `SecureEventService.persistResetAttempts` calls `resetFailedAttemptsDirect` — a JPQL `UPDATE` that bypasses the `@Version` optimistic-lock check:

```sql
UPDATE User u SET u.failedAttemptCount = 0, u.lockedUntil = NULL WHERE u.id = :userId
```

**Why not `findById + save`?** The outer `LoginUseCase` TX already called `unlockIfExpired()` on the same entity in its session, mutating it in memory. If `persistResetAttempts` ran in REQUIRES_NEW with a `save()`, it would commit at `version = V+1`. The outer session would then flush at `version = V`, causing `ObjectOptimisticLockingFailureException` → HTTP 500 on successful login (M-OL-1). The bulk UPDATE leaves `version` untouched so both sessions flush cleanly. See ADR 0009.

### 2.4 Auto-expiry

`User.unlockIfExpired(Instant now)` evaluates in-memory at Step 3 (strict `isBefore` — accounts locked until exactly `now` are NOT auto-unlocked). The state change only commits if login succeeds (Step 8b via `persistResetAttempts`). If the user provides the wrong password on an expired lock, the lock remains until they provide correct credentials.

---

## 3. Key Security Decisions

| Decision | Rationale |
|----------|-----------|
| Argon2 runs before lockout check (Step 2 before Step 4) | Eliminates timing oracle: locked accounts take the same wall-clock time as wrong-password attempts (T-LCK-5). |
| DB lockout is global (not per-IP) | Effective against distributed botnets that rotate IPs (T-LCK-2). IP bucket is a rate-limiter, not the lockout gate. |
| Lockout does NOT revoke refresh families (DF-4) | Brute-force lockout ≠ credential compromise. An attacker who fails 5 logins does not hold a valid refresh token for that account. US-007 password reset will revoke all families. |
| `retryAfterSeconds` disclosed in 423 body and `Retry-After` header | Standard HTTP semantics needed by legitimate clients; minor attacker value (DF-5, accepted). |
| LOCKOUT_WINDOW_SECONDS is defined but not enforced | Implementation counts all failures since the last successful login, not a rolling window. Constant retained for future rolling-window implementation and documentation. |
| IP bucket uses `getRemoteAddr()` only, never XFF (DF-1) | XFF headers are attacker-controllable. Effective only in single-instance deployments without a reverse proxy — documented as a deployment precondition. DB lockout remains globally authoritative regardless. |
| `AUTH_PWD_002` is an exact-match denylist (DF-6) | Trivial mutations bypass it. Documented in `PasswordPolicyService` Javadoc. Normalization (case-fold + leet-collapse) is future work. |

---

## 4. HTTP Contract Changes

### `POST /api/v1/auth/login` — new response code

**423 Locked** (account locked after repeated failures):

```http
HTTP/1.1 423 Locked
Content-Type: application/problem+json
Retry-After: 874

{
  "status": 423,
  "detail": "Account locked. Try again later or reset your password.",
  "code": "AUTH_LCK_001",
  "retryAfterSeconds": 874,
  "traceId": "a1b2c3d4"
}
```

- `retryAfterSeconds` is the remaining lock duration in seconds (≥ 0). When the lock has just expired and auto-expiry committed, this is 0.
- `Retry-After` header equals `String.valueOf(retryAfterSeconds)`.
- Body never contains email, password, stack trace, or Java class names.

### `POST /api/v1/auth/login` — unchanged codes

| Code | Meaning |
|------|---------|
| 200 | Successful login |
| 400 | Bean validation failure |
| 401 AUTH_001 | Invalid credentials (unknown email or wrong password — identical response) |
| 403 AUTH_002 | Account not verified (PENDING status) |
| 429 RATE_001 | IP or user-HMAC rate limit exceeded (from `LoginRateLimitFilter`) |

### `PasswordPolicyService` error code split

| Code | Condition |
|------|-----------|
| `AUTH_PWD_001` | Password shorter than 12 characters |
| `AUTH_PWD_002` | Password is in the denylist (exact-match) |

---

## 5. Configuration

See [deployment.md](deployment.md) for the full environment-variable reference.

```yaml
nexus:
  security:
    rate-limit:
      store-type: memory            # memory | redis
      ip-max-attempts: 10           # Login IP bucket ceiling
      ip-window-seconds: 60         # Login IP bucket window
      user-max-attempts: 5          # Login user-HMAC bucket ceiling
      user-window-seconds: 900      # Login user-HMAC bucket window
      refresh-max-attempts: 30      # Refresh IP bucket ceiling
```

Lockout thresholds are code constants (not config) to prevent misconfiguration in production:

```java
AuthConstants.LOCKOUT_THRESHOLD        = 5    // consecutive failures before lock
AuthConstants.LOCKOUT_DURATION_SECONDS = 900  // 15 minutes
```

---

## 6. Audit Events

| Event | Trigger |
|-------|---------|
| `LOGIN_FAILURE` | Every failed login (wrong credentials or on a locked account) |
| `ACCOUNT_LOCKED` | Account transitions to LOCKED status |
| `ACCOUNT_UNLOCKED` | Expired lock auto-clears on successful login |
| `ACCOUNT_LOCKED_WRITE_FAILED` | Inner REQUIRES_NEW TX fails on a non-optimistic exception |
| `LOGIN_SUCCESS` | Successful login |

All events include `userId` (where known) and `ipAddress` from `RequestContext`. No email addresses or passwords are logged.

---

## 7. Domain Model Changes (`User` aggregate)

New methods added to `User` (all in `identity.domain`):

| Method | Description |
|--------|-------------|
| `recordFailedAttempt() → int` | Increments `failedAttemptCount`, returns new value |
| `lockAccount(Instant lockedUntil)` | Sets status = LOCKED, sets `lockedUntil`. Idempotent. |
| `resetFailedAttempts()` | Zeroes counter, clears `lockedUntil`. Does NOT change status. |
| `unlockIfExpired(Instant now) → boolean` | If LOCKED and `lockedUntil.isBefore(now)`, transitions to ACTIVE, resets counter. Returns whether unlock occurred. |

---

## 8. Known Limitations & Future Work

- **Rolling window not enforced** — failures accumulate since the last successful login. An attacker who fails 2 attempts, waits a year, then fails 3 more will lock the account. A future rolling-window implementation can use `LOCKOUT_WINDOW_SECONDS = 900` which is already defined.
- **Concurrency race (DF-3)** — under very high concurrency, a few extra failed attempts may slip through before the lock is persisted. The optimistic-lock collision is swallowed as benign. An atomic `UPDATE failed_attempt_count = failed_attempt_count + 1` would eliminate this but was deferred (MVP).
- **IP rate limit behind a proxy (DF-1)** — `getRemoteAddr()` is the proxy IP in proxied deployments. Redis bucket + `ForwardedHeaderFilter` is the future path.
- **No CAPTCHA or device fingerprinting** — explicitly out of scope; part of a future anti-fraud layer.
