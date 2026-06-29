# US-006 Impact Analysis

## Summary

US-006 hardens the login path with two independent brute-force defenses plus a P1 password-policy error-code split. All required schema (the `failed_attempt_count`, `locked_until` columns and the `LOCKED` enum value) already exists in `V2__identity_schema.sql`, so **no Flyway migration is required**. The work is concentrated in the Identity bounded context: the `User` domain aggregate gains lockout state-transition methods, `LoginUseCase` gains the lockout lifecycle (pre-check, increment, lock, reset, auto-expire), a new `AccountLockedException` maps to HTTP 423 in `GlobalExceptionHandler`, the IP rate-limit config is reshaped from 5/300s to a split 10/60s IP bucket, and the Angular login form adds an `AUTH_LCK_001` case. The single highest-risk item is **transaction semantics**: `LoginUseCase` is `@Transactional` and throws on failed login, so the failed-attempt counter increment and lock write must commit via a `REQUIRES_NEW` boundary (the existing `SecureEventService` pattern) or they will be rolled back and the counter will never advance.

---

## Affected Files

### Backend — Modify (existing files that need changes)

| File path | Layer | Change summary |
|-----------|-------|----------------|
| `nexus-backend/src/main/java/com/example/nexus/identity/domain/User.java` | domain | Add state-transition methods: `recordFailedAttempt()` (increment + return count), `lockAccount(Instant until)` (set `status=LOCKED`, `lockedUntil`), `resetFailedAttempts()` (zero count, clear `lockedUntil`), `unlockExpired(Instant now)` (if `LOCKED` and `lockedUntil` past → `ACTIVE`). All mutate currently read-only fields (`failedAttemptCount`, `lockedUntil`, `status`). No new columns. |
| `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthConstants.java` | domain | Add `LOCKOUT_THRESHOLD=5`, `LOCKOUT_WINDOW_SECONDS=900`, `LOCKOUT_DURATION_SECONDS=900` (window == duration per requirements assumption #3). |
| `nexus-backend/src/main/java/com/example/nexus/identity/application/service/LoginUseCase.java` | application | Core change. Insert lockout pre-check after the ACTIVE gate / before token issuance; auto-expire (`unlockExpired`) at lookup; on credential failure for a *found* user, increment counter and lock at threshold; reset counter on success. Must keep Argon2-always invariant (Q1=a: run Argon2 before returning 423 to preserve timing uniformity). Add `AUTH_LCK_001` constant and throw new `AccountLockedException`. **Transaction caveat — see Top Risk #1.** New audit events `ACCOUNT_LOCKED` / `ACCOUNT_UNLOCKED`. |
| `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/LoginRateLimitFilter.java` | infrastructure/web | Constructor currently injects a single `max-attempts`/`window-seconds` pair used for **both** IP and USER buckets. Split into `ip-max-attempts` (10), `ip-window-seconds` (60) and `user-max-attempts`/`user-window-seconds` (Q3=a). The `handleLogin` `tryConsume` calls must use the correct per-bucket values. (Q2=a: keep the email-HMAC USER bucket alongside DB lockout.) |
| `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/InMemoryRateLimitStore.java` | infrastructure/security | Constructor reads `${nexus.security.rate-limit.window-seconds}` for its eviction interval. When that key is renamed/split, update the `@Value` reference (e.g. to the IP window) so the eviction thread still starts. Behavioral logic unchanged. |
| `nexus-backend/src/main/resources/application.yml` | config | Reshape `nexus.security.rate-limit` block: replace `max-attempts: 5` / `window-seconds: 300` with `ip-max-attempts: 10`, `ip-window-seconds: 60`, `user-max-attempts`, `user-window-seconds`. |
| `nexus-backend/src/main/resources/application-test.yml` | config | Mirror the renamed rate-limit keys so `*IT` and `@Value`-wired beans resolve. **Breaking if not updated — context fails to start.** |
| `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java` | interfaces (advice) | Add `@ExceptionHandler(AccountLockedException.class)` returning `ResponseEntity<ProblemDetail>` with `HttpStatus.LOCKED` (423) and a `Retry-After` header (seconds until `lockedUntil`). Mirror the existing `handleRateLimit` shape. |
| `nexus-backend/src/main/java/com/example/nexus/identity/application/PasswordPolicyService.java` | application (P1, AC-4) | Split error code: keep `AUTH_PWD_001` for length violations; use new `AUTH_PWD_002` for denylist (breach) matches (Q4=a). Two distinct codes/messages. |

### Backend — Create (net-new files)

| File path | Layer | Purpose |
|-----------|-------|---------|
| `nexus-backend/src/main/java/com/example/nexus/common/domain/AccountLockedException.java` | common.domain | New `DomainException` subclass carrying `retryAfterSeconds`; maps to HTTP 423 + `AUTH_LCK_001`. Mirror `RateLimitException` (which already carries `retryAfterSeconds`). |

> No new outbound port is required — `UserRegistrationPort.save(User)` is reused for lockout-state persistence (requirements assumption #4). No Redis adapter (Q5=b; in-memory store is sufficient for MVP).

### Frontend — Modify

| File path | Change summary |
|-----------|----------------|
| `nexus-frontend/src/app/features/auth/login-form/login-form.component.ts` | Add `case 'AUTH_LCK_001':` to the error `switch` (line ~167) setting the message "Too many attempts. Try again later or reset your password." (AC-2 — no attempt count). |

### No-change files (explicitly confirmed)

- `nexus-backend/src/main/resources/db/migration/V2__identity_schema.sql` — already contains `failed_attempt_count INT NOT NULL DEFAULT 0`, `locked_until DATETIME(6) NULL`, and `status ENUM(... 'LOCKED' ...)`. **No migration needed.**
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/UserStatus.java` — `LOCKED` already present.
- `nexus-backend/src/main/java/com/example/nexus/identity/application/port/out/UserRegistrationPort.java` — `save(User)` reused; no new method.
- `nexus-backend/src/main/java/com/example/nexus/identity/application/port/out/RateLimitStore.java` / `RateLimitResult.java` — abstraction already supports per-bucket `windowSeconds`/`maxAttempts` args; no signature change.
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/LoginController.java` — no change; `AccountLockedException` propagates to `GlobalExceptionHandler` like the existing `AuthenticationException`.
- `nexus-frontend/src/app/core/http/api-error.interceptor.ts` — status-agnostic; surfaces any RFC 7807 `code` (incl. 423/`AUTH_LCK_001`) to the component unchanged.
- `nexus-frontend/src/app/features/auth/auth.service.ts` — passes errors through; no change.
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaUserRegistrationAdapter.java` / `JpaUserRepository.java` — `save` already covers updates.

---

## Database Impact

- **Migration required: No.** All columns and the `LOCKED` enum value already exist in `V2__identity_schema.sql` (lines 17, 20–21). `ddl-auto=validate` (ADR-0003) will pass because the entity already maps them.
- **Tables affected:** `users` — `failed_attempt_count` and `locked_until` will now be **written** on failed/locked/reset paths (currently they are read-only / always default). `auth_events` — two new `event_type` values (`ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`); the column is `VARCHAR(64)`, so no schema change.
- **Index changes: None.** The login lookup is already served by `uq_users_tenant_id_email_hmac`. The lockout update is by primary key. `idx_users_tenant_id_status` is unaffected. No new query patterns introduced.
- **Write volume:** failed-login path adds one `UPDATE users` (counter, and on threshold the lock fields) guarded by `@Version` optimistic lock; successful login after a non-zero counter adds one reset `UPDATE`.

---

## API Contract Changes

- **New status code:** `POST /api/v1/auth/login` may now return **423 Locked** with a `Retry-After` header. (429 for IP rate limit already exists.)
- **New error codes:** `AUTH_LCK_001` (locked account, 423). `AUTH_PWD_002` (breached/denylisted password, 400) on `POST /api/v1/auth/register` (and future `/reset`, US-007).
- **Breaking vs additive:**
  - **Additive** for login — existing clients route unknown codes through their `default` branch (the frontend already does).
  - **Minor contract change** for registration — `AUTH_PWD_002` replaces `AUTH_PWD_001` for the *denylist* path; clients/tests asserting `AUTH_PWD_001` on a denylisted password will break and must be updated.
- **No versioning change:** stays on `/api/v1`; no new endpoints.

---

## Test Impact

### Existing tests that will BREAK (assertions change)

| Test file | Break reason |
|-----------|-------------|
| `identity/application/service/LoginUseCaseTest.java` | Asserts `LOCKED` user → `AuthenticationException`/`AUTH_001`; new behavior throws `AccountLockedException`/`AUTH_LCK_001` (423). Must be rewritten. User mocks need stubs for `getFailedAttemptCount()`/`getLockedUntil()` and new methods. |
| `identity/application/service/LoginUseCaseSecurityTest.java` | `should_returnAuth001_when_accountLocked` has the same problem; update to expect `AUTH_LCK_001`/423. Wrong-password tests need verification that counter increments and `save` is invoked. |
| `identity/infrastructure/web/LoginRateLimitFilterTest.java` | Constructor called as `new LoginRateLimitFilter(store, blindIndex, 5, 300)`; after IP/user config split, arity/params change. Every test needs the new constructor signature; `tryConsume` stubs must reflect IP window (60) / max (10). |
| `identity/application/PasswordPolicyServiceTest.java` | `validate_throws_when_denylistEntry` asserts `AUTH_PWD_001`; after split must assert `AUTH_PWD_002`. Length/null tests keep `AUTH_PWD_001`. |
| `identity/interfaces/rest/RegistrationControllerIT.java` | Any test exercising a denylisted password must expect `AUTH_PWD_002` (add case if missing for AC-4 coverage). |
| `auth/login-form/login-form.component.spec.ts` | Add `AUTH_LCK_001` case test mirroring the existing `RATE_001` test. |

### Existing tests that need EXTENSION (no break, add cases)

- `common/web/GlobalExceptionHandlerTest.java` — add `should_return423WithRetryAfter_when_accountLocked` mirroring the 429 test.
- `identity/domain/UserTest.java` — add tests for the four new state-transition methods (increment, lock, reset, auto-expire incl. boundary at exactly `lockedUntil`).

### New test classes / files required

- `LoginUseCase` lockout-lifecycle unit test set: 5 failures → lock; 4 + success → reset; auto-expire after window → success. Covers Test Scenarios #1, #2.
- Integration test (`*IT`, Testcontainers MySQL, never H2 per TESTING.md) for the **full 423 HTTP contract** and **auto-expiry** — no `Login*IT` currently exists. Must assert `Retry-After` is present and counter persistence survives the failed-login rollback (Top Risk #1). Covers Scenario #1, #4.
- Security/timing assertion: locked-account latency ≈ normal-401 latency (Argon2-always; Scenario #4), following the pattern in `RegistrationControllerIT`.

---

## Integration Points

- **Task sequencing (dependencies):**
  1. `AuthConstants` + `AccountLockedException` + `GlobalExceptionHandler` handler (foundation, no deps)
  2. `User` state-transition methods (no deps; enables 3)
  3. `LoginUseCase` lockout logic (depends on 1 + 2). **Resolve the transaction-boundary decision before coding** (Risk #1).
  4. `LoginRateLimitFilter` + `application*.yml` config split (independent of 1–3, but must update `application-test.yml` in the same change or `*IT` contexts fail to start)
  5. `PasswordPolicyService` `AUTH_PWD_002` split (independent P1; touches registration tests)
  6. Frontend `AUTH_LCK_001` case (depends only on the contract from 1; can proceed in parallel)

- **Concurrent-write / optimistic-locking:** `User` carries `@Version`. Two racing failed logins can collide on the counter `UPDATE`, throwing `OptimisticLockingFailureException`. A lost increment under contention is benign (worst case: attacker gets one extra attempt), but the exception must **not** surface as 500 — catch it and treat as a normal failed attempt.

- **Cross-layer:** the IP filter (servlet layer, pre-MVC) and the DB lockout (application layer) are deliberately independent enforcement points (Q2=a). They share no state; the filter owns 429/`RATE_001`, the use-case owns 423/`AUTH_LCK_001`.

---

## Top 3 Risks

1. **Failed-attempt counter lost to transaction rollback (Critical).** `LoginUseCase` is `@Transactional` and throws `AuthenticationException` on a wrong password, rolling back the same transaction that would persist the incremented `failed_attempt_count`. If the increment runs in the outer transaction, it is rolled back and the counter never advances — lockout silently never triggers. **Mitigation:** persist the counter/lock via a `REQUIRES_NEW` boundary, reusing the exact pattern already proven by `SecureEventService.recordEvent`. Add an `*IT` that asserts the counter actually increments across five separate failed HTTP calls.

2. **Config rename breaks application startup and the test suite (High).** The IP/user rate-limit split renames `nexus.security.rate-limit.max-attempts` / `window-seconds`, which are bound via `@Value` in both `LoginRateLimitFilter` and `InMemoryRateLimitStore` and set in `application.yml` and `application-test.yml`. A partial rename causes `PlaceholderResolutionException` at context startup, failing every `@SpringBootTest`/`*IT`. **Mitigation:** rename keys in all three places (both YAML profiles + both `@Value` references) atomically; update `LoginRateLimitFilterTest`'s explicit constructor calls in the same commit.

3. **Lockout-as-DoS and timing side-channel (Medium).** An attacker can deliberately lock a victim's account (`AUTH_LCK_001` reveals the account exists). Skipping Argon2 on a known-locked account leaks a timing oracle distinguishing locked vs. active accounts. **Mitigation:** run Argon2 unconditionally before returning 423 (Q1=a) so locked-account latency matches the normal failed path; document the accepted enumeration trade-off (OWASP lockout guidance) and rely on the US-007 password-reset escape path plus a support runbook.
