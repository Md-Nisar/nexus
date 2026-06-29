# US-006 — Requirements: Enforce Password Policy and Brute-Force Lockout

## Problem Statement

Harden the login path so that repeated credential-stuffing attempts are throttled at two levels:
(1) **Account lockout** — track per-user consecutive failures in the DB; after 5 failures within 15 min, set `status=LOCKED` for 15 min and return 423 + `AUTH_LCK_001`; auto-expire on the next successful login after the window passes.
(2) **IP-level rate limiting** — reject more than 10 login attempts/min from the same IP with 429 + `Retry-After`.

Bounded context: **Identity** (`com.example.nexus.identity`).

---

## Reuse-First Survey

### Already implemented — no new code needed

| Artifact | Location | Status |
|----------|----------|--------|
| `users.failed_attempt_count` column | `V2__identity_schema.sql` | ✅ Schema already present |
| `users.locked_until` column | `V2__identity_schema.sql` | ✅ Schema already present |
| `UserStatus.LOCKED` enum value | `UserStatus.java` | ✅ Already in enum |
| `User` JPA fields (`failedAttemptCount`, `lockedUntil`) | `User.java` | ✅ Fields mapped |
| `LoginUseCase` LOCKED status gate | `LoginUseCase.java:151` | ✅ Blocks LOCKED — wrong code only |
| `UserRegistrationPort.save(User)` | `UserRegistrationPort.java` | ✅ Reuse for lockout state saves |
| `LoginRateLimitFilter` + `RateLimitStore` + `InMemoryRateLimitStore` | `infrastructure/web` + `infrastructure/security` | ✅ IP rate limiting infrastructure ready |
| `PasswordPolicyService` + denylist | `application/PasswordPolicyService.java` | ✅ Breach check at registration (P1 coverage) |
| `DomainException` hierarchy + `GlobalExceptionHandler` | `common/domain` + `common/web` | ✅ Exception wiring pattern to follow |
| `LoginFormComponent` error-code switch | `login-form.component.ts:167` | ✅ Extend with `AUTH_LCK_001` case |

### Must extend

| What | Where | Change |
|------|-------|--------|
| `User` domain | `domain/User.java` | Add `recordFailedAttempt()`, `lockAccount(Instant)`, `resetFailedAttempts()`, `unlockExpired(Instant)` methods |
| `AuthConstants` | `domain/AuthConstants.java` | Add `LOCKOUT_THRESHOLD=5`, `LOCKOUT_WINDOW_SECONDS=900`, `LOCKOUT_DURATION_SECONDS=900` |
| `LoginUseCase` | `application/service/LoginUseCase.java` | Pre-check lockout → 423; increment count on failure; lock after threshold; reset on success; auto-expire |
| `LoginRateLimitFilter` IP config | `application.yml` | Split IP config to 10/min; add lockout config section |
| `LoginFormComponent` | `login-form.component.ts` | Add `AUTH_LCK_001` case: "Too many attempts. Try again later or reset your password." |

### Must create (net-new)

| Artifact | Package | Purpose |
|----------|---------|---------|
| `AccountLockedException` | `common.domain` | Domain exception → 423 Locked + `AUTH_LCK_001` |
| `GlobalExceptionHandler` handler | `common.web` | Map `AccountLockedException` → 423 with `Retry-After` |

**No Flyway migration required** — V2 already has `failed_attempt_count`, `locked_until`, and the `LOCKED` status value.

---

## Acceptance Criteria (annotated)

| # | Criterion | Priority | Gap |
|---|-----------|----------|-----|
| 1 | 5 consecutive failed logins in 15 min → `status=LOCKED` for 15 min; returns 423 + `AUTH_LCK_001` | P0 | LoginUseCase has no count logic; returns AUTH_001 for LOCKED instead of 423+AUTH_LCK_001 |
| 2 | UI shows "Too many attempts. Try again later or reset your password." — no attempt count | P0 | LoginFormComponent has no `AUTH_LCK_001` case; falls through to generic error |
| 3 | >10 login attempts/min/IP → 429 + `Retry-After`; limit configurable | P0 | Filter exists but config is 5/300s (not 10/60s); needs split IP vs. account-lockout config |
| 4 | Registration/reset passwords checked against denylist → 400 + `AUTH_PWD_002` | P1 | `PasswordPolicyService` uses `AUTH_PWD_001` for all violations including denylist |
| 5 | After 15 min, login with correct credentials succeeds (auto-expire) | P0 | No unlock-on-login logic; no `lockedUntil` expiry check |

---

## Impact Map

### Backend layers

- **Domain**: `User` (new state-transition methods), new `AccountLockedException`, `AuthConstants` (new constants)
- **Application**: `LoginUseCase` (lockout logic, counter increment, auto-expiry, success reset), new auth event types (`ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`)
- **Infrastructure/security**: `application.yml` (new `nexus.security.lockout.*` config block)
- **Infrastructure/web**: `LoginRateLimitFilter` (IP limit config change only — no structural change)
- **Interfaces**: `GlobalExceptionHandler` (new 423 handler)

### Frontend

- `login-form.component.ts` — add `AUTH_LCK_001` error case

### API contract changes

- `POST /api/v1/auth/login` gains a new 423 response for locked accounts (additive, non-breaking for existing clients that handle unknown codes in their default branch)

### Data

- No schema changes — V2 migration already has the columns and `LOCKED` enum value
- `failed_attempt_count` and `locked_until` in `users` will be written on failed/locked paths

---

## Non-Functional & Risk Flags

### Security
- **Timing uniformity (AC-4 test scenario)**: Argon2 must still run even when the account is detected as locked. Skipping Argon2 for locked accounts leaks a timing side-channel (attacker can distinguish "wrong password on active account" vs. "locked account" by latency).
- **Anti-enumeration preserved**: The lockout error (`AUTH_LCK_001`) reveals that an account exists for that email. This is the accepted trade-off per OWASP account-lockout guidance — the usability benefit outweighs the marginal enumeration risk at the locked-account stage.
- **DoS via lockout**: Attacker can lock a victim account. Mitigated by the password-reset escape path (US-007) plus support runbook (documented in threat model).

### Performance
- Lockout check adds two DB writes on failed path (read is already done for auth): one `UPDATE users SET failed_attempt_count = ..., locked_until = ... WHERE id = ?`. Target: adds <20ms to login.
- `failed_attempt_count` is guarded by the JPA `@Version` optimistic lock — concurrent racing failures are safe.

### Observability
- New audit events: `ACCOUNT_LOCKED` (when threshold crossed) and optionally `ACCOUNT_UNLOCKED` (when auto-expiry fires).
- Log `WARN` when an account is locked; include `userId` + `tenantId` (masked IP in MDC).

---

## Open Questions for Gate 1

| # | Question | Impact if unresolved |
|---|----------|----------------------|
| Q1 | **Timing uniformity for locked accounts**: Should Argon2 run before returning 423? Adds ~100ms but prevents timing-based locked-account detection. | Security posture; implementation order in LoginUseCase |
| Q2 | **Dual-layer rate limiting**: Keep the per-email-HMAC bucket in `LoginRateLimitFilter` (currently 5/300s) alongside DB-based account lockout (5/900s)? Or drop the HMAC filter bucket and rely solely on DB lockout? | Config complexity; AC-3 only mandates IP limiting |
| Q3 | **IP rate limit config reshape**: AC-3 says >10/min/IP. The filter currently shares one `max-attempts` for both IP and email-HMAC buckets. Should we split into two config properties (`nexus.security.rate-limit.ip-max-attempts` and `nexus.security.rate-limit.user-max-attempts`)? | Breaking change to existing config key |
| Q4 | **AUTH_PWD_001 → AUTH_PWD_002 split (P1)**: Should this story rename the breach-check error code, or defer to US-007 (password reset)? The code change is tiny but touches existing tests. | Error-code contract; potentially deferred |
| Q5 | **Redis adapter scope**: AC-3 notes "Redis token bucket" and the story has "External: Redis" as a dependency. Is a Redis `RateLimitStore` adapter in scope for this sprint, or is in-memory acceptable for MVP? | Infra dependency; Redis needs to be running in CI |

---

## Assumptions

1. No Flyway migration is needed — V2 already contains the lockout columns.
2. Auto-expiry is done inline at login time (not a background job): if `lockedUntil` is in the past when login is attempted, unlock and proceed.
3. Consecutive failure window (15 min) and lockout duration (15 min) are the same value (900 s) — a single constant covers both.
4. The `UserRegistrationPort.save(User)` is reused for lockout state persistence (no new port needed).
5. Redis adapter is out of scope for MVP; the `RateLimitStore` abstraction already supports a future swap.
6. P1 item (AC-4 `AUTH_PWD_002`) will be implemented in this story if time permits, treating it as a minor error-code rename in `PasswordPolicyService`.
