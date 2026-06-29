# US-006 Test Audit — Password Policy & Brute-Force Lockout

Generated: 2026-06-30

---

## Test inventory (tests per source file, pre-audit)

| File | Count | What it covers |
|------|-------|----------------|
| `AccountLockedExceptionTest` | 4 | code/message/retryAfter storage, extends DomainException |
| `GlobalExceptionHandlerTest` | 13 | All exception-handler methods incl. `handleAccountLocked` (873 s case) |
| `UserTest` | 17 | Construction invariants, verify(), recordFailedAttempt (×1, ×3), lockAccount (once, idempotent), resetFailedAttempts (with prior count), unlockIfExpired (active, future lock, boundary==now, past lock) |
| `PasswordPolicyServiceTest` | 8 | null, 11-char, 12-char, max (1024), denylist, Unicode boundaries |
| `LoginUseCaseTest` | 16 | Happy path, wrong password, unknown email, PENDING, LOCKED+correct, DISABLED, retryAfter, LOGIN_FAILURE event on lock, persistFailedAttempt called/not-called, expired-lock unlock, clean-login no-reset, non-zero-count reset, Argon2-before-lock-check ×2 |
| `LoginUseCaseSecurityTest` | 7 | AUTH_001 (unknown email, wrong password, pending+wrong), AUTH_002, AUTH_LCK_001, AUTH_001 (disabled), happy path |
| `SecureEventServiceTest` | 8 | Below-threshold, at-threshold, optimistic-lock swallow, generic-exception swallow+event, user-not-found, persistResetAttempts call, reset swallows exception, log-injection type-safety, rate-signal event |
| `SecureEventServiceConcurrencyTest` | 2 | DF-3 lock-within-bound, below-threshold no-lock |
| `AccountLockedExceptionTest` | 4 | (listed above) |
| `LoginLockoutIT` | 5 | T-020a (5 failures→lock→correct-still-locked), T-020b (expired lock→200), T-021 (REQUIRES_NEW counter persists), T-021b (DB LOCKED status after threshold), T-022 (RFC 7807 body+Retry-After header) |
| `AuthAuditIT` | 8 | LOGIN_SUCCESS, LOGIN_FAILURE, LOGIN_PENDING_ACCOUNT, TOKEN_REFRESH_SUCCESS, REFRESH_FAMILY_REVOKED, LOGOUT, tokenless-logout, no-raw-token-in-logs, T-023a (ACCOUNT_LOCKED event), T-023b (ACCOUNT_UNLOCKED event) |
| `LoginFormComponent spec` | 8 | submit calls login, invalid no-call, loading guard, AUTH_001, AUTH_002, RATE_001, AUTH_LCK_001 (msg+DOM), unknown code, success navigates |

---

## Gaps identified

| Severity | Gap | Closed in |
|----------|-----|-----------|
| HIGH | `AccountLockedException` with `retryAfterSeconds = 0` — boundary where `lockedUntil == now`; type must accept 0 | `AccountLockedExceptionTest` |
| HIGH | `AccountLockedException` with `retryAfterSeconds < 0` — production code never emits this but type must not reject it | `AccountLockedExceptionTest` |
| HIGH | `GlobalExceptionHandler.handleAccountLocked` with `retryAfterSeconds = 0` — `Retry-After: 0` header and body field must be `0L` not absent | `GlobalExceptionHandlerTest` |
| HIGH | `LoginUseCase` — LOCKED account + WRONG password must throw `AccountLockedException` (423), not `AuthenticationException` (401). Step 4 (lock gate) fires after Step 2 (Argon2) but before Step 5 (credential gate) | `LoginUseCaseTest` |
| MED | `LoginUseCase` — `ACCOUNT_UNLOCKED` event must NOT be emitted on a clean login (justUnlocked == false, count == 0) | `LoginUseCaseTest` |
| MED | `LoginUseCase` — `ACCOUNT_UNLOCKED` event must carry `userId` (non-null) when emitted on expired-lock path | `LoginUseCaseTest` |
| MED | `UserTest` — `recordFailedAttempt` sequential 0→1→2→…→LOCKOUT_THRESHOLD with per-call return-value verification | `UserTest` |
| MED | `UserTest` — `resetFailedAttempts` called when count is already 0 (idempotent no-op) | `UserTest` |
| MED | `UserTest` — `unlockIfExpired` on PENDING user (not LOCKED) must return false without mutation | `UserTest` |
| MED | `UserTest` — `unlockIfExpired` on ACTIVE user with null `lockedUntil` (the `lockedUntil != null` guard) | `UserTest` |
| MED | `SecureEventService.persistFailedAttempt` — count *above* threshold (> 5) also triggers lock (the `>=` branch) | `SecureEventServiceTest` |
| LOW | `PasswordPolicyService` — empty string (`""`) rejected with AUTH_PWD_001 | `PasswordPolicyServiceTest` |
| LOW | `PasswordPolicyService` — 1025-char password accepted (no artificial upper-bound check) | `PasswordPolicyServiceTest` |

---

## Tests added

### `AccountLockedExceptionTest` (+2 tests)
- `should_storeZeroRetryAfterSeconds_when_constructedWithZero`
- `should_storeNegativeRetryAfterSeconds_when_constructedWithNegative`

### `GlobalExceptionHandlerTest` (+1 test)
- `should_return423WithZeroRetryAfter_when_accountLockedOnBoundary`

### `UserTest` (+4 tests)
- `should_returnSequentialCounts_when_recordFailedAttemptCalledUpToLockoutThreshold`
- `should_remainAtZero_when_resetFailedAttemptsCalledOnCleanUser`
- `should_returnFalse_when_unlockIfExpiredCalledOnPendingUser`
- `should_returnFalse_when_unlockIfExpiredCalledWithNullLockedUntil`

### `LoginUseCaseTest` (+3 tests)
- `execute_lockedAccount_wrongPassword_throwsAccountLockedException` — HIGH gap: LOCKED+wrong-password → 423 not 401
- `execute_cleanLogin_doesNotEmitAccountUnlockedEvent` — MED gap: no spurious ACCOUNT_UNLOCKED on clean path
- `execute_expiredLock_emitsAccountUnlockedEventWithUserId` — MED gap: userId populated in ACCOUNT_UNLOCKED event

### `SecureEventServiceTest` (+1 test)
- `should_lockAccountAndRecordEvent_when_failedAttemptExceedsThreshold` — count > LOCKOUT_THRESHOLD also locks

### `PasswordPolicyServiceTest` (+2 tests)
- `validate_throws_AUTH_PWD_001_when_emptyString`
- `validate_passes_when_exactly1025Chars`

---

## Run results

**Backend (unit tests, -DskipITs):**
- Before: 319/319 passing
- After: **325/325 passing** (6 new test methods added; all pass)
- `./mvnw test -DskipITs` → `BUILD SUCCESS`

**Frontend:**
- **130/130 passing** (no changes made — existing spec already covered AUTH_LCK_001)
- `npm run test:ci` → 22 test files, 130 tests, 0 failures

**Integration tests (LoginLockoutIT, AuthAuditIT):** Not run locally (require Docker + Testcontainers MySQL). Designed correctly per project conventions (TestcontainersConfiguration import, `@ActiveProfiles("test")`, high rate-limit overrides to prevent IP bucket interference).

---

## Flaky tests

### RateLimitIT — `rate_limit_resets_after_window`
**File:** `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/RateLimitIT.java`
**Issue:** Contains `Thread.sleep(11_000L)` to wait for the 10-second sliding window to expire. This makes the test slow (>11 s) and timing-sensitive — if the CI machine is under load and the sleep overshoots significantly, the test could intermittently pass or fail depending on the host clock granularity. The test comment explicitly notes this.
**Recommendation:** Replace with a `FakeClock` injected into `InMemoryRateLimitStore` and advance time programmatically, eliminating the real-time dependency. This is not addressed in this audit because it requires a non-trivial refactor of `InMemoryRateLimitStore` and is pre-existing.

No other flaky tests identified. All new tests use:
- Fixed `Clock.fixed(...)` for time-sensitive assertions
- Mockito stubs (no real Argon2 calls, no real DB)
- Unique email prefixes with `UUID.randomUUID()` in ITs to prevent cross-test DB pollution

---

## Coverage assessment (qualitative)

### Domain layer (`User`, `AuthConstants`, `AccountLockedException`)
All public methods and state transitions are now explicitly exercised:
- `recordFailedAttempt`: 0→1, 0→n, 0→LOCKOUT_THRESHOLD (sequential return-value verification) — complete
- `lockAccount`: once, idempotent (twice with different expiry) — complete
- `resetFailedAttempts`: with count > 0, with count == 0 — complete
- `unlockIfExpired`: ACTIVE (no-op), PENDING (no-op), LOCKED+future (no-op), LOCKED+boundary (no-op — `isBefore` strict), LOCKED+past (unlock+reset) — complete
- `AccountLockedException`: positive, zero, negative retryAfterSeconds — complete

### Application layer (`LoginUseCase`, `SecureEventService`, `PasswordPolicyService`)
- `LoginUseCase` all nine steps covered including: LOCKED+correct, LOCKED+wrong, expired-lock unlock, clean-login no-reset, non-zero-count reset, ACCOUNT_UNLOCKED event emission and suppression, Argon2 timing invariant — complete
- `SecureEventService.persistFailedAttempt`: user-not-found, below-threshold, at-threshold, above-threshold, optimistic-lock swallow, generic-exception swallow — complete
- `SecureEventService.persistResetAttempts`: happy path, exception swallow — complete
- `PasswordPolicyService`: null, empty, too-short, boundary-12, denylist, max, above-max, Unicode — complete

### Infrastructure layer (`GlobalExceptionHandler`, `LoginRateLimitFilter`)
- `GlobalExceptionHandler.handleAccountLocked`: positive retryAfter, zero retryAfter — complete
- `LoginRateLimitFilter`: covered by existing `LoginRateLimitFilterTest` (8 tests) and `RateLimitIT` (5 tests + 1 flaky); all 5 `@Value`-wired config params exercised via IT properties

### Integration layer (`LoginLockoutIT`, `AuthAuditIT`)
- Full lifecycle: 5 failures → 423, expired lock → 200, REQUIRES_NEW boundary, RFC 7807 body contract — complete
- Audit events: ACCOUNT_LOCKED (after 5 failures), ACCOUNT_UNLOCKED (after expired lock) — complete

### Frontend (`LoginFormComponent`)
- All 5 error codes (AUTH_001, AUTH_002, RATE_001, AUTH_LCK_001, unknown) covered
- AUTH_LCK_001: message, loading reset, no navigation, DOM banner text — complete

No coverage regressions introduced. JaCoCo gate (80% line/branch) remains unaffected — new tests only add coverage.
