# US-006 Task Breakdown

## Epic: US-006 — Enforce Password Policy and Brute-Force Lockout

**Source artifacts:** `docs/features/US-006/03-design.md`, `docs/features/US-006/03b-threat-model.md`.

**Gate 2 decisions folded in:**
- **DF-1:** MVP runs single-instance / no reverse proxy. No `ForwardedHeaderFilter` this sprint. Documented as a precondition (T-019, T-024).
- **DF-2:** `persistFailedAttempt` catches `OptimisticLockingFailureException` (lost increment, benign) AND all other exceptions (log WARN with `userId` only, emit `ACCOUNT_LOCKED_WRITE_FAILED` audit event); the caller still throws `AUTH_001`. Never surfaces as 500 (T-006, M-8).

**Global constraints (apply to every task):**
- Test-first: unit tests are written before or alongside implementation in the same task/commit.
- All integration tests carry the `*IT` suffix and run on Testcontainers MySQL (never H2).
- `application.yml` and `application-test.yml` config-key changes MUST land in the same commit as the `@Value` references and the filter/store constructors that read them (Group 4, T-009).
- `auth_events.event_type` is `VARCHAR(64)`; all new event types (`ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`, `ACCOUNT_LOCKED_WRITE_FAILED`) fit — no schema change.

**Sequencing summary:**
- Group 1 (verify) → no deps; do first.
- Group 2 (domain) → no deps; blocks Group 3.
- Group 3 (application) → internal order: T-006 before T-007; T-008 independent.
- Group 4 (config split) → ONE atomic task (T-009).
- Group 5 (GlobalExceptionHandler) → depends only on T-004; parallel to Group 3.
- Group 6 (frontend) → no backend deps; fully parallel.
- Group 7 (security mitigations) → each references the implementing task; tests depend on their target group.
- Group 8 (integration tests) → depends on all backend groups completing.
- Group 9 (docs) → finalize after all decisions are recorded.

---

## Group 1: Database

### T-001 — Verify existing schema satisfies US-006 (no migration)

**Description:** Confirm that `V2__identity_schema.sql` already provides every column and enum value US-006 needs, so that NO new Flyway migration is created. Verify `users` has: `failed_attempt_count INT NOT NULL DEFAULT 0`, `locked_until DATETIME(6) NULL`, `version BIGINT NOT NULL DEFAULT 0`, and `status ENUM('PENDING','ACTIVE','LOCKED','DISABLED')` including `LOCKED`. Confirm `auth_events.event_type` is `VARCHAR(64)`. Confirm `User.java` JPA mappings (`failedAttemptCount` line 49, `lockedUntil` line 52, `@Version version` line 59) match. Document the finding in the PR description — no file changes expected.

**Dependencies:** None
**Files impacted:** None (verification only)
**Files created:** None
**Complexity:** S
**Risk:** Someone adds a redundant Flyway migration, or a column type assumption is wrong and only surfaces at `ddl-auto=validate` startup.
**Testing requirements:**
- Unit: none.
- Integration: rely on the existing `IdentitySchemaMigrationIT`; no new test required.
- Frontend: none.
**Definition of Done:**
- [ ] All four columns + `LOCKED` enum value + `version` confirmed in V2.
- [ ] `User.java` mappings confirmed matching.
- [ ] `event_type VARCHAR(64)` confirmed to accommodate new event strings.
- [ ] "No Flyway migration required" explicitly recorded in the task/PR notes.

---

## Group 2: Backend — Domain

### T-002 — AuthConstants: lockout threshold/window/duration constants ✅

**Description:** Add three constants to `AuthConstants.java` per design §3b: `LOCKOUT_THRESHOLD = 5`, `LOCKOUT_WINDOW_SECONDS = 900`, `LOCKOUT_DURATION_SECONDS = 900`. Keep window and duration as separate constants even though equal today — a future tuning change to one must not silently change the other. Class remains a non-instantiable constants holder (existing private-constructor pattern).

**Dependencies:** None
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthConstants.java`
**Files created:** None
**Complexity:** S
**Risk:** Reusing one constant for both window and duration, defeating the future-tuning intent.
**Testing requirements:**
- Unit: assertion confirming the three values are 5 / 900 / 900 and are distinct symbols.
- Integration: none.
- Frontend: none.
**Definition of Done:**
- [x] Three constants present with documented values.
- [x] Window and duration are separate fields.
- [x] Compiles; no instantiation possible.

---

### T-003 — User aggregate: state-transition methods ✅

**Description:** Add four state-transition methods to `User.java` per design §3a. Domain-only mutation; persistence stays in the application layer (hexagonal, ADR-0002 — `User` imports nothing from infrastructure).

- `int recordFailedAttempt()` — `failedAttemptCount += 1; return failedAttemptCount;`. Does NOT lock.
- `void lockAccount(Instant lockedUntil)` — sets `status = LOCKED` and `lockedUntil`; idempotent (overwrites `lockedUntil` if already locked). **Javadoc (M-9/DF-4):** document that refresh-token families are intentionally NOT revoked — lockout is a brute-force defense, not a compromise-response control; the extension point is `SecureEventService.revokeFamily` if future requirements change.
- `void resetFailedAttempts()` — `failedAttemptCount = 0; lockedUntil = null;`. Does NOT touch `status`.
- `boolean unlockIfExpired(Instant now)` — if `status == LOCKED` AND `lockedUntil.isBefore(now)` (strictly before; at exactly `lockedUntil` stays locked, matching the `Retry-After` contract), then set `status = ACTIVE`, `failedAttemptCount = 0`, `lockedUntil = null`, return `true`; else return `false` with no state change.

**Dependencies:** None
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/identity/domain/User.java`
**Files created:** None
**Complexity:** M
**Risk:** Off-by-one on the strict-before boundary (`isBefore` vs `!isAfter`) would unlock one second early and break the `Retry-After` contract; accidentally mutating `status` in `resetFailedAttempts`.
**Testing requirements:**
- Unit (`UserTest`, extended): `recordFailedAttempt` increments and returns the new count across successive calls; `lockAccount` sets status+instant and is idempotent on re-lock; `resetFailedAttempts` zeroes count and nulls `lockedUntil` without changing `status`; `unlockIfExpired` returns `false` when not LOCKED; returns `false` at exactly `lockedUntil` (boundary); returns `true` and resets all three fields strictly after `lockedUntil`.
- Integration: none (pure domain).
- Frontend: none.
**Definition of Done:**
- [x] All four methods present with the exact semantics above.
- [x] Strict-before boundary explicitly tested.
- [x] No infrastructure imports added to `User`.
- [x] `unlockIfExpired` resets count and `lockedUntil` on unlock.
- [x] M-9/DF-4 decision in `lockAccount` Javadoc.

---

### T-004 — AccountLockedException (new) ✅

**Description:** Create `AccountLockedException` in `com.example.nexus.common.domain`, mirroring `RateLimitException`: extends `DomainException`, carries `long retryAfterSeconds`, exposes `retryAfterSeconds()`. Constructor signature: `(String code, String message, long retryAfterSeconds)`. Thrown by `LoginUseCase` (T-007) as `new AccountLockedException("AUTH_LCK_001", "Account locked. Try again later or reset your password.", retryAfterSeconds)` where `retryAfterSeconds = max(0, secondsBetween(now, lockedUntil))`. Lives in `common.domain` (not `identity.domain`) so `GlobalExceptionHandler` in `common.web` can import it without cross-context layering violation.

**Dependencies:** None
**Files impacted:** None
**Files created:** `nexus-backend/src/main/java/com/example/nexus/common/domain/AccountLockedException.java`
**Complexity:** S
**Risk:** Placing it in `identity.domain` would force `common.web` to import `identity`, breaking hexagonal layering.
**Testing requirements:**
- Unit: assert `code()`, `getMessage()`, and `retryAfterSeconds()` round-trip the constructor args.
- Integration: none.
- Frontend: none.
**Definition of Done:**
- [x] Class in `common.domain`, extends `DomainException`.
- [x] `retryAfterSeconds` field + accessor.
- [x] Unit test green.

---

## Group 3: Backend — Application

### T-006 — SecureEventService: persistFailedAttempt + persistResetAttempts (incl. DF-2 / M-8) ✅

**Description:** Extend `SecureEventService.java` per design §4. Add `UserRegistrationPort` to the constructor (constructor injection only). Add two `@Transactional(propagation = REQUIRES_NEW)` methods that re-read the user **by id** (managed instance with fresh `@Version`) inside the new transaction — NOT the detached entity from the caller's rolling-back outer TX.

**`void persistFailedAttempt(UUID userId, Instant now)`:**
1. `findById(userId)`; if absent, no-op (user vanished between lookup and write — benign).
2. `int count = user.recordFailedAttempt();`
3. If `count >= LOCKOUT_THRESHOLD`: call `user.lockAccount(now.plusSeconds(LOCKOUT_DURATION_SECONDS))`, record an `ACCOUNT_LOCKED` event (`outcome=FAILURE`), log `WARN "ACCOUNT_LOCKED userId={} tenantId={}"` (no email/IP in clear).
4. `userRegistrationPort.save(user)`.
- **Exception handling (DF-2 / M-8):** Catch `OptimisticLockingFailureException` → log DEBUG "lost increment (benign)", return. Catch any other `Exception` (deadlock, pool timeout, connection loss) → log WARN with `userId` only, record an `ACCOUNT_LOCKED_WRITE_FAILED` audit event (`outcome=FAILURE`), return normally. Method NEVER rethrows — the caller still throws `AUTH_001`.

**`void persistResetAttempts(UUID userId)`:**
1. `findById(userId)`; if absent, no-op.
2. `user.resetFailedAttempts();`
3. `userRegistrationPort.save(user)`.
- Catch `OptimisticLockingFailureException` (reset will recur on next clean login) and other exceptions (WARN, no rethrow).

**Dependencies:** T-002, T-003
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/identity/application/service/SecureEventService.java`
**Files created:** None
**Complexity:** L
**Risk:** Catching too broadly could silently disable lockout under DB stress without a signal (mitigated by `ACCOUNT_LOCKED_WRITE_FAILED` event); re-reading the wrong instance or mutating the caller's detached entity breaks optimistic-lock semantics; emitting `ACCOUNT_LOCKED` outside the same TX as the `save` could desync the audit trail.
**Testing requirements:**
- Unit (`SecureEventServiceTest`, extended): increment-below-threshold → saves without locking, no `ACCOUNT_LOCKED` event; increment-at-threshold → locks with `lockedUntil == now + LOCKOUT_DURATION_SECONDS`, records `ACCOUNT_LOCKED`, logs WARN; `OptimisticLockingFailureException` from `save` → swallowed, no rethrow, no `ACCOUNT_LOCKED_WRITE_FAILED`; generic `RuntimeException` from `save`/`findById` → swallowed AND emits `ACCOUNT_LOCKED_WRITE_FAILED` (**DF-2 assertion**); `findById` empty → no-op; `persistResetAttempts` zeroes and saves, swallow-safe on both exception types.
- Integration: covered by T-021 (REQUIRES_NEW commit-after-rollback) and T-016 (concurrency).
- Frontend: none.
**Definition of Done:**
- [x] Both methods present, each `@Transactional(REQUIRES_NEW)`, re-reading by `userId`.
- [x] Threshold lock + `ACCOUNT_LOCKED` event + WARN log inside the boundary.
- [x] `OptimisticLockingFailureException` swallowed as benign (no `ACCOUNT_LOCKED_WRITE_FAILED`).
- [x] All other exceptions swallowed with WARN + `ACCOUNT_LOCKED_WRITE_FAILED` event; never rethrown (DF-2 / M-8).
- [x] `persistResetAttempts` only mutates count/`lockedUntil`, not `status`.
- [x] Constructor injection only for `UserRegistrationPort`.
- [x] Unit tests green for every exception branch.

---

### T-007 — LoginUseCase: revised 9-step flow with lockout pre-check and auto-expiry ✅

**Description:** Rework `LoginUseCase.execute(...)` per design §4 step order, preserving the Argon2-always invariant (Step 2 runs before any status/lock branch — Gate 1 Q1=a, closes timing oracle T-LCK-5).

**Revised step order:**
- **Step 1** Look up by tenant+emailHmac; set `found`; do not branch. *(unchanged)*
- **Step 2** Argon2 verify — ALWAYS runs (`found ? real hash : dummyHash`). *(unchanged)*
- **Step 3** Auto-expiry (found only): `boolean justUnlocked = user.unlockIfExpired(now)`. Hold as local flag; do NOT persist here — unlock commits only on the success path (Step 8b), so a wrong-password attempt after the window does not silently unlock.
- **Step 4** Lockout pre-check (found only, AFTER Argon2): if `user.getStatus() == LOCKED` → record a `LOGIN_FAILURE` audit event (lock-active rejection must be auditable), then `throw new AccountLockedException("AUTH_LCK_001", "...", max(0, secondsBetween(now, user.getLockedUntil())))`.
- **Step 5** Credential failure path (unknown user OR wrong password — identical code path): if `found` → call `secureEventService.persistFailedAttempt(user.getId(), now)` (REQUIRES_NEW; real users only, never unknown emails); record `LOGIN_FAILURE`; `throw new AuthenticationException("AUTH_001", "Invalid email or password")`.
- **Step 6** Status gate — ACTIVE allowlist *(unchanged)*: `PENDING → AUTH_002`; any non-ACTIVE other than already-handled LOCKED (e.g. DISABLED) → `AUTH_001`.
- **Step 7** Issue access JWT. *(unchanged)*
- **Step 8** Generate + persist refresh token. *(unchanged)*
- **Step 8b** On success, if `user.getFailedAttemptCount() > 0 || justUnlocked`: call `secureEventService.persistResetAttempts(user.getId())` (REQUIRES_NEW). If `justUnlocked`, also record `ACCOUNT_UNLOCKED` event (`outcome=SUCCESS`, INFO).
- **Step 9** Record `LOGIN_SUCCESS`; return tokens. *(unchanged)*

**Load-bearing note:** `LoginUseCase` is `@Transactional` and throws on the failed path, rolling back its outer transaction. The counter `UPDATE` MUST go through `SecureEventService` REQUIRES_NEW (T-006) or it is rolled back and the counter never advances (T-LCK-6). Never move the counter write into the outer transaction.

**Dependencies:** T-002, T-003, T-004, T-006
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/identity/application/service/LoginUseCase.java`
**Files created:** None
**Complexity:** L
**Risk:** Reordering Step 4 before Step 2 reopens the timing oracle (T-LCK-5); committing the unlock in Step 3 instead of 8b allows unauthenticated unlock (design 12.5); calling `persistFailedAttempt` for non-found users creates rows for unknown emails (enumeration, T-LCK-4).
**Testing requirements:**
- Unit (`LoginUseCaseTest` / `LoginUseCaseSecurityTest`, extended): LOCKED user → `AccountLockedException` with `code=AUTH_LCK_001`, non-negative `retryAfterSeconds`, a `LOGIN_FAILURE` recorded, and `persistFailedAttempt` NOT called; wrong password on found user → `persistFailedAttempt(user.getId(), now)` invoked then `AUTH_001`; unknown email → `persistFailedAttempt` NOT invoked; expired-lock + correct password → `unlockIfExpired` true, `persistResetAttempts` called, `ACCOUNT_UNLOCKED` recorded, tokens returned; clean login (`failedAttemptCount == 0`, `justUnlocked == false`) → `persistResetAttempts` NOT called; PENDING → `AUTH_002`; DISABLED → `AUTH_001`. Verify `PasswordVerifierPort.matches(...)` invoked on every path including LOCKED (M-1 invariant, see T-015).
- Integration: full lifecycle in T-020.
- Frontend: none.
**Definition of Done:**
- [x] Steps 1–9 + 8b implemented in the documented order.
- [x] Argon2 (Step 2) provably before the Step 4 lock branch.
- [x] `AccountLockedException` thrown with correct code, message, and `retryAfterSeconds = max(0, ...)`.
- [x] Counter write only for found users, via REQUIRES_NEW.
- [x] Auto-expiry committed only on success (Step 8b).
- [x] `persistResetAttempts` gated on `count > 0 || justUnlocked`.
- [x] `ACCOUNT_UNLOCKED` emitted only when `justUnlocked`.
- [x] Unit tests green for every branch.

---

### T-008 — PasswordPolicyService: AUTH_PWD_002 split (P1) + M-5 Javadoc ✅

**Description:** Split the single error code in `PasswordPolicyService.java` per design §8 (Gate 1 Q4=a). Replace `CODE`/`MESSAGE` with two pairs: `CODE_LENGTH = "AUTH_PWD_001"` / `MSG_LENGTH = "Password must be at least 12 characters."` for null/too-short; `CODE_DENYLIST = "AUTH_PWD_002"` / `MSG_DENYLIST = "Password is too common. Choose a less predictable password."` for denylist hits.

**M-5:** Update the class/method Javadoc to document the exact-match (`Set.contains`) limitation — trivial mutations (capitalisation, leetspeak, appended digits) bypass the denylist; case-fold + leet-collapse normalization is explicitly out of scope for this story. `AUTH_PWD_002` is a stable public contract code.

**Dependencies:** None (independent P1 task)
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/identity/application/PasswordPolicyService.java`
**Files created:** None
**Complexity:** S
**Risk:** Changing the error code consumed by the frontend register form without verifying the form handles or ignores `AUTH_PWD_002` gracefully.
**Testing requirements:**
- Unit (`PasswordPolicyServiceTest`, extended): null → `AUTH_PWD_001`; < 12 chars → `AUTH_PWD_001`; valid-length denylisted → `AUTH_PWD_002`; valid non-denylisted → no throw. Assert `field == "password"` and the new distinct messages.
- Integration: extend `RegistrationControllerIT` — a denylisted password returns `AUTH_PWD_002` (update any assertion that currently expects `AUTH_PWD_001` for a denylist hit).
- Frontend: none in this task (register form is out of US-006 frontend scope; verify it handles unknown codes gracefully and flag if it branches on `AUTH_PWD_001` vs `AUTH_PWD_002`).
**Definition of Done:**
- [x] Length/null → `AUTH_PWD_001`; denylist → `AUTH_PWD_002`.
- [x] Distinct messages per failure mode.
- [x] M-5 exact-match limitation documented in Javadoc.
- [x] Unit + register IT updated and green.

---

## Group 4: Backend — Infrastructure

### T-009 — Rate-limit config split (ATOMIC: yml + @Value + filter + store + filter test) ✅

**Description:** **ONE atomic commit.** Splitting config keys without simultaneously updating every `@Value` reference and the test constructors causes `PlaceholderResolutionException` at boot, failing the entire test suite.

Do ALL of the following together in one commit:

1. **`application.yml`** — replace `nexus.security.rate-limit.{max-attempts, window-seconds}` with:
   ```yaml
   nexus:
     security:
       rate-limit:
         store-type: memory
         ip-max-attempts: 10
         ip-window-seconds: 60
         user-max-attempts: 5
         user-window-seconds: 900
         refresh-max-attempts: 30
   ```

2. **`application-test.yml`** (same commit):
   ```yaml
   nexus:
     security:
       rate-limit:
         ip-max-attempts: 3
         ip-window-seconds: 10
         user-max-attempts: 3
         user-window-seconds: 10
   ```
   Note: the test profile uses 3/10s to keep ITs fast; coordinate with T-020 to ensure the 5th login attempt is reachable within the IP allowance.

3. **`LoginRateLimitFilter`** — new constructor with five `@Value` params: `ip-max-attempts`, `ip-window-seconds`, `user-max-attempts`, `user-window-seconds`, `refresh-max-attempts` (promote the hardcoded `30` literal at line 67). `handleLogin` calls `tryConsume("IP:"+clientIp, ipWindowSeconds, ipMaxAttempts)` and `tryConsume("USER:"+emailHmac, userWindowSeconds, userMaxAttempts)`. `handleRefresh` uses `ipWindowSeconds + refreshMaxAttempts`. Update class Javadoc to state 10/min/IP. Add DF-1 precondition note (single-instance / no-proxy; see T-019).

4. **`InMemoryRateLimitStore`** — repoint eviction `@Value` (line 48) from `${...window-seconds}` to `${...ip-window-seconds}`.

5. **`LoginRateLimitFilterTest`** — update all constructor calls to new arity in the SAME commit.

Also check `application-dev.yml` for any overrides of the old keys.

**Dependencies:** None (independent of Groups 2/3)
**Files impacted:** `nexus-backend/src/main/resources/application.yml`, `nexus-backend/src/main/resources/application-test.yml`, `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/LoginRateLimitFilter.java`, `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/InMemoryRateLimitStore.java`, `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/web/LoginRateLimitFilterTest.java`
**Files created:** None
**Complexity:** M
**Risk:** **Critical — startup breakage:** any straggler `@Value` referencing the old keys (`max-attempts` / `window-seconds`) fails placeholder resolution. Grep the entire `src/` tree for old keys before committing. Splitting across commits leaves a non-building intermediate state.
**Testing requirements:**
- Unit (`LoginRateLimitFilterTest`): IP bucket enforced at `ip-max-attempts` independently; USER bucket enforced at `user-max-attempts` independently; refresh path uses `refresh-max-attempts`; `Retry-After` is `max(ip, user)` on breach; new constructor arity exercised.
- Integration: a `@SpringBootTest` context startup with the split keys confirms no unresolved placeholders (the existing `NexusApplicationIT` or `NexusSmokeTest` covers this).
- Frontend: none.
**Definition of Done:**
- [x] Both yml files updated in the same commit.
- [x] All five files updated in the same commit; build green at HEAD.
- [x] `grep -r "rate-limit\.max-attempts\|rate-limit\.window-seconds" src/` returns no results.
- [x] `InMemoryRateLimitStore` reads `ip-window-seconds`.
- [x] `application-dev.yml` checked for old key overrides.
- [x] Context starts cleanly; `LoginRateLimitFilterTest` green.

---

## Group 5: Backend — Interfaces

### T-010 — GlobalExceptionHandler: 423 handler for AccountLockedException ✅

**Description:** Add `handleAccountLocked(AccountLockedException)` to `GlobalExceptionHandler.java` per design §5b, mirroring the existing `handleRateLimit` shape (lines 62–68). Returns `ResponseEntity<ProblemDetail>` with `HttpStatus.LOCKED` (423), `code = AUTH_LCK_001`, the exception message as `detail`, a `retryAfterSeconds` problem-document property, and a `Retry-After` header set to `retryAfterSeconds`. The existing `problem(...)` helper (lines 131–136) produces the `code` + `traceId` fields — no internals leak.

**Dependencies:** T-004
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java`
**Files created:** None
**Complexity:** S
**Risk:** Forgetting the `Retry-After` header (the contract requires it); returning a bare `ProblemDetail` instead of `ResponseEntity` (header would be lost).
**Testing requirements:**
- Unit (`GlobalExceptionHandlerTest`): `AccountLockedException("AUTH_LCK_001", "...", 873)` → status 423, body `code=AUTH_LCK_001`, `retryAfterSeconds=873`, header `Retry-After: 873`, `traceId` present.
- Integration: full HTTP contract asserted in T-022.
- Frontend: none.
**Definition of Done:**
- [x] `@ExceptionHandler(AccountLockedException.class)` returning `ResponseEntity<ProblemDetail>`.
- [x] 423 status, `AUTH_LCK_001` code, `retryAfterSeconds` property, `Retry-After` header.
- [x] `traceId` present via existing helper.
- [x] Unit test green.

---

## Group 6: Frontend

### T-011 — LoginFormComponent: AUTH_LCK_001 case + spec ✅

**Description:** Add one case to the `switch (err.code)` in `submit()` of `login-form.component.ts` (after the existing `RATE_001` case, before `default`), per design §7:

```typescript
case 'AUTH_LCK_001':
  this.errorMessage.set('Too many attempts. Try again later or reset your password.');
  break;
```

Message deliberately omits attempt count and `Retry-After` value (AC-2). Add a matching spec case in `login-form.component.spec.ts` mirroring the existing `RATE_001` test: drive an `AppError` with `code: 'AUTH_LCK_001'` through the mocked `AuthService` error path; assert the rendered banner text and that no navigation occurs. No `any`; component sees `AppError`, never `HttpErrorResponse`.

**Dependencies:** None (fully parallel)
**Files impacted:** `nexus-frontend/src/app/features/auth/login-form/login-form.component.ts`, `nexus-frontend/src/app/features/auth/login-form/login-form.component.spec.ts`
**Files created:** None
**Complexity:** S
**Risk:** Leaking `retryAfterSeconds` or attempt count into the message (violates AC-2); placing the case after `default` (unreachable code).
**Testing requirements:**
- Frontend (Vitest): error with `code: 'AUTH_LCK_001'` sets `errorMessage` to the lockout text, clears `loading`, does NOT navigate to `/dashboard`; message contains no number or "seconds".
- Backend: none.
**Definition of Done:**
- [x] New case added before `default`.
- [x] Message free of count/Retry-After detail.
- [x] Spec case green; `npm run lint` and `format:check` pass.

---

## Group 7: Cross-cutting — Security Mitigations

### T-015 — M-1: Timing test (locked ≈ wrong-password latency) ✅

**Description:** Add a test proving Argon2 (Step 2) runs before the Step 4 lock branch on the LOCKED path (T-LCK-5). Primary assertion: a spy confirms `PasswordVerifierPort.matches(...)` is invoked exactly once on BOTH the LOCKED (423) path and the wrong-password (401) path. Use a structural invariant rather than wall-clock timing to avoid flaky CI. An optional latency-parity assertion may supplement it with generous tolerance and a fixed iteration count.

**Dependencies:** T-007
**Files impacted:** `nexus-backend/src/test/java/com/example/nexus/identity/application/service/LoginUseCaseSecurityTest.java`
**Files created:** None
**Complexity:** M
**Risk:** Wall-clock timing assertions are flaky in CI; mitigate by making the structural `matches(...)` invocation the primary assertion.
**Testing requirements:**
- Unit: spy confirms `matches(...)` called once on the LOCKED path before `AccountLockedException` is thrown; same on wrong-password path before `AuthenticationException`.
- Integration/Frontend: none.
**Definition of Done:**
- [x] Test proves Argon2 runs on the LOCKED path before the 423 branch.
- [x] No flaky wall-clock-only assertion (structural invariant is primary).

---

### T-016 — M-3: Concurrency test + atomic-UPDATE decision (DF-3) ✅

**Description:** Add a concurrency `*IT` firing N parallel failed logins for one account on Testcontainers MySQL, asserting the account reaches `LOCKED` within a documented upper bound (T-LCK-7 / DF-3). Use a `CountDownLatch` / barrier to maximize collision pressure. After the test, **record the measured bound** and make an explicit decision: (a) accept the bound as documented (option a), or (b) switch to an atomic `UPDATE users SET failed_attempt_count = failed_attempt_count + 1 ...` (option b — requires escalation; do NOT implement silently). Record the chosen option in the PR and feed into T-024.

**Dependencies:** T-006, T-007
**Files impacted:** None unless option b is chosen (escalation required)
**Files created:** `nexus-backend/src/test/java/com/example/nexus/identity/application/service/LockoutConcurrencyIT.java`
**Complexity:** L
**Risk:** Non-deterministic thread interleaving — use a latch/barrier to maximize collision. Option b is a persistence-contract change that needs explicit sign-off.
**Testing requirements:**
- Integration (`LockoutConcurrencyIT`, Testcontainers MySQL): N concurrent wrong-password attempts → account ends LOCKED; effective attempts ≤ documented bound; no `OptimisticLockingFailureException` escapes as 500.
- Unit/Frontend: none.
**Definition of Done:**
- [x] Concurrency IT green and deterministic (barrier-synchronized).
- [x] Measured upper bound documented in the PR / T-024.
- [x] Explicit recorded decision: option a (accept) or option b (escalate for atomic UPDATE).

---

### T-017 — M-6: Log-injection assertion on lockout log lines ✅

**Description:** Verify no attacker-controlled string (email, raw request headers) reaches any new log line on the lockout paths (`ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`, `ACCOUNT_LOCKED_WRITE_FAILED`, Step 4 `LOGIN_FAILURE`). Add a test submitting an email with CRLF / control characters and asserting the captured log output contains no injected newline / forged log record and no clear-text email or IP. Use an in-memory log appender (the existing `logback-test.xml` pattern).

**Dependencies:** T-006, T-007
**Files impacted:** `nexus-backend/src/test/java/com/example/nexus/identity/application/service/LoginUseCaseSecurityTest.java` (or `SecureEventServiceTest`)
**Files created:** None
**Complexity:** M
**Risk:** A future change interpolating `email` into a log line reintroduces CRLF injection — this test is the permanent guard.
**Testing requirements:**
- Unit: capture log output for a lockout triggered by a CRLF-laden email; assert only `userId`/`tenantId` appear, no newline injection, no email/IP in clear.
- Integration/Frontend: none.
**Definition of Done:**
- [x] CRLF/log-injection assertion present for all new lockout log lines.
- [x] No attacker-controlled string in any asserted log line.

---

### T-018 — M-7: ACCOUNT_LOCKED rate-observable signal ✅

**Description:** Make mass-lockout campaigns detectable (T-LCK-3). No Micrometer/`MeterRegistry` exists in the codebase — introducing a `Counter` is a new pattern requiring an ADR. **Decision (audit-event-based):** rely on the existing `auth_events` mechanism — `ACCOUNT_LOCKED` events (emitted by T-006) are queryable via `idx_auth_events_event_type_created_at`. Tasks: (1) confirm `ACCOUNT_LOCKED` and `ACCOUNT_LOCKED_WRITE_FAILED` are durably recorded (verified by T-023); (2) document an alert threshold (e.g. ">N `ACCOUNT_LOCKED` events per tenant per minute") in the observability docs (T-024). If a Prometheus counter is desired, flag it as **ADR Required** — do not introduce silently.

**Dependencies:** T-006
**Files impacted:** None in main code (audit-event reuse); doc deliverable in T-024
**Files created:** None
**Complexity:** S
**Risk:** An audit-table-only approach needs a documented query/alert or it is not actionable for ops.
**Testing requirements:**
- Integration: covered by T-023 (`ACCOUNT_LOCKED` rows filterable by `event_type`).
- Unit/Frontend: none.
**Definition of Done:**
- [x] `ACCOUNT_LOCKED` + `ACCOUNT_LOCKED_WRITE_FAILED` confirmed durably recorded and filterable.
- [x] Alert threshold documented in T-024.
- [x] Any Prometheus-counter proposal flagged as ADR Required, not implemented silently.

---

### T-019 — M-4 / DF-1: Document IP-bucket single-instance precondition

**Description:** The IP bucket uses `request.getRemoteAddr()` only (filter line 84, T-1.3). Per Gate 2 DF-1 decision (no `ForwardedHeaderFilter` this sprint), the IP-layer credential-stuffing control is meaningful only when Nexus runs single-instance with direct client connections — no reverse proxy or load balancer. Document this precondition in the `LoginRateLimitFilter` Javadoc (in the same area touched by T-009) and in T-024. Note that DB lockout remains globally authoritative regardless of topology.

**Dependencies:** T-009 (filter already touched; add Javadoc note there)
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/LoginRateLimitFilter.java` (Javadoc only)
**Files created:** None
**Complexity:** S
**Risk:** Shipping the IP bucket as a "credential-stuffing control" without the precondition documented overstates the protection for proxied deployments.
**Testing requirements:** None (documentation). `getRemoteAddr()`-only behavior already asserted by existing filter tests.
**Definition of Done:**
- [ ] Filter Javadoc states the single-instance/no-proxy precondition and that XFF is intentionally not parsed.
- [ ] DB-lockout-is-globally-authoritative noted.
- [ ] Cross-referenced in T-024.

---

### T-019b — M-5: Denylist exact-match Javadoc (via T-008)

**Description:** Covered inside **T-008**. This entry maps threat-model mitigation M-5 to its implementing task. No separate work — verify the exact-match limitation Javadoc landed in `PasswordPolicyService` during T-008.

**Dependencies:** T-008
**Definition of Done:**
- [ ] Confirmed exact-match limitation Javadoc present in `PasswordPolicyService` (from T-008).

---

### T-019c — M-8: DF-2 inner-TX failure handling (via T-006)

**Description:** Covered inside **T-006** (`persistFailedAttempt` broad-catch policy + `ACCOUNT_LOCKED_WRITE_FAILED` event). This entry maps M-8 to its implementing task. No separate work — verify the DF-2 catch policy and the generic-exception unit test landed in T-006.

**Dependencies:** T-006
**Definition of Done:**
- [ ] Confirmed DF-2 catch policy + `ACCOUNT_LOCKED_WRITE_FAILED` emission implemented and unit-tested in T-006.

---

### T-019d — M-9 / DF-4: Lockout-does-not-revoke-refresh-families decision

**Description:** Covered in **T-003** (`lockAccount` Javadoc). Recorded decision: lockout is a brute-force defense, not a compromise-response control; refresh-token families are intentionally NOT revoked on lock. Extension point is `SecureEventService.revokeFamily` if future requirements change. No code change beyond the T-003 Javadoc.

**Dependencies:** T-003
**Definition of Done:**
- [ ] `lockAccount` Javadoc states the decision with rationale and extension point.
- [ ] Decision referenced in T-024.

---

## Group 8: Integration Tests

### T-020 — Full lockout lifecycle IT (5 failures → 423 → wait → success) ✅

**Description:** New `*IT` exercising the end-to-end lifecycle against Testcontainers MySQL and the real HTTP stack. Sequence: seed an ACTIVE user; POST `/api/v1/auth/login` with wrong password 4 times (each 401 `AUTH_001`); 5th wrong attempt persists the lock; next attempt returns 423 `AUTH_LCK_001` with `Retry-After` header. Then advance time past `lockedUntil` (via clock override or direct row update on the `lockedUntil` column) and assert a correct-password login returns 200, `failed_attempt_count = 0`, `locked_until IS NULL`, `status = ACTIVE`.

Coordinate with T-009 test config (ip=3/10s in test profile): the 5 failed logins must be reachable within the IP allowance. Options: (a) inject a test `USER-HMAC` bucket limit ≥ 5 in the test config, or (b) space the requests across the 10-second IP window. Prefer (a) to avoid sleep-based tests.

**Dependencies:** T-002, T-003, T-004, T-006, T-007, T-009, T-010 (all backend groups)
**Files impacted:** possibly `application-test.yml` if IP bucket blocks 5 attempts
**Files created:** `nexus-backend/src/test/java/com/example/nexus/identity/interfaces/rest/LockoutLifecycleIT.java`
**Complexity:** L
**Risk:** Test-profile IP rate limit (3/10s) trips before the 5th login attempt, preventing the lock; time-advancement flakiness if real sleeps are used.
**Testing requirements:**
- Integration: 4×401 → 5th (lock-persisting) → 423+Retry-After; post-window correct login → 200 + DB state reset.
**Definition of Done:**
- [x] 4×401 → lock commit → 423 with `Retry-After`.
- [x] Post-window correct login → 200 + `failed_attempt_count=0`, `locked_until IS NULL`.
- [x] No real `Thread.sleep` for the lock window (clock/row-aging used).
- [x] IP vs lockout threshold reconciled in test config.

---

### T-021 — M-2: Counter-persists-after-rollback IT ✅

**Description:** New `*IT` proving `failed_attempt_count` is durably committed by `persistFailedAttempt` (REQUIRES_NEW) even though the outer `LoginUseCase` `@Transactional` rolls back on `AuthenticationException` (T-LCK-6). Drive a single wrong-password login through the real use-case + persistence on Testcontainers MySQL; after the 401, read the user row in a fresh transaction and assert `failed_attempt_count == 1`. This test is the permanent guard against a future refactor that moves the counter write back into the outer transaction.

**Dependencies:** T-006, T-007
**Files impacted:** None
**Files created:** `nexus-backend/src/test/java/com/example/nexus/identity/application/service/FailedAttemptPersistenceIT.java` (or fold into `LockoutLifecycleIT`)
**Complexity:** M
**Risk:** Asserting in the same transaction that just rolled back (would not see the committed row); test passing for the wrong reason if the outer TX is not actually rolling back.
**Testing requirements:**
- Integration: one wrong-password attempt → 401 → fresh-TX read shows `failed_attempt_count == 1`.
**Definition of Done:**
- [x] Counter == 1 after a rolled-back failed login, read in a fresh TX.
- [x] Test comment ties it to T-LCK-6 / M-2.

---

### T-022 — HTTP contract IT (423 body + Retry-After header) ✅

**Description:** New `*IT` asserting the exact 423 wire contract (design §6): lock an account, then assert response is `423 Locked`, `Content-Type: application/problem+json`, body has `code=AUTH_LCK_001`, `status=423`, a `detail` string, numeric `retryAfterSeconds`, `traceId`, and a `Retry-After` header matching `retryAfterSeconds`. Confirm no internal details (stack trace, SQL, class names) leak. Also assert the 401/403/429 responses on the same endpoint are unaffected.

**Dependencies:** T-004, T-007, T-009, T-010
**Files impacted:** None
**Files created:** `nexus-backend/src/test/java/com/example/nexus/identity/interfaces/rest/AccountLockedContractIT.java`
**Complexity:** M
**Risk:** `Retry-After` header missing or mismatched with `retryAfterSeconds`; problem body `type`/`title` deviating from the existing RFC 7807 shape.
**Testing requirements:**
- Integration: full HTTP assertion of body + headers on a locked account; other status codes unaffected.
**Definition of Done:**
- [x] 423, `application/problem+json`, all body fields and `Retry-After` header asserted.
- [x] No internal information leaked.
- [x] 401/403/429 regression assertions green.

---

### T-023 — AuthAudit IT extensions (ACCOUNT_LOCKED / ACCOUNT_UNLOCKED / WRITE_FAILED) ✅

**Description:** Extend `AuthAuditIT.java` to assert new audit events land in `auth_events` with correct `event_type`, `outcome`, and only safe fields. Assert: `ACCOUNT_LOCKED` (`FAILURE`) written when the 5th failure crosses the threshold (with `userId`, no email); the Step 4 lock-active rejection writes `LOGIN_FAILURE`; `ACCOUNT_UNLOCKED` (`SUCCESS`) written on a successful post-window login; query-by-`event_type` via `idx_auth_events_event_type_created_at` returns the correct rows (supports M-7 detectability). The `ACCOUNT_LOCKED_WRITE_FAILED` event can be asserted at the unit level in T-006 (inner-TX fault injection is complex at IT level) — note if included or deferred.

**Dependencies:** T-006, T-007
**Files impacted:** `nexus-backend/src/test/java/com/example/nexus/identity/interfaces/rest/AuthAuditIT.java`
**Files created:** None
**Complexity:** M
**Risk:** Asserting metadata that contains PII; append-only trigger on `auth_events` rejecting any test that tries to update rows.
**Testing requirements:**
- Integration: new event types with correct outcomes and safe fields; `event_type` query path exercised.
**Definition of Done:**
- [x] `ACCOUNT_LOCKED`, `LOGIN_FAILURE` (lock-active), and `ACCOUNT_UNLOCKED` asserted with correct outcome and no email/clear-IP.
- [x] `event_type` query via index exercised (M-7 support).

---

## Group 9: Documentation

### T-024 — Document lockout policy, DF-1 precondition, and recorded decisions ✅

**Description:** Update `SECURITY.md` (and/or `docs/observability-standards.md`) with: (1) lockout policy — 5 consecutive failures / 15-min window → 15-min lock, 423 `AUTH_LCK_001`, auto-expiry on next successful login; (2) IP rate-limit reshape — 10/min/IP, separate user-HMAC bucket 5/900s; (3) **DF-1 single-instance/no-proxy precondition** (T-019); (4) **M-7 alert threshold** on `ACCOUNT_LOCKED` events and the support runbook entry for US-007 self-service reset (lockout-as-DoS compensating control); (5) **M-9 decision** — lockout does not revoke refresh families (T-019d); (6) **DF-3 concurrency bound** and the option-a/b decision from T-016; (7) new error codes `AUTH_LCK_001` and `AUTH_PWD_002` in the error-code catalog. Flag any atomic-UPDATE (T-016 option b) or Prometheus-counter (T-018) choice as **ADR Required** if adopted.

**Dependencies:** T-016 (bound decision), T-018 (alert), T-019, T-019d (decisions finalized)
**Files impacted:** `SECURITY.md`, possibly `docs/observability-standards.md`, error-code catalog
**Files created:** None (unless an ADR is triggered by T-016 or T-018)
**Complexity:** M
**Risk:** Documentation drifting from the shipped behavior; omitting the DF-1 precondition (the highest-residual threat, T-LCK-9 High in proxied deployments).
**Testing requirements:** None (documentation).
**Definition of Done:**
- [x] Lockout policy, IP/user rate-limit values documented.
- [x] DF-1 single-instance precondition recorded.
- [x] M-7 alert threshold + US-007 reset runbook entry recorded.
- [x] M-9 and DF-3 decisions recorded.
- [x] New error codes catalogued.
- [x] Any atomic-UPDATE / Prometheus-counter choice flagged as ADR Required.

---

## Dependency Graph (quick reference)

```
T-001  (verify schema)  ─── standalone, do first

T-002, T-003, T-004  ─── domain, no deps, fully parallel

T-006  ─── needs T-002, T-003
T-007  ─── needs T-002, T-003, T-004, T-006
T-008  ─── no deps (parallel P1 task)

T-009  ─── no deps; ATOMIC single commit

T-010  ─── needs T-004 (parallel to Group 3)
T-011  ─── no deps (fully parallel)

T-015  ─── needs T-007
T-016  ─── needs T-006, T-007
T-017  ─── needs T-006, T-007
T-018  ─── needs T-006
T-019  ─── with/after T-009 (Javadoc addition)
T-019b ─── verifies M-5 in T-008
T-019c ─── verifies M-8 in T-006
T-019d ─── needs T-003

T-020, T-021, T-022, T-023  ─── need all backend groups (2–5) complete
T-024  ─── finalize after T-016, T-018, T-019, T-019d
```

**Fast path for a single engineer (sequential):**
T-001 → T-002 → T-003 → T-004 → T-009 → T-006 → T-010 → T-007 → T-008 → T-011 → T-015 → T-016 → T-017 → T-018 → T-019 → T-020 → T-021 → T-022 → T-023 → T-024
