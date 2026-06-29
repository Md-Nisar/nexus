# US-006 Code Review

**Reviewer:** code-reviewer agent  
**Date:** 2026-06-29  
**Branch:** feature/US-006  
**Verdict:** APPROVE WITH NITS

---

## Summary

| Severity | Count |
|----------|-------|
| BLOCKER  | 0 |
| HIGH     | 1 |
| MEDIUM   | 3 |
| LOW/NIT  | 5 |

---

## Findings

### [HIGH] @Modifying missing clearAutomatically = true on resetFailedAttemptsDirect

**File:** nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaUserRepository.java:33
**Finding:** The new @Modifying annotation on resetFailedAttemptsDirect does not set clearAutomatically = true. Both existing bulk-update queries in JpaRefreshTokenRepository (lines 21 and 26) set clearAutomatically = true to evict stale entities from the JPA first-level cache after a JPQL bulk UPDATE. The new method deviates from this established project convention without documented justification.
**Impact:** Benign in the current flow — persistResetAttempts ends its REQUIRES_NEW transaction immediately after the UPDATE with no subsequent reads. However any future caller that performs a findById after resetFailedAttemptsDirect within the same transaction will read stale failedAttemptCount from the L1 cache even though the DB row holds 0. This is a latent consistency bug and a silent deviation from the codebase pattern.
**Suggestion:** Add @Modifying(clearAutomatically = true) to match every other bulk UPDATE in the codebase and protect future callers.

---

### [MEDIUM] Potential NPE on getLockedUntil() in Step 4 for LOCKED rows with NULL locked_until

**File:** nexus-backend/src/main/java/com/example/nexus/identity/application/service/LoginUseCase.java:153-154
**Finding:** When user.getStatus() == LOCKED and unlockIfExpired returned false, the code unconditionally calls user.getLockedUntil().getEpochSecond(). lockAccount() always sets lockedUntil, but if a LOCKED row exists in the DB with locked_until = NULL (possible via direct DB manipulation, a migration error, or a future code path that sets status LOCKED without calling lockAccount), this line throws a NullPointerException that escapes as HTTP 500 on the unauthenticated login endpoint.
**Impact:** HTTP 500 on the login path produces an INTERNAL_ERROR response to unauthenticated callers, which is a security information-disclosure concern and will trigger monitoring alerts.
**Suggestion:** Guard the dereference:

    Instant lu = user.getLockedUntil();
    long retryAfter = lu != null
        ? Math.max(0, lu.getEpochSecond() - clock.instant().getEpochSecond())
        : 0L;
    throw new AccountLockedException(AUTH_LCK_001,
        "Account locked. Try again later or reset your password.", retryAfter);

Also add Objects.requireNonNull(lockedUntil) inside User.lockAccount() to make the invariant explicit at write time.

---

### [MEDIUM] LOCKOUT_WINDOW_SECONDS is defined but not enforced — rolling window is absent

**File:** nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthConstants.java:22
**Finding:** LOCKOUT_WINDOW_SECONDS = 900 is declared and has a corresponding test assertion, but no production code uses it. The design (section 3b) states that consecutive failures within a 15-minute window are counted, yet persistFailedAttempt accumulates ALL failures since the last reset with no time-based cutoff. A user who makes 4 failed attempts in month 1 and 1 more in month 2 will be locked out.
**Impact:** Deviation from the stated design. Legitimate users who mistype their password occasionally over a long span may be unexpectedly locked. The constant name and Javadoc imply a rolling-window behavior that does not exist, misleading future maintainers.
**Suggestion:** Either (a) implement the rolling window by adding a last_failed_at column and resetting the counter in persistFailedAttempt when the inter-failure gap exceeds LOCKOUT_WINDOW_SECONDS — which requires a Flyway migration; or (b) explicitly remove LOCKOUT_WINDOW_SECONDS and update the design to document that failures accumulate until a successful login resets them. Option (b) is lower-risk for this release.

---

### [MEDIUM] application-test.yml missing refresh-max-attempts — test profile is not self-contained

**File:** nexus-backend/src/main/resources/application-test.yml
**Finding:** The design (section 5a) explicitly mandates updating application-test.yml in the same change for all new rate-limit config keys. The four login-path keys are present in application-test.yml, but refresh-max-attempts is absent. Tests that activate the test profile without a @SpringBootTest(properties) override silently inherit refresh-max-attempts: 30 from application.yml through Spring Boot profile merging.
**Impact:** Hidden coupling to the base config. If the base key is renamed or removed in a future commit, the test suite fails at startup with no clear pointer to the missing value in application-test.yml. Violates the design mandate labeled as Impact Risk #2.
**Suggestion:** Add refresh-max-attempts: 1000 (or another suitably large value) to application-test.yml to make the test profile self-contained.

---

### [LOW] InMemoryRateLimitStore eviction truncates the USER-HMAC bucket to ip-window-seconds

**File:** nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/InMemoryRateLimitStore.java:104
**Finding:** The background eviction thread runs at ip-window-seconds (60 s) and prunes all entries older than 60 s regardless of bucket type. USER-HMAC entries configured for user-window-seconds = 900 are also evicted after 60 s. An attacker who spaces login attempts more than 60 s apart has their USER-HMAC counter reset by the eviction thread, bypassing the 900-second per-user rate limit.
**Impact:** Defense-in-depth degradation: the USER-HMAC sliding window is effectively 60 s rather than 900 s. The DB account lockout remains the primary authoritative brute-force control, but the configured per-user rate layer does not function as designed.
**Suggestion:** Use Math.max(ipWindowSeconds, userWindowSeconds) as the eviction thread interval, or apply per-key-prefix logic during eviction using the appropriate window for each bucket type. Minimally the discrepancy should be noted in the Javadoc.

---

### [LOW] SecureEventServiceConcurrencyTest contains only single-threaded tests — M-3 not concurrency-verified

**File:** nexus-backend/src/test/java/com/example/nexus/identity/application/service/SecureEventServiceConcurrencyTest.java
**Finding:** The class name and Javadoc claim to address M-3 (concurrent failed-attempt bound with documented upper limit), but every test in it is single-threaded with mocks. The class Javadoc acknowledges a real concurrency integration test is tracked separately, but that test is not present anywhere in the repository.
**Impact:** M-3 mitigation is documented as accepted but the promised automation does not exist. The optimistic-lock extra-attempt window remains an untested assumption.
**Suggestion:** Rename the class to SecureEventServiceLockoutBoundaryTest to remove the misleading concurrency implication, and create a tracked follow-up ticket for the parallel-thread Testcontainers integration test with a concrete acceptance criterion.

---

### [LOW] Return value of resetFailedAttemptsDirect silently discarded

**File:** nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaUserRegistrationAdapter.java:34-36
**Finding:** JpaUserRepository.resetFailedAttemptsDirect returns int (affected row count), but the adapter and port interface declare void, silently dropping the value. A return of 0 (user not found in DB) is indistinguishable from a successful update.
**Impact:** No correctness impact in current flows. Missed observability: a DEBUG-level log when 0 rows are affected would help diagnose unexpected no-ops.
**Suggestion:** In the adapter, log log.debug for 0-row results to aid future troubleshooting.

---

### [NIT] M-6 log-injection test verifies type contract only — does not inspect actual log output

**File:** nexus-backend/src/test/java/com/example/nexus/identity/application/service/SecureEventServiceTest.java:186-199
**Finding:** The M-6 test asserts that persistFailedAttempt does not throw, relying on static reasoning that UUID.toString() is CRLF-safe. It does not capture or inspect actual log output. A future code change that interpolates an attacker-controlled string into a log call in SecureEventService would not be caught.
**Impact:** M-6 would not catch a regression if a future developer adds a log line containing user-supplied data.
**Suggestion:** Use a ListAppender<ILoggingEvent> (as in AuthAuditIT.no_raw_refresh_token_in_logs) to capture log output and assert no emitted message contains carriage-return or newline characters.

---

## Positive Observations

1. **Transaction safety is correct and well-documented.** The REQUIRES_NEW boundary is placed correctly on persistFailedAttempt and persistResetAttempts. The rationale for re-reading by userId (not passing a detached entity) is precisely explained in both the design and Javadoc. The bulk-JPQL-UPDATE fix for the optimistic-lock collision on the success path (M-OL-1) is the correct solution, documented at design, Javadoc, and test levels.

2. **Argon2-always invariant is enforced and test-verified.** passwordVerifier.matches() is called unconditionally at Step 2 before any lock branch. Tests execute_lockedAccount_argon2StillRunsBeforeLockCheck and execute_wrongPassword_argon2Runs verify identical Argon2 invocation counts on both paths, explicitly closing T-LCK-5 (M-1).

3. **Counter increment scope is correct.** persistFailedAttempt is gated on if (found) in Step 5, and the test execute_wrongPassword_unknownUser_doesNotCallPersistFailedAttempt verifies that unknown emails never produce a counter write.

4. **Full RFC 7807 HTTP 423 contract verified end-to-end.** LoginLockoutIT T-022 asserts Content-Type: application/problem+json, the Retry-After header, the retryAfterSeconds body field, and absence of stack traces. GlobalExceptionHandlerTest unit-verifies the 423 handler shape.

5. **Config key atomicity is complete.** All old max-attempts/window-seconds keys are fully replaced in application.yml, both @Value annotations (LoginRateLimitFilter, InMemoryRateLimitStore), and every test property override. No legacy keys survive anywhere in the source.

6. **ArchUnit compliance maintained.** AccountLockedException in common.domain imports nothing from identity.*. SecureEventService in application.service imports only port interfaces, not infrastructure classes.

7. **DF-2 non-optimistic exception catch policy is implemented.** The broader catch (Exception e) in persistFailedAttempt logs at WARN with userId only, records ACCOUNT_LOCKED_WRITE_FAILED, and does not rethrow — guaranteeing AUTH_001 rather than 500 under any inner-TX failure.

8. **Frontend lockout handling is correct and secure.** The AUTH_LCK_001 case shows a generic message with no attempt count or Retry-After value exposed (AC-2 compliance). The spec test asserts the exact banner text and confirms no navigation occurs.

9. **PasswordPolicyService split is clean and documented.** AUTH_PWD_001 and AUTH_PWD_002 are correctly separated, and the exact-match denylist limitation is documented in Javadoc per M-5/DF-6.

10. **Comprehensive integration test coverage.** LoginLockoutIT covers the full lockout lifecycle, the REQUIRES_NEW boundary proof (M-2), and the HTTP contract (T-020, T-021, T-022). AuthAuditIT covers ACCOUNT_LOCKED and ACCOUNT_UNLOCKED audit events end-to-end against a Testcontainers MySQL instance (T-023).
