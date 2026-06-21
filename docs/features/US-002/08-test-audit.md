# Test Audit — US-002: Self-Service Registration with Email Verification

**Date:** 2026-06-20
**Author:** QA Engineer (Claude Sonnet 4.6)
**Branch:** US-002
**Base:** main

---

## Summary table

| Source class | Test class | Gaps found | Gaps closed |
|---|---|---|---|
| `RegisterUserUseCase` | `RegisterUserUseCaseTest` | None — happy path, dup email, anti-enumeration hash, password policy all covered | — |
| `VerifyEmailUseCase` | `VerifyEmailUseCaseTest` | Missing: `user.verify()` throws `IllegalStateException` (ACTIVE user path) | Added `verify_userAlreadyActive_throwsTokenExpiredWithCode_AUTH_VRF_002` |
| `ResendVerificationUseCase` | `ResendVerificationUseCaseTest` | None — all throttle paths, non-PENDING, unknown email covered | — |
| `PasswordPolicyService` | `PasswordPolicyServiceTest` | None — null, 11-char, 12-char, denylist, unicode boundary all covered | — |
| `TokenGenerator` | `TokenGeneratorTest` | None — format and distinctness (1000 calls) covered | — |
| `TokenHasher` | `TokenHasherTest` | Missing: non-hex input raises `IllegalArgumentException` | Added `hash_throwsIllegalArgumentException_when_inputIsNotHex` |
| `User` (domain) | `UserTest` | Missing: `verify()` on ACTIVE user message; no setter for `passwordHash` | Added `should_throwIllegalStateException_when_verifyCalledOnLockedUser`, `should_haveNoPublicSetterForPasswordHash_when_inspectedViaReflection` |
| `GlobalExceptionHandler` | `GlobalExceptionHandlerTest` | Missing: `NoResourceFoundException` handler; 3600s `Retry-After` variant | Added `should_return404WithResourceNotFoundCode_when_noResourceFound`, `should_return429WithRetryAfterOf3600_when_dailyRateLimitExceeded` |
| `RegistrationController` | `RegistrationControllerIT` | Missing: email >254 chars (400), email exactly 254 (201), password 1024 (201), password 1025 (400), blank resend email (400) | Added 5 HTTP boundary tests |
| `PasswordStrengthMeterComponent` | `password-strength-meter.component.spec.ts` | Missing: score=2 (Fair), score=3 (Strong), aria-label prefix format | Added 3 tests |
| `RegistrationFormComponent` | `registration-form.component.spec.ts` | Missing: disabled on empty form; error banner for non-field error; no banner for field error | Added 3 tests |
| `VerificationLandingComponent` | `verification-landing.component.spec.ts` | Missing: INVALID_LINK no resend; verifyEmail called with exact token | Added 2 tests |

---

## Pass rates

### Backend unit tests (no Spring context, no Docker)

**Before:** 161/161
**After:** 167/167

```
Tests run: 167, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

### Backend integration tests (`*IT`, Testcontainers MySQL)

Not run in this audit (requires Docker). Integration tests are in:
- `RegistrationIT` — full register→verify→ACTIVE flow
- `VerificationTokenIT` — expired/consumed/concurrent consumption
- `ResendVerificationIT` — 60s cooldown, 24h daily limit
- `IdentitySchemaMigrationIT` — V3 `password_hash` column and throttle index
- `RegistrationControllerIT` — HTTP contract, SEC-5 timing, feature flag

The `RegistrationControllerIT` now includes 5 additional boundary tests (email length, password length, blank resend email).

### Frontend tests (Vitest)

**Before:** 74/74
**After:** 82/82 (17 test files)

Coverage improvement:
- `registration-form.component.ts` branch coverage: 64.58% → 79.16%
- `password-strength-meter.component.ts` branch coverage: 96.42% → 96.42% (score=2 and =3 paths added)
- `verification-landing.component.ts` branch coverage: 93.75% → maintained

---

## Tests added

### Backend

| File | Method |
|---|---|
| `VerifyEmailUseCaseTest.java` | `verify_userAlreadyActive_throwsTokenExpiredWithCode_AUTH_VRF_002` |
| `TokenHasherTest.java` | `hash_throwsIllegalArgumentException_when_inputIsNotHex` |
| `UserTest.java` | `should_throwIllegalStateException_when_verifyCalledOnLockedUser` |
| `UserTest.java` | `should_haveNoPublicSetterForPasswordHash_when_inspectedViaReflection` |
| `GlobalExceptionHandlerTest.java` | `should_return404WithResourceNotFoundCode_when_noResourceFound` |
| `GlobalExceptionHandlerTest.java` | `should_return429WithRetryAfterOf3600_when_dailyRateLimitExceeded` |
| `RegistrationControllerIT.java` | `register_email255Chars_returns400` |
| `RegistrationControllerIT.java` | `register_email254Chars_returns201` |
| `RegistrationControllerIT.java` | `register_password1024Chars_returns201` |
| `RegistrationControllerIT.java` | `register_password1025Chars_returns400` |
| `RegistrationControllerIT.java` | `resend_blankEmail_returns400` |

### Frontend

| File | Test |
|---|---|
| `password-strength-meter.component.spec.ts` | `should report Fair for password12Chars (score 2)` |
| `password-strength-meter.component.spec.ts` | `should report Strong for password with length + uppercase + digit (score 3)` |
| `password-strength-meter.component.spec.ts` | `should include password strength label in aria-label for screen reader accessibility` |
| `registration-form.component.spec.ts` | `should disable submit button when form is empty (initial state)` |
| `registration-form.component.spec.ts` | `should show error banner for non-field server error` |
| `registration-form.component.spec.ts` | `should NOT show error banner when server returns field-level details` |
| `verification-landing.component.spec.ts` | `should NOT show resend link when token is absent (INVALID_LINK code)` |
| `verification-landing.component.spec.ts` | `should call verifyEmail with the exact token string from query params` |

---

## Load scenarios

The design document (§13) describes a canary rollout starting at 1% of traffic on Day 1. No absolute RPS threshold exceeding 10 RPS is specified for these endpoints at this stage. Load tests are deferred. If registration volume projections are provided in US-003 planning, add a k6 scenario to `nexus-backend/src/test/load/`.

---

## Flaky tests

### `VerificationTokenIT.verify_concurrentConsumption_exactlyOneSucceeds`

**Risk: LOW.** The test uses two threads with a `CountDownLatch` to race on a single token. Outcome depends on JPA optimistic locking (`@Version`) enforced at the DB level. In practice this is deterministic under MySQL's MVCC, but on a heavily loaded CI agent the 10-second timeout could be tight. The test is structurally correct and does not use `Thread.sleep()` for timing — it waits for a latch. Document as acceptable.

### `RegistrationControllerIT.register_sec5_newAndDuplicatePathsHaveEquivalentTiming`

**Risk: MEDIUM.** The timing assertion (`|mean_new - mean_dup| < 50 ms`) is inherently load-sensitive. Under CI resource contention, GC pauses, or CPU throttling, the means can diverge. The 50 ms threshold is intentionally wide (Argon2 typically ~150 ms per call under low-memory params), but there is no hard guarantee. If this test becomes unstable in CI, increase the threshold to 100 ms or extract it into a separate `@Tag("timing")` profile excluded from the default CI run.

---

## Security validation

- `rawToken` does not appear in any test log assertion. The `RegistrationControllerIT.verifyEmail_noRawTokenInLogs_secTi4` test asserts this dynamically against the live log stream.
- Anti-enumeration: `register_duplicateEmail_returns201IdenticalShape` in `RegistrationControllerIT` confirms HTTP 201 is returned for duplicate email, never 409.
- Password hash: No test asserts the hash value directly — tests assert behaviour (user activates, token consumed) not the stored `passwordHash` content.
