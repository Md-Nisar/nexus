# Test Audit — US-007: Self-Service Password Reset via Email

Date: 2026-07-01
Auditor: QA Engineer (qa-engineer agent) + Security Review fixes session
Branch: feature/US-007

---

## Source → Test Map

### Backend

| Source file | Test file | Tests |
|-------------|-----------|-------|
| `ForgotPasswordUseCase.java` | `ForgotPasswordUseCaseTest` | 6 |
| `ResetPasswordUseCase.java` | `ResetPasswordUseCaseTest` | 13 |
| `PasswordResetController.java` | `PasswordResetControllerTest` | 7 |
| `PasswordResetEmailEvent.java` | `DomainEventToStringTest` | 1 (in 3-test class) |
| `LoginRateLimitFilter.java` | `LoginRateLimitFilterTest` | 15 |
| `MailEventListener.java` | `MailEventListenerTest` | 1 (in 3-test class) |
| `LoggingMailSenderAdapter.java` | `LoggingMailSenderAdapterTest` | 2 (in 4-test class) |
| `SmtpMailSenderAdapter.java` | `SmtpMailSenderAdapterTest` | 1 (in 3-test class) |
| `SecureEventService.revokeAllUserSessions` | `SecureEventServiceTest` | 1 (in 11-test class) |
| `AuthToken.forReset()` | `AuthTokenTest` | 1 (in 5-test class) |
| `User.applyPasswordReset()` | `UserTest` | 4 (in 27-test class) |

### Frontend

| Source file | Test file | Tests |
|-------------|-----------|-------|
| `ForgotPasswordComponent` | `forgot-password.component.spec.ts` | 9 |
| `ResetPasswordComponent` | `reset-password.component.spec.ts` | 13 |
| `AuthService.forgotPassword/resetPassword` | `auth.service.spec.ts` | 6 |
| `LoginFormComponent` (banner + link) | `login-form.component.spec.ts` | 2 (in 11-test class) |

---

## Gaps Identified and Status

### Gaps closed in this audit

| # | Gap | Resolution |
|---|-----|------------|
| G1 | `PasswordResetEmailEvent.toString()` had no SEC-3 assertion verifying raw token is `<redacted>` and email is masked | Added `passwordResetEmailEvent_toString_masksEmailAndRedactsToken` to `DomainEventToStringTest` |
| G2 | `ForgotPasswordUseCaseTest` did not assert `PASSWORD_RESET_THROTTLED` audit event type, outcome, userId, or ipAddress | Added `execute_fourthReset_suppressesEmailAndRecordsThrottledEvent` and `execute_throttledRequest_auditEventContainsUserIdAndIpAddress` |
| G3 | `ForgotPasswordUseCaseTest` did not assert `PASSWORD_RESET_REQUESTED` audit event separately from the email event | Added `execute_happyPath_recordsPasswordResetRequestedAuditEvent` |
| G4 | `MailEventListenerTest` had no test for `onPasswordReset` handler | Added `onPasswordReset_delegatesRawTokenAndAddress_toPort` |
| G5 | `LoggingMailSenderAdapterTest` had no test for `sendPasswordResetEmail` — specifically no SEC-3 assertion that raw token is not logged | Added `sendPasswordResetEmail_completesWithoutThrowing` and `sendPasswordResetEmail_doesNotLogRawToken` |
| G6 | `SmtpMailSenderAdapterTest` had no test for `sendPasswordResetEmail` verifying To/From/Subject and reset URL shape | Added `sendPasswordResetEmail_setsToFromSubjectAndResetUrlInBody` |
| G7 | `SecureEventServiceTest` had no test for `revokeAllUserSessions` | Added `should_delegateToRevokeByUserId_when_revokeAllUserSessionsCalled` |
| G8 | `AuthTokenTest` had no test for `AuthToken.forReset()` factory method | Added `should_setResetType_when_forResetFactoryCalled` |
| G9 | `UserTest` had no tests for `applyPasswordReset()` domain method | Added 4 tests covering: hash+tokenVersion increment, LOCKED→ACTIVE transition, PENDING→ACTIVE transition, multiple resets increment version |
| G10 | `ResetPasswordUseCaseTest` had no test verifying session-revocation failure is swallowed (MEDIUM-1 fix) | Added `execute_sessionRevocationFailure_isSwallowedAndPasswordStillSaved` |
| G11 | `ResetPasswordComponent` spec had no test for `AUTH_PWD_002` (too-common password) error branch | Added `should set AUTH_PWD_002 error when password is too common` |
| G12 | `ResetPasswordComponent` spec had no test for the URL token-stripping LOW-1 fix | Added `should strip token from URL on init to prevent Referer leakage` |
| G13 | `ResetPasswordComponent` spec had no test for `maxlength` validation (MEDIUM-2 fix) | Added `should not call resetPassword when password exceeds 256 characters` |
| G14 | `ForgotPasswordComponent` spec had no test for the loading guard (double-submit prevention) | Added `should not call forgotPassword a second time while already loading` |
| G15 | `LoginRateLimitFilter` tests missing for `/password/forgot` (IP reject, email reject, pass-through) and `/password/reset` (IP reject, pass-through) — HIGH-3/HIGH-4 security fixes | Added 7 tests: `shouldNotFilter_returnsFalse_forPostOnForgotPath`, `shouldNotFilter_returnsFalse_forPostOnResetPath`, `doFilterInternal_forgotPath_ipRateLimited_writes429`, `doFilterInternal_forgotPath_emailRateLimited_writes429`, `doFilterInternal_forgotPath_notRateLimited_passesThroughWithBody`, `doFilterInternal_resetPath_ipRateLimited_writes429`, `doFilterInternal_resetPath_notRateLimited_passesThrough` |

### Gaps accepted (not added in this audit)

| # | Gap | Reason |
|---|-----|--------|
| A1 | Integration test asserting `PASSWORD_RESET_FAILED` event persists after outer TX rollback (REQUIRES_NEW durability) | Requires Testcontainers; Docker not available in this environment. Mitigated by inline comment in `recordFailure()` and unit test for the revocation-failure path. |
| A2 | Integration test for `MailEventListener.onPasswordReset` firing after transaction commit | Requires Testcontainers + running application context. Mitigated by unit test + `@Async @TransactionalEventListener(AFTER_COMMIT)` contract verification at the annotation level. |
| A3 | Load tests for `/password/forgot` and `/password/reset` at >10 RPS | The `LoginRateLimitFilter` (now covering both paths) rate-limits the endpoints. Load testing would require a running infrastructure stack. |
| A4 | End-to-end Playwright test for the full reset flow (email link → reset page → login) | Playwright e2e test would require running backend + mail server. Deferred to manual QA or integration environment. |

---

## Test Counts

### Backend

| Test class | Tests |
|------------|-------|
| `ForgotPasswordUseCaseTest` | 6 |
| `ResetPasswordUseCaseTest` | 13 |
| `PasswordResetControllerTest` | 7 |
| `LoginRateLimitFilterTest` | 15 |
| `DomainEventToStringTest` | 3 |
| `MailEventListenerTest` | 3 |
| `LoggingMailSenderAdapterTest` | 4 |
| `SmtpMailSenderAdapterTest` | 3 |
| `SecureEventServiceTest` | 11 |
| `AuthTokenTest` | 5 |
| `UserTest` | 27 |
| All other existing tests | ~265 |
| **Total** | **369** |

### Frontend

| Test file | Tests |
|-----------|-------|
| `forgot-password.component.spec.ts` | 9 |
| `reset-password.component.spec.ts` | 13 |
| `auth.service.spec.ts` | ~15 (includes 6 for reset endpoints) |
| `login-form.component.spec.ts` | 11 |
| All other existing tests | ~115 |
| **Total** | **≥ 163** |

---

## Pass Rates

| Suite | Status | Notes |
|-------|--------|-------|
| Backend `./mvnw test` | **PASS** (exit 0) | 369 tests, 0 failures, 0 skipped |
| Backend `./mvnw verify -DskipITs` | **PASS** (exit 0) | + checkstyle, SpotBugs, ArchUnit, JaCoCo |
| Frontend `npm run test:ci` | **PASS** (exit 0) | Coverage: Statements 87.46%, Branches 82.09%, Functions 82.82%, Lines 90.16% |

---

## Flaky Tests

Three test files in the frontend suite exhibit intermittent 5000ms timeout failures when all 24 spec files run concurrently under `npm run test:ci`. The failures are timing-based (resource contention between Angular zones across many test files), not assertion failures. The affected tests are in files **not modified by US-007**:

| File | Test | Observation |
|------|------|-------------|
| `shared/ui/nx-select.spec.ts` | `renders the select trigger` | Timeout when run concurrently |
| `registration-form.component.spec.ts` | `should disable submit when consentAccepted is false` | Timeout when run concurrently |

Both files use `provideAnimationsAsync()` which can cause async zone teardown races under heavy parallel execution. These failures are pre-existing (not introduced by US-007) and pass when run in isolation. Recommend increasing `testTimeout` in `vitest.config.ts` from 5000ms to 10000ms as a follow-up task.

---

## Verdict

**PASS** — all 15 gaps identified were closed. Both backend and frontend suites are green. Accepted gaps are documented with rationale. The feature is ready for `/docs` and `/release-prep`.
