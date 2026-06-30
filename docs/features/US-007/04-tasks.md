# US-007 — Task Breakdown

_Output of `/breakdown` (architect + engineers + qa-engineer). Feeds Gate 3._

All tasks are test-first. Backend tasks use Spring Boot 4 / Java 25 / JUnit 5 + Testcontainers conventions. Frontend tasks use Angular 21 standalone + Vitest conventions. Dependencies are listed explicitly; tasks within a dependency group can be parallelised.

---

## Task Map

```
T1 (migration + repo query)
  └─► T2 (domain changes)
        └─► T3 (mail infrastructure)   ──┐
        └─► T4 (SecureEventService)     ──┤
              └─► T5 (ForgotPasswordUseCase) ──┐
              └─► T6 (ResetPasswordUseCase)  ──┤
                    └─► T7 (Controller + SecurityConfig + full IT)
                              └─► T8 (FE: AuthService + routes)
                                    └─► T9  (FE: ForgotPasswordComponent)
                                    └─► T10 (FE: ResetPasswordComponent)
                                    └─► T11 (FE: LoginFormComponent changes)
```

---

## T1 — Flyway V4 migration and JPA query method

**Layer:** `identity.infrastructure` / DB  
**Depends on:** none (foundational)  
**Parallelisable with:** nothing (must go first)

### What to build
1. `V4__auth_tokens_reset_throttle_index.sql` in `src/main/resources/db/migration/`:
   ```sql
   CREATE INDEX idx_auth_tokens_user_id_type_created_at
       ON auth_tokens (user_id, type, created_at);
   ```
2. Add JPQL query to `JpaAuthTokenRepository`:
   ```java
   @Query("""
       SELECT COUNT(t) FROM AuthToken t
       WHERE t.userId = :userId AND t.type = :type AND t.createdAt > :since
       """)
   int countByUserIdAndTypeAndCreatedAtAfter(
       @Param("userId") UUID userId,
       @Param("type") AuthTokenType type,
       @Param("since") Instant since);
   ```
3. Verify `JpaAuthTokenAdapter` delegates to the new repo method (implementing `AuthTokenPort.countByUserIdAndTypeAndCreatedAtAfter` which already exists on the port).

### Tests
- `MigrationIT` (or existing migration smoke test): verify `idx_auth_tokens_user_id_type_created_at` exists after migration
- `JpaAuthTokenAdapterIT`: `countByUserIdAndTypeAndCreatedAtAfter` returns correct count for RESET tokens in window, zero for VERIFICATION tokens, zero for tokens outside window

### Acceptance criteria verified
- V4 migration runs cleanly on a blank DB
- Checksum stable in CI
- No existing tests broken

---

## T2 — Domain changes: `AuthToken.forReset` and `User.applyPasswordReset`

**Layer:** `identity.domain`  
**Depends on:** T1 (migration must be mergeable)  
**Parallelisable with:** T3, T4 (after T2 is merged)

### What to build

**`AuthToken`** — add factory method:
```java
public static AuthToken forReset(
    UUID id, UUID userId, String tokenHash, Instant expiresAt) {
  return new AuthToken(id, userId, AuthTokenType.RESET, tokenHash, expiresAt);
}
```

**`User`** — add domain method:
```java
/**
 * Applies a completed password reset: updates hash, increments tokenVersion,
 * transitions any status to ACTIVE (AC-4), resets lockout state.
 * Session revocation is the caller's responsibility (use SecureEventService).
 */
public void applyPasswordReset(String newPasswordHash) {
  this.passwordHash = newPasswordHash;
  this.tokenVersion += 1;
  this.status = UserStatus.ACTIVE;
  this.failedAttemptCount = 0;
  this.lockedUntil = null;
}
```

### Tests
- `AuthTokenTest`: `forReset()` creates token with type=RESET, correct fields, null consumedAt
- `UserTest`:
  - `applyPasswordReset` on ACTIVE user → hash updated, tokenVersion incremented, status ACTIVE
  - `applyPasswordReset` on LOCKED user → status becomes ACTIVE, failedAttemptCount=0, lockedUntil=null
  - `applyPasswordReset` on PENDING user → status becomes ACTIVE (edge case)
  - tokenVersion increments from any starting value

### Acceptance criteria verified
- AC-4: LOCKED → ACTIVE on reset
- Token factory available for use-case

---

## T3 — Mail infrastructure extension

**Layer:** `identity.infrastructure.mail` / `identity.application.port.out` / `identity.application.event`  
**Depends on:** T2  
**Parallelisable with:** T4

### What to build
1. `PasswordResetEmailEvent` record (mirrors `VerificationEmailEvent`):
   ```java
   public record PasswordResetEmailEvent(String toEmail, String rawToken, UUID userId) {
     @Override public String toString() {
       return "PasswordResetEmailEvent[toEmail=" + LogMaskingUtil.maskEmail(toEmail)
           + ", rawToken=<redacted>, userId=" + userId + "]";
     }
   }
   ```
2. `MailSenderPort` — add method:
   ```java
   void sendPasswordResetEmail(String toEmail, String rawToken);
   ```
3. `SmtpMailSenderAdapter` — implement `sendPasswordResetEmail` (send SMTP with reset link body; link format: `${nexus.frontend.base-url}/auth/reset-password?token={rawToken}`)
4. `LoggingMailSenderAdapter` — implement `sendPasswordResetEmail` (log masked email + `[reset link suppressed]`)
5. `MailEventListener` — add handler:
   ```java
   @Async
   @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
   public void onPasswordReset(PasswordResetEmailEvent event) {
     log.debug("Dispatching reset email to {}", LogMaskingUtil.maskEmail(event.toEmail()));
     mailSenderPort.sendPasswordResetEmail(event.toEmail(), event.rawToken());
   }
   ```

### Tests
- `MailEventListenerTest`: `onPasswordReset` calls `mailSenderPort.sendPasswordResetEmail` with correct args
- `LoggingMailSenderAdapterTest`: `sendPasswordResetEmail` logs masked email; rawToken NOT in log output
- `PasswordResetEmailEvent.toString()` does not contain rawToken (SEC-3 log scrub)

### Acceptance criteria verified
- T-I3 (token not logged), T-R2 (repudiation via logs prevented)

---

## T4 — `SecureEventService.revokeAllUserSessions`

**Layer:** `identity.application.service`  
**Depends on:** T2  
**Parallelisable with:** T3

### What to build

Add to `SecureEventService`:
```java
@Transactional(propagation = Propagation.REQUIRES_NEW)
public void revokeAllUserSessions(UUID userId, Instant revokedAt) {
  refreshTokenPort.revokeByUserId(userId, revokedAt);
}
```

### Tests
- `SecureEventServiceTest`: `revokeAllUserSessions` calls `refreshTokenPort.revokeByUserId` with correct args in a new transaction (verify REQUIRES_NEW via `@Transactional` annotation or integration test)
- Verify existing `revokeFamily` tests still pass

### Acceptance criteria verified
- AC-3: all refresh families revoked on successful reset (via `revokeByUserId`)

---

## T5 — `ForgotPasswordUseCase`

**Layer:** `identity.application`  
**Depends on:** T1, T2, T3, T4  
**Parallelisable with:** T6 (after T1-T4 are merged)

### What to build

`ForgotPasswordUseCase` (`@Service`, `@Transactional`):

```
execute(UUID tenantId, String email, RequestContext ctx):
  1. emailHmac = emailBlindIndexService.blindIndex(email)
  2. userOpt = userRegistrationPort.findByTenantAndEmailHmac(tenantId, emailHmac)
  3. if userOpt.isEmpty() → return (no-op)
  4. user = userOpt.get()
  5. sinceOneHour = clock.instant().minus(1, HOURS)
  6. count = authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(user.getId(), RESET, sinceOneHour)
  7. if count >= MAX_RESET_REQUESTS_PER_HOUR (3):
       secureEventService.recordEvent(PASSWORD_RESET_THROTTLED event)
       return
  8. rawToken = tokenGenerator.generate()
  9. tokenHash = tokenHasher.hash(rawToken)
  10. expiresAt = clock.instant().plus(AUTH_RESET_TOKEN_TTL)
  11. authTokenPort.save(AuthToken.forReset(uuidGenerator.newId(), user.getId(), tokenHash, expiresAt))
  12. decryptedEmail = emailCipher.decrypt(user.getEmailCipher())
  13. eventPublisher.publishEvent(new PasswordResetEmailEvent(decryptedEmail, rawToken, user.getId()))
  14. secureEventService.recordEvent(PASSWORD_RESET_REQUESTED event)
```

Constants: `MAX_RESET_REQUESTS_PER_HOUR = 3` (package-private for tests).

### Tests

**Unit tests (`ForgotPasswordUseCaseTest`):**
- Unknown email → no token saved, no event published
- Known user, first request → token saved, `PasswordResetEmailEvent` published, `PASSWORD_RESET_REQUESTED` recorded
- Known user, 3rd request (count=2) → email sent (still under limit)
- Known user, 4th request (count=3) → no email, `PASSWORD_RESET_THROTTLED` recorded (AC-5)
- Token type is RESET, expiresAt = now + 60 min

**Integration test (`ForgotPasswordUseCaseIT`):**
- Full path with Testcontainers MySQL: user exists, token row created, `PASSWORD_RESET_REQUESTED` event in `auth_events`
- Timing test: known vs. unknown email request duration delta < 50ms (measure with `Instant.now()` before/after)

### Acceptance criteria verified
- AC-1 (uniform response — always 202 from controller perspective)
- AC-5 (throttle max 3/hr)

---

## T6 — `ResetPasswordUseCase`

**Layer:** `identity.application`  
**Depends on:** T1, T2, T4  
**Parallelisable with:** T5

### What to build

`ResetPasswordUseCase` (`@Service`, `@Transactional`):

```
execute(String rawToken, String newPassword, RequestContext ctx):
  1. tokenHash = tokenHasher.hash(rawToken)
  2. tokenOpt = authTokenPort.findByTokenHash(tokenHash)
  3. if empty → record(PASSWORD_RESET_FAILED) → throw TokenExpiredException(AUTH_RST_002, MSG)
  4. token = tokenOpt.get()
  5. if token.type != RESET → record(RESET_FAILED) → throw TokenExpiredException(AUTH_RST_002, MSG)
  6. now = clock.instant()
  7. if now.isAfter(token.expiresAt) → record(RESET_FAILED) → throw TokenExpiredException(AUTH_RST_002, MSG)
  8. if token.consumedAt != null → record(RESET_FAILED) → throw TokenExpiredException(AUTH_RST_002, MSG)
  9. passwordPolicyService.validate(newPassword)
  10. user = userRegistrationPort.findById(token.userId).orElseThrow(IllegalStateException)
  11. if passwordVerifier.matches(newPassword, user.passwordHash):
        throw FieldValidationException(AUTH_RST_003, "password", "New password must differ from current password.")
  12. newHash = passwordHasher.hash(newPassword)
  13. try:
        authTokenPort.markConsumed(token, now)
        authTokenPort.flush()
      catch OptimisticLockingFailureException:
        throw TokenExpiredException(AUTH_RST_002, MSG)
  14. user.applyPasswordReset(newHash)
  15. userRegistrationPort.save(user)
  16. secureEventService.revokeAllUserSessions(user.getId(), now)
  17. secureEventService.recordEvent(PASSWORD_CHANGED event with userId)
```

### Tests

**Unit tests (`ResetPasswordUseCaseTest`):**
- Token not found → `TokenExpiredException` AUTH_RST_002
- Token found but type=VERIFICATION → `TokenExpiredException` AUTH_RST_002
- Token expired (expiresAt in past) → `TokenExpiredException` AUTH_RST_002
- Token already consumed → `TokenExpiredException` AUTH_RST_002
- New password fails length check → `FieldValidationException` AUTH_PWD_001
- New password in denylist → `FieldValidationException` AUTH_PWD_002
- New password equals current → `FieldValidationException` AUTH_RST_003
- Happy path: token consumed, `user.applyPasswordReset` called, `revokeAllUserSessions` called, `PASSWORD_CHANGED` recorded
- `OptimisticLockingFailureException` on flush → `TokenExpiredException` AUTH_RST_002
- LOCKED user: after reset, status is ACTIVE (AC-4)

**Integration tests (`ResetPasswordUseCaseIT`):**
- Full flow with Testcontainers MySQL: token created, reset executed, user now ACTIVE, old refresh tokens revoked
- Concurrent reset with same token: second call returns `TokenExpiredException` (T-T2)
- `PASSWORD_CHANGED` + `PASSWORD_RESET_FAILED` events in `auth_events`

### Acceptance criteria verified
- AC-2 (single-use, 1h expiry, 410 on reuse)
- AC-3 (sessions revoked)
- AC-4 (LOCKED → ACTIVE)
- AC-6 (policy + same-password check)

---

## T7 — `PasswordResetController`, DTOs, `SecurityConfig`

**Layer:** `identity.interfaces.rest` / `config`  
**Depends on:** T5, T6  
**Parallelisable with:** nothing (final backend task)

### What to build
1. DTOs (records with Bean Validation):
   - `ForgotPasswordRequest(@NotBlank @Email @Size(max=254) String email)`
   - `ForgotPasswordResponse(String message)`
   - `ResetPasswordRequest(@NotBlank @Size(min=64, max=64) String token, @NotBlank @Size(max=256) String newPassword)`
   - `ResetPasswordResponse(String message)`
2. `PasswordResetController` per design (§6 of 03-design.md):
   - `POST /api/v1/auth/password/forgot` → 202
   - `POST /api/v1/auth/password/reset` → 200
   - No `@ConditionalOnProperty`
3. `SecurityConfig`: add `/api/v1/auth/password/forgot` and `/api/v1/auth/password/reset` to `permitAll`

### Tests

**Controller unit tests (`PasswordResetControllerTest` with `@WebMvcTest`):**
- Valid forgot request → 202 + message body
- Blank email → 400 VALIDATION_FAILED
- Invalid email format → 400 VALIDATION_FAILED
- Valid reset request → 200 + message body
- Token too short/long → 400 VALIDATION_FAILED
- `ForgotPasswordUseCase` throws nothing (always swallowed at use-case level)
- `ResetPasswordUseCase` throws `TokenExpiredException` → 410 AUTH_RST_002
- `ResetPasswordUseCase` throws `FieldValidationException(AUTH_PWD_001)` → 400

**Integration tests (`PasswordResetControllerIT`):**
- Full E2E: `POST /forgot` → token in DB → `POST /reset` → 200; user can log in with new password; old refresh tokens rejected
- Anti-enumeration: `POST /forgot` with non-existent email → 202 (same body)
- Reset with used token → 410
- Reset with expired token → 410 (clock manipulation)
- AC-5 throttle: 4 consecutive `/forgot` for same user → all 202 but only 3 tokens in DB
- Security: `POST /forgot` and `POST /reset` accessible without Authorization header (permitAll)

### Acceptance criteria verified
- All 6 AC (full-stack)
- SecurityConfig allows unauthenticated access

---

## T8 — Frontend: `AuthService` extensions + `auth.routes.ts`

**Layer:** Frontend `features/auth`  
**Depends on:** T7 (backend must be ready for contract alignment)  
**Parallelisable with:** nothing (frontend tasks chain from here)

### What to build
1. `AuthService` — add two methods:
   ```typescript
   forgotPassword(email: string): Observable<{ message: string }> {
     return this.http.post<{ message: string }>(
       `${this.config.apiUrl}/auth/password/forgot`, { email });
   }

   resetPassword(token: string, newPassword: string): Observable<{ message: string }> {
     return this.http.post<{ message: string }>(
       `${this.config.apiUrl}/auth/password/reset`, { token, newPassword });
   }
   ```
2. `auth.routes.ts` — add:
   ```typescript
   { path: 'forgot-password', loadComponent: () =>
       import('./forgot-password/forgot-password.component').then(m => m.ForgotPasswordComponent) },
   { path: 'reset-password', loadComponent: () =>
       import('./reset-password/reset-password.component').then(m => m.ResetPasswordComponent) },
   ```

### Tests (`auth.service.spec.ts`)
- `forgotPassword` POSTs to correct URL with `{ email }`
- `resetPassword` POSTs to correct URL with `{ token, newPassword }`
- Both use `apiErrorInterceptor` (by virtue of `HttpClient` — no extra test needed)

---

## T9 — Frontend: `ForgotPasswordComponent`

**Layer:** Frontend `features/auth/forgot-password`  
**Depends on:** T8  
**Parallelisable with:** T10, T11

### What to build

Standalone component with:
- `ChangeDetectionStrategy.OnPush`
- Signals: `loading`, `submitted`, `errorMessage`
- Reactive form: `email` (`required`, `email`, `maxLength(254)`)
- On submit: call `authService.forgotPassword(email)`:
  - Success (202): `submitted.set(true)` → show "If an account exists, a reset link has been sent."
  - Error 400 (VALIDATION_FAILED): show field error inline (structural only — not enumeration)
  - Any other error: generic message
- WCAG 2.1 AA: label associated, errors via `aria-describedby`
- Router link "Back to sign in" → `/auth/login`

### Tests (`forgot-password.component.spec.ts`)
- Renders email field and submit button
- Submit with blank email → client-side validation error, service not called
- Submit with invalid email format → validation error
- Submit with valid email → `authService.forgotPassword` called; on success, confirmation message shown
- Submitted state: form hidden, confirmation shown
- Loading state: button disabled during request

---

## T10 — Frontend: `ResetPasswordComponent`

**Layer:** Frontend `features/auth/reset-password`  
**Depends on:** T8  
**Parallelisable with:** T9, T11

### What to build

Standalone component with:
- `ChangeDetectionStrategy.OnPush`
- On init: read `token` query param via `inject(ActivatedRoute).queryParamMap`
- Signals: `loading`, `success`, `errorMessage`, `tokenFromUrl`
- Reactive form: `newPassword` (`required`, `minLength(12)`, `maxLength(256)`)
- Reuse `PasswordStrengthMeterComponent` from `registration-form/password-strength-meter/`
- On submit: call `authService.resetPassword(tokenFromUrl(), newPassword)`:
  - Success (200): navigate to `/auth/login?reset=true`
  - `AUTH_RST_002` → "This reset link has expired or already been used. [Request a new one]"
  - `AUTH_PWD_001` → "Password must be at least 12 characters."
  - `AUTH_PWD_002` → "Password is too common. Choose a different one."
  - `AUTH_RST_003` → "New password must be different from your current password."
- WCAG 2.1 AA: label, `aria-describedby`, strength meter conveys level via text + icon

### Tests (`reset-password.component.spec.ts`)
- Reads token from query param on init
- Blank password → validation error; service not called
- Short password (< 12 chars) → client-side error
- Calls `authService.resetPassword` with correct token + password
- `AUTH_RST_002` → shows expired message with link to forgot-password
- `AUTH_PWD_001/002/RST_003` → shows correct message
- Success → navigates to `/auth/login?reset=true`

---

## T11 — Frontend: `LoginFormComponent` changes

**Layer:** Frontend `features/auth/login-form`  
**Depends on:** T8  
**Parallelisable with:** T9, T10

### What to build

Two minimal changes to `LoginFormComponent`:
1. Add "Forgot password?" link below password field:
   ```html
   <p class="login-form__forgot-link">
     <a routerLink="/auth/forgot-password">Forgot password?</a>
   </p>
   ```
2. On init, check `ActivatedRoute.queryParamMap` for `reset=true`; if present, show a success banner: "Password reset successfully. Please sign in." (one-time display; cleared on dismiss or interaction)

Signal: `resetSuccess = signal(false)` — set from query param.

### Tests (extend `login-form.component.spec.ts`)
- "Forgot password?" link present and points to `/auth/forgot-password`
- `?reset=true` query param → success banner visible
- No `?reset` param → no banner

### Acceptance criteria verified
- Login form escape path (AUTH_LCK_001 scenario) links to forgot-password
- Post-reset success feedback (UX close-out)

---

## Sequencing Summary

| Wave | Tasks | Notes |
|------|-------|-------|
| 1 | T1 | Migration must merge before domain changes |
| 2 | T2 | Domain, no runtime deps |
| 3 | T3, T4 | Parallel: mail infrastructure and SecureEventService |
| 4 | T5, T6 | Parallel: use-cases (both depend on T3+T4) |
| 5 | T7 | Controller + SecurityConfig (depends on both use-cases) |
| 6 | T8 | FE auth service + routes (after BE contract is stable) |
| 7 | T9, T10, T11 | Parallel: three FE components |

---

## Test Plan Summary

| Category | Coverage |
|----------|----------|
| Unit | AuthToken, User domain methods; each use-case (mocked ports); controller (WebMvcTest); FE components (Vitest) |
| Integration (Testcontainers) | ForgotPasswordUseCaseIT, ResetPasswordUseCaseIT, PasswordResetControllerIT |
| Security | Token entropy, log-scrub (no raw token in output), concurrent-reset race, timing anti-enumeration |
| E2E (Playwright) | Happy path: forgot → email link → reset → login with new password |

JaCoCo gate: all new classes must contribute to the ≥ 80% line-coverage threshold.

---

## Risk Register (Implementation)

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| `@TransactionalEventListener(AFTER_COMMIT)` does not fire in tests without real TX | Low | Med | Use `@SpringBootTest` + Testcontainers IT for mail event tests; not `@WebMvcTest` |
| Argon2 hash in step 12 (`passwordHasher.hash`) is slow in unit tests | Low | Low | Use test profile with reduced Argon2 params (existing `PasswordEncoderConfig` test profile) |
| `PasswordStrengthMeterComponent` import path changes due to relocation | Low | Low | Check path before T10; adjust import if needed |
