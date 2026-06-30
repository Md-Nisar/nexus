# US-007 — Technical Design

_Output of `/design` (architect). Reviewed against `api-design`, `spring-boot-standards`, `angular-standards` skills. Feeds Gate 2._

**Gate 1 decision recorded:** JWT validation remains stateless; `token_version` is NOT checked against the DB on each request. Outstanding 15-min access tokens remain valid after reset. This is an accepted residual risk documented in the threat model (03b-threat-model.md, T-RST-5).

---

## 1. API Design

### `POST /api/v1/auth/password/forgot`

**Purpose:** Accept a password-reset request. Always returns 202 regardless of whether the email is registered (anti-enumeration, AC-1).

**Request**
```http
POST /api/v1/auth/password/forgot HTTP/1.1
Content-Type: application/json

{ "email": "user@example.com" }
```

**Response — success (always)**
```http
HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "message": "If an account with that email exists, a reset link has been sent."
}
```

**Error responses**
- `400` — Bean-validation failure only (malformed JSON, blank/missing field, invalid email format). This does not reveal account existence — it fires on structurally invalid input, not on "email not found".
- No `404`, no `429` surfaced to caller (throttle is silent per AC-5).

---

### `POST /api/v1/auth/password/reset`

**Purpose:** Redeem a reset token and set a new password.

**Request**
```http
POST /api/v1/auth/password/reset HTTP/1.1
Content-Type: application/json

{
  "token": "<64-char-hex-reset-token>",
  "newPassword": "MyNewStr0ngP@ssword"
}
```

**Response — success**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "message": "Password reset successfully. Please sign in."
}
```

**Error responses**

| Status | Code | Trigger |
|--------|------|---------|
| `410 Gone` | `AUTH_RST_002` | Token not found / expired / already consumed |
| `400 Bad Request` | `AUTH_PWD_001` | New password < 12 chars |
| `400 Bad Request` | `AUTH_PWD_002` | New password in breached-password denylist |
| `400 Bad Request` | `AUTH_RST_003` | New password equals current password |
| `400 Bad Request` | `VALIDATION_FAILED` | Bean-validation failure (blank token, blank newPassword) |

All error bodies follow RFC 7807 with `code` + `traceId` extensions (existing `GlobalExceptionHandler`).

---

### SecurityConfig additions

Add to the `permitAll` matcher list in `SecurityConfig.apiSecurity()`:

```java
"/api/v1/auth/password/forgot",
"/api/v1/auth/password/reset"
```

No `@ConditionalOnProperty` on `PasswordResetController` (US-007 story: "Feature flag required: No").

---

## 2. Domain Layer Changes

### `AuthToken` — new factory method

```java
/** Factory for password-reset tokens (symmetric to forVerification). */
public static AuthToken forReset(
    UUID id, UUID userId, String tokenHash, Instant expiresAt) {
  return new AuthToken(id, userId, AuthTokenType.RESET, tokenHash, expiresAt);
}
```

### `User` — new domain method

```java
/**
 * Applies a completed password reset:
 *   1. Updates password hash.
 *   2. Increments tokenVersion (invalidates future JWTs that carry the old version;
 *      outstanding 15-min tokens remain valid — accepted residual, Gate 1 decision).
 *   3. Transitions status to ACTIVE regardless of current status (unlocks LOCKED accounts, AC-4).
 *   4. Resets failedAttemptCount and clears lockedUntil.
 */
public void applyPasswordReset(String newPasswordHash) {
  this.passwordHash = newPasswordHash;
  this.tokenVersion += 1;
  this.status = UserStatus.ACTIVE;
  this.failedAttemptCount = 0;
  this.lockedUntil = null;
}
```

This single method satisfies AC-3 (session revocation is handled separately in the use case via `SecureEventService`), AC-4 (LOCKED → ACTIVE), and AC-6 (new hash stored).

---

## 3. Application Layer

### `ForgotPasswordUseCase` — sequence

```
execute(tenantId, rawEmail, ctx):
  1. email = rawEmail.toLowerCase().strip()
  2. emailHmac = emailBlindIndexService.blindIndex(email)
  3. userOpt = userRegistrationPort.findByTenantAndEmailHmac(tenantId, emailHmac)
  4. if userOpt.isEmpty() → [no-op; timing balanced by HMAC compute] → return
  5. user = userOpt.get()
  6. sinceOneHour = clock.instant().minus(1, HOURS)
  7. count = authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(user.getId(), RESET, sinceOneHour)
  8. if count >= 3:
       secureEventService.recordEvent(PASSWORD_RESET_THROTTLED)
       return  ← silent suppression, still returns 202 to caller
  9. rawToken = tokenGenerator.generate()
  10. tokenHash = tokenHasher.hash(rawToken)
  11. expiresAt = clock.instant().plus(AUTH_RESET_TOKEN_TTL)  // 60 min
  12. authTokenPort.save(AuthToken.forReset(uuidGenerator.newId(), user.getId(), tokenHash, expiresAt))
  13. decryptedEmail = emailCipher.decrypt(user.getEmailCipher())
  14. eventPublisher.publishEvent(new PasswordResetEmailEvent(decryptedEmail, rawToken, user.getId()))
  15. secureEventService.recordEvent(PASSWORD_RESET_REQUESTED)
```

**Anti-enumeration note:** Steps 1-4 are the fast path for unknown emails. The HMAC compute (step 2) adds ~1ms regardless. Steps 5-15 add ~5-10ms for token generation and DB write. The delta is < 50ms as required by AC-1 because email dispatch is async (`@TransactionalEventListener(AFTER_COMMIT)` + `@Async`).

### `ResetPasswordUseCase` — sequence

```
execute(rawToken, newPassword, ctx):
  1. tokenHash = tokenHasher.hash(rawToken)
  2. tokenOpt = authTokenPort.findByTokenHash(tokenHash)
  3. if tokenOpt.isEmpty() → authEventPort.record(RESET_FAILED) → throw TokenExpiredException(AUTH_RST_002)
  4. token = tokenOpt.get()
  5. if token.type != RESET → [fall through to expired check — type mismatch treated same as invalid]
  6. now = clock.instant()
  7. if now.isAfter(token.expiresAt) → record(RESET_FAILED) → throw TokenExpiredException(AUTH_RST_002)
  8. if token.consumedAt != null → record(RESET_FAILED) → throw TokenExpiredException(AUTH_RST_002)
  9. passwordPolicyService.validate(newPassword)  // throws FieldValidationException on violation
  10. user = userRegistrationPort.findById(token.userId).orElseThrow(...)
  11. if passwordVerifier.matches(newPassword, user.getPasswordHash()):
        throw FieldValidationException(AUTH_RST_003, "password", "New password must be different from current password.")
  12. newHash = passwordHasher.hash(newPassword)
  13. try:
        authTokenPort.markConsumed(token, now)
        authTokenPort.flush()   // force version-check UPDATE before outer commit
      catch OptimisticLockingFailureException:
        throw TokenExpiredException(AUTH_RST_002, "...")
  14. user.applyPasswordReset(newHash)
  15. userRegistrationPort.save(user)
  16. secureEventService.revokeAllUserSessions(user.getId(), now)  // REQUIRES_NEW
  17. secureEventService.recordEvent(PASSWORD_CHANGED)
```

**Transaction boundary:** `ResetPasswordUseCase` is annotated `@Transactional`. Steps 12-15 commit together. Step 16 runs in a separate REQUIRES_NEW sub-transaction (same pattern as `SecureEventService.revokeFamily` used in logout).

### `SecureEventService` — new method

```java
@Transactional(propagation = Propagation.REQUIRES_NEW)
public void revokeAllUserSessions(UUID userId, Instant revokedAt) {
  refreshTokenPort.revokeByUserId(userId, revokedAt);
}
```

---

## 4. Database Design

### V4 Migration — covering index

File: `nexus-backend/src/main/resources/db/migration/V4__auth_tokens_reset_throttle_index.sql`

```sql
-- Covering index for the reset-request throttle query:
-- AuthTokenPort.countByUserIdAndTypeAndCreatedAtAfter(userId, RESET, since)
-- The existing idx_auth_tokens_user_id_type_consumed_at has consumed_at as the third
-- column, not created_at. This new index supports efficient throttle window scans.
-- Additive migration (ADR 0003) — append-only.
CREATE INDEX idx_auth_tokens_user_id_type_created_at
    ON auth_tokens (user_id, type, created_at);
```

No data migration. No schema modification to existing columns. No `ALTER TABLE`. Safe for zero-downtime deployment (MySQL creates the index without locking the table for reads/writes in production mode).

### `JpaAuthTokenRepository` extension

Add JPQL query method:

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

> Note: `countByUserIdAndTypeAndCreatedAtAfter` already exists on `AuthTokenPort` — this adds the JPA implementation.

---

## 5. Infrastructure — Mail

### `PasswordResetEmailEvent`

```java
public record PasswordResetEmailEvent(String toEmail, String rawToken, UUID userId) {
  @Override
  public String toString() {
    return "PasswordResetEmailEvent[toEmail=" + LogMaskingUtil.maskEmail(toEmail)
        + ", rawToken=<redacted>, userId=" + userId + "]";
  }
}
```

### `MailSenderPort` extension

```java
/**
 * Sends a password-reset link to the given address.
 *
 * @param toEmail  recipient's plaintext email address
 * @param rawToken 64-char hex reset token (must never appear in any log — SEC-3)
 */
void sendPasswordResetEmail(String toEmail, String rawToken);
```

### `MailEventListener` handler

```java
@Async
@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
public void onPasswordReset(PasswordResetEmailEvent event) {
  log.debug("Dispatching reset email to {}", LogMaskingUtil.maskEmail(event.toEmail()));
  mailSenderPort.sendPasswordResetEmail(event.toEmail(), event.rawToken());
}
```

---

## 6. REST Controller

```java
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Password reset flow")
public class PasswordResetController {

  private final ForgotPasswordUseCase forgotPasswordUseCase;
  private final ResetPasswordUseCase resetPasswordUseCase;
  private final UUID defaultTenantId;

  // constructor injection ...

  @PostMapping("/password/forgot")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public ForgotPasswordResponse forgotPassword(
      @Valid @RequestBody ForgotPasswordRequest request,
      HttpServletRequest httpRequest) {
    forgotPasswordUseCase.execute(
        defaultTenantId,
        request.email().toLowerCase(Locale.ROOT).strip(),
        requestContext(httpRequest));
    return new ForgotPasswordResponse(
        "If an account with that email exists, a reset link has been sent.");
  }

  @PostMapping("/password/reset")
  public ResetPasswordResponse resetPassword(
      @Valid @RequestBody ResetPasswordRequest request,
      HttpServletRequest httpRequest) {
    resetPasswordUseCase.execute(
        request.token(),
        request.newPassword(),
        requestContext(httpRequest));
    return new ResetPasswordResponse("Password reset successfully. Please sign in.");
  }

  private RequestContext requestContext(HttpServletRequest req) {
    return new RequestContext(req.getRemoteAddr(), MDC.get("traceId"));
  }
}
```

**DTOs**

```java
public record ForgotPasswordRequest(
    @NotBlank @Email @Size(max = 254) String email) {}

public record ForgotPasswordResponse(String message) {}

public record ResetPasswordRequest(
    @NotBlank @Size(min = 64, max = 64) String token,
    @NotBlank @Size(max = 256) String newPassword) {}

public record ResetPasswordResponse(String message) {}
```

---

## 7. Frontend Design

### Routes (`auth.routes.ts`)

```typescript
{
  path: 'forgot-password',
  loadComponent: () =>
    import('./forgot-password/forgot-password.component')
      .then(m => m.ForgotPasswordComponent),
},
{
  path: 'reset-password',
  loadComponent: () =>
    import('./reset-password/reset-password.component')
      .then(m => m.ResetPasswordComponent),
},
```

The `reset-password` route reads the `token` query param from the link URL: `/auth/reset-password?token=<hex>`.

### `AuthService` additions

```typescript
forgotPassword(email: string): Observable<void> {
  return this.http.post<void>(`${this.apiBase}/auth/password/forgot`, { email });
}

resetPassword(token: string, newPassword: string): Observable<{ message: string }> {
  return this.http.post<{ message: string }>(
    `${this.apiBase}/auth/password/reset`,
    { token, newPassword }
  );
}
```

### `ForgotPasswordComponent`

- **Type:** Smart component (calls `AuthService`)
- **State:** `loading = signal(false)`, `submitted = signal(false)`, `errorMessage = signal<string | null>(null)`
- **Form:** `email` field with `Validators.required`, `Validators.email`, `Validators.maxLength(254)`
- **Success state:** On 202, set `submitted = true` and show: "If an account exists, a reset link has been sent. Check your email."
- **Error handling:** `apiErrorInterceptor` maps to `AppError`; only structural errors (400) show inline; no enumeration possible
- **Link from login:** `<a routerLink="/auth/forgot-password">Forgot password?</a>` added below password field in `LoginFormComponent`

### `ResetPasswordComponent`

- **Type:** Smart component (calls `AuthService`)
- **State:** `loading = signal(false)`, `success = signal(false)`, `errorMessage = signal<string | null>(null)`, `tokenFromUrl = signal<string>('')`
- **Initialisation:** `inject(ActivatedRoute).queryParamMap` → read `token` param on init
- **Form:** `newPassword` field + `PasswordStrengthMeterComponent` (existing, from registration-form)
- **Validation:** `Validators.required`, `Validators.minLength(12)`, `Validators.maxLength(256)`
- **Error code mapping:**
  - `AUTH_RST_002` → "This reset link has expired or already been used. Please [request a new one](/auth/forgot-password)."
  - `AUTH_PWD_001` → "Password must be at least 12 characters."
  - `AUTH_PWD_002` → "Password is too common. Choose a different one."
  - `AUTH_RST_003` → "New password must be different from your current password."
- **Success:** Navigate to `/auth/login` with query param `?reset=true` → `LoginFormComponent` shows success toast "Password reset successfully. Please sign in."
- **WCAG 2.1 AA:** Labels associated; errors via `aria-describedby`; strength meter conveys level via text + icon (matching registration-form pattern)

### `LoginFormComponent` — minimal change

Add below the password field:
```html
<p class="login-form__forgot-link">
  <a routerLink="/auth/forgot-password">Forgot password?</a>
</p>
```

Read `?reset=true` query param on init to show a one-time success banner.

---

## 8. Audit Events Emitted

| Event Type | Outcome | When |
|------------|---------|------|
| `PASSWORD_RESET_REQUESTED` | SUCCESS | Token created and email dispatched |
| `PASSWORD_RESET_THROTTLED` | FAILURE | Request suppressed (≥ 3/hr per user) |
| `PASSWORD_RESET_FAILED` | FAILURE | Token invalid, expired, or consumed |
| `PASSWORD_CHANGED` | SUCCESS | New password saved, sessions revoked |

All events carry `userId` (when resolved), `ip_address`, and `metadata` (user-agent, traceId) per the US-008 schema.

---

## 9. Observability

- **Logs:** Debug-level on email dispatch (masked email only); warn-level on `revokeAllUserSessions` failures
- **Metrics:** No new metrics required; email async queue depth covered by existing async executor metrics
- **Alerts:** Audit event `PASSWORD_RESET_THROTTLED` high-volume → abuse indicator (downstream SIEM/alert)

---

## 10. Design Decisions Recorded

| Decision | Choice | Rationale |
|----------|--------|-----------|
| JWT stateless validation | No `token_version` DB check per request | Gate 1 approved; accept ≤15-min residual window |
| Session revocation scope | All refresh families for the user via `revokeByUserId` | AC-3: full revocation; `REQUIRES_NEW` for durability |
| Throttle mechanism | DB count on `auth_tokens` (not `RateLimitStore`) | Survives restarts; no Redis dep; per-account window |
| Error code for expired/used token | `AUTH_RST_002` on 410 | Matches AC-2; `TokenExpiredException` maps to 410 |
| Error code for same password | `AUTH_RST_003` on 400 | Distinct from `AUTH_PWD_001`/`002`; field-level |
| Feature flag | None | Story says "Feature flag required: No" |
| Post-reset navigation | Redirect to login (not auto-login) | Security best practice; avoids issuing token on reset endpoint |
