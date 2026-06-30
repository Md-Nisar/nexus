# US-007 — Impact Analysis

_Output of `/impact-analysis` (architect). Feeds Gate 2._

---

## 1. Backend Layers Touched

### `identity.domain`

| File | Change | Type |
|------|--------|------|
| `AuthToken` | Add `forReset(UUID id, UUID userId, String tokenHash, Instant expiresAt)` static factory | Extend |
| `User` | Add `applyPasswordReset(String newPasswordHash)` — sets hash, increments tokenVersion, transitions any status → ACTIVE, resets failedAttemptCount + lockedUntil | Extend |

No new domain entities or value objects. No schema change to match (both fields already exist on `users`).

### `identity.application`

| File | Change | Type |
|------|--------|------|
| `ForgotPasswordUseCase` | New: orchestrates email-lookup → throttle-check → token generation → event publish → 202 | **New** |
| `ResetPasswordUseCase` | New: orchestrates token validation → policy check → password update → session revocation → audit | **New** |
| `event/PasswordResetEmailEvent` | New Spring event record (mirrors `VerificationEmailEvent`) | **New** |
| `port/out/MailSenderPort` | +`sendPasswordResetEmail(String toEmail, String rawToken)` | Extend |

### `identity.application.service`

| File | Change | Type |
|------|--------|------|
| `SecureEventService` | +`revokeAllUserSessions(UUID userId, Instant revokedAt)` — wraps `RefreshTokenPort.revokeByUserId` in REQUIRES_NEW | Extend |

### `identity.infrastructure`

| File | Change | Type |
|------|--------|------|
| `mail/MailEventListener` | +`onPasswordReset(PasswordResetEmailEvent)` listener method | Extend |
| `mail/SmtpMailSenderAdapter` | Implement `sendPasswordResetEmail` | Extend |
| `mail/LoggingMailSenderAdapter` | Implement `sendPasswordResetEmail` | Extend |

### `identity.interfaces.rest`

| File | Change | Type |
|------|--------|------|
| `PasswordResetController` | New: `POST /api/v1/auth/password/forgot`, `POST /api/v1/auth/password/reset` | **New** |
| `dto/ForgotPasswordRequest` | New record: `{ String email }` | **New** |
| `dto/ResetPasswordRequest` | New record: `{ String token, String newPassword }` | **New** |
| `dto/ResetPasswordResponse` | New record: `{ String message }` | **New** |

### `config`

| File | Change | Type |
|------|--------|------|
| `SecurityConfig` | Add `/api/v1/auth/password/forgot` and `/api/v1/auth/password/reset` to `permitAll` | Extend |

---

## 2. Frontend Layers Touched

| File | Change | Type |
|------|--------|------|
| `features/auth/forgot-password/forgot-password.component.ts` | New standalone component: email form → POST /forgot | **New** |
| `features/auth/reset-password/reset-password.component.ts` | New standalone component: new-password form (reuses `PasswordStrengthMeterComponent`) → POST /reset | **New** |
| `features/auth/auth.service.ts` | +`forgotPassword(email)` → `POST /api/v1/auth/password/forgot` <br/> +`resetPassword(token, newPassword)` → `POST /api/v1/auth/password/reset` | Extend |
| `features/auth/auth.routes.ts` | +`{ path: 'forgot-password', ... }`, `{ path: 'reset-password', ... }` | Extend |
| `features/auth/login-form/login-form.component.ts` | Add "Forgot password?" `routerLink` below the password field | Extend |

No new shared types needed; `AppError` (existing) carries API error codes to components.

---

## 3. Database Impact

### Schema changes

**No changes to existing tables.** The `auth_tokens` table already has:
- `type ENUM('VERIFICATION','RESET')` — RESET already present
- `token_hash`, `expires_at`, `consumed_at` — all used for reset tokens

### New Flyway migration required

**V4: covering index for reset-request throttle query**

```sql
-- V4__auth_tokens_reset_throttle_index.sql
CREATE INDEX idx_auth_tokens_user_id_type_created_at
    ON auth_tokens (user_id, type, created_at);
```

The existing `idx_auth_tokens_user_id_type_consumed_at` covers `(user_id, type, consumed_at)` but not `created_at`, which `countByUserIdAndTypeAndCreatedAtAfter` filters on for throttling. Token volumes are tiny per-user, so this is a micro-optimization — the migration is additive and safe to deploy with no downtime impact.

---

## 4. API Changes

### New endpoints

| Method | URL | Auth | Description |
|--------|-----|------|-------------|
| `POST` | `/api/v1/auth/password/forgot` | `permitAll` | Request a reset link |
| `POST` | `/api/v1/auth/password/reset` | `permitAll` | Redeem token, set new password |

### Existing endpoints — no breaking changes

No existing endpoint signatures change. The `users` entity gains one new domain method (`applyPasswordReset`) but no API contract changes.

### SecurityConfig addition

```java
"/api/v1/auth/password/forgot",
"/api/v1/auth/password/reset"
```

added to the `permitAll` matcher list.

---

## 5. Cross-Context Effects

| Context | Effect |
|---------|--------|
| `common.web.GlobalExceptionHandler` | No change — `TokenExpiredException` already maps to 410, `FieldValidationException` to 400 |
| `common.domain` | No new exception types — `TokenExpiredException` and `FieldValidationException` reused |
| US-006 lockout | `applyPasswordReset` transitions LOCKED → ACTIVE, directly satisfying the "reset unlocks account" contract |
| US-008 audit events | Four new event types emitted: `PASSWORD_RESET_REQUESTED`, `PASSWORD_CHANGED`, `PASSWORD_RESET_THROTTLED`, `PASSWORD_RESET_FAILED` |

No other bounded contexts are touched.

---

## 6. Dependency Summary

| Dependency | Direction | Nature |
|------------|-----------|--------|
| `RefreshTokenPort.revokeByUserId` | Reuse | Mass-revoke all sessions on reset |
| `AuthTokenPort.countByUserIdAndTypeAndCreatedAtAfter` | Reuse | Throttle check (AC-5) |
| `PasswordPolicyService.validate` | Reuse | New-password policy (AC-6) |
| `PasswordVerifierPort.matches` | Reuse | Same-as-current check (AC-6) |
| `EmailBlindIndexService.blindIndex` | Reuse | User lookup |
| `TokenGenerator` / `TokenHasher` | Reuse | Token generation + storage |
| `MailSenderPort` | Extend | +`sendPasswordResetEmail` |
| `MailEventListener` | Extend | +`onPasswordReset` handler |
| `SecureEventService` | Extend | +`revokeAllUserSessions` REQUIRES_NEW |
