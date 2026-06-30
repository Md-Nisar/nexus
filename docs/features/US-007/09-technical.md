# Technical Reference — US-007: Self-Service Password Reset via Email

Cross-reference: [Design](03-design.md) · [Threat model](03b-threat-model.md) · [Tasks](04-tasks.md) · [ADR 0010](../../adr/0010-password-reset-token-in-url.md)

---

## Overview

US-007 adds a self-service password reset flow. A user who has forgotten their password submits their email address; if the address is registered, a single-use 256-bit reset link is emailed. Following the link presents a form where the user sets a new password, after which all existing sessions are revoked and the user is redirected to the login page with a success banner.

The entire flow is hardened against account enumeration (`POST /forgot` always returns 202), token brute-forcing (256-bit entropy + SHA-256 storage + single-use), email bombing (3-per-account-per-hour DB throttle + filter-level per-IP/per-email rate limits), and credential stuffing (password policy reuse on reset).

---

## Architecture

### Backend — hexagonal layers

```
interfaces/rest
  PasswordResetController          POST /api/v1/auth/password/forgot → 202
                                   POST /api/v1/auth/password/reset  → 200

application
  ForgotPasswordUseCase            Validates, throttles, generates token, records audit
  ResetPasswordUseCase             Validates token, applies policy, resets credential
  TokenGenerator                   32-byte SecureRandom → 64-char hex (256-bit entropy)
  TokenHasher                      SHA-256 of raw token; only the hash is persisted
  EmailBlindIndexService           HMAC-SHA256 of normalised email for blind index lookup
  PasswordPolicyService            AUTH_PWD_001 / AUTH_PWD_002 — reused from US-006
  event/PasswordResetEmailEvent    Record (toEmail, rawToken, userId) — toString redacts both
  service/SecureEventService       revokeAllUserSessions (REQUIRES_NEW), recordEvent

infrastructure/mail
  MailEventListener                @Async @TransactionalEventListener(AFTER_COMMIT)
  SmtpMailSenderAdapter            Builds reset URL; sends via JavaMailSender
  LoggingMailSenderAdapter         Stubs email in dev; token suppressed from logs

infrastructure/web
  LoginRateLimitFilter             Extended: FORGOT_IP + FORGOT_USER + RESET_IP buckets

domain
  AuthToken.forReset()             Factory method; type = RESET
  User.applyPasswordReset()        Hash update + tokenVersion++ + status = ACTIVE + lockout reset
```

### Frontend components

| Component | Route | Purpose |
|-----------|-------|---------|
| `ForgotPasswordComponent` | `/auth/forgot-password` | Email form; anti-enumeration confirmation |
| `ResetPasswordComponent` | `/auth/reset-password?token=<hex>` | New-password form; reads + strips token from URL |
| `LoginFormComponent` | `/auth/login?reset=true` | Shows success banner after redirect |

Both new components use `ChangeDetectionStrategy.OnPush`, standalone, and Angular signals for all reactive state.

---

## Key Design Decisions

### 1. Anti-enumeration: always 202

`POST /forgot` returns 202 with the same body regardless of whether the email is registered. The not-found path performs a dummy `tokenGenerator.generate()` (SecureRandom + hex) to partially equalize CPU-bound timing with the found path. A residual DB round-trip timing difference (1 COUNT + 1 INSERT on the found path vs. 0 on the not-found path) is accepted as an architectural constraint; see ADR 0010 for mitigation rationale.

### 2. Token entropy and storage

`TokenGenerator` draws 32 bytes from `SecureRandom` and encodes as 64-char lowercase hex (256-bit entropy). The raw token is passed only to the email body; `TokenHasher` applies SHA-256 before persistence. The database stores only `token_hash`; the raw token is never written to any column, log line, or error response.

### 3. Single-use enforcement via optimistic locking

`ResetPasswordUseCase` calls `authTokenPort.markConsumed(token, now)` followed by `authTokenPort.flush()` before the Argon2 hash call. Under concurrent duplicate submissions, the second request hits an `OptimisticLockingFailureException` from the JPA `@Version` column and receives a 410. This fail-fast pattern avoids paying the full Argon2 cost twice.

### 4. Asynchronous email dispatch

`MailEventListener.onPasswordReset` is annotated `@Async @TransactionalEventListener(AFTER_COMMIT)`. The SMTP call is offloaded to the Spring async executor; it fires only after the outer transaction commits, so phantom emails are impossible on rollback.

### 5. Audit durability: REQUIRES_NEW on failure events

`SecureEventService.recordEvent` is annotated `@Transactional(propagation = REQUIRES_NEW)`. When `ResetPasswordUseCase` calls `recordFailure()` and then throws `TokenExpiredException`, the outer `@Transactional` rolls back but the `PASSWORD_RESET_FAILED` audit event has already committed in its own sub-transaction. This invariant is documented inline and tested in `ResetPasswordUseCaseTest`.

### 6. Session revocation on successful reset

`User.applyPasswordReset()` increments `tokenVersion`, which invalidates all outstanding JWTs (access tokens use `tokenVersion` as a claim; `JwtAuthenticationFilter` rejects tokens whose claim does not match). `SecureEventService.revokeAllUserSessions()` additionally marks all `auth_tokens` of type REFRESH for the user as revoked, closing the refresh-token escape window. Revocation failure is swallowed with a WARN log; the password change and audit event still commit.

### 7. Rate limiting: three tiers

| Tier | Key prefix | Limit (default) | Scope |
|------|-----------|----------------|-------|
| Filter — `/forgot` per IP | `FORGOT_IP:<ip>` | 10 / 60 s | `LoginRateLimitFilter` |
| Filter — `/forgot` per email HMAC | `FORGOT_USER:<hmac>` | 5 / 900 s | `LoginRateLimitFilter` |
| Filter — `/reset` per IP | `RESET_IP:<ip>` | 20 / 60 s | `LoginRateLimitFilter` |
| Application — per account per hour | DB COUNT on `auth_tokens` | 3 / hour | `ForgotPasswordUseCase` |

The application-level throttle uses the existing `auth_tokens` table with a covering index `idx_auth_tokens_user_id_type_created_at` (created in V3, shared with `ResendVerificationUseCase`). A TOCTOU race is possible when concurrent requests pass the COUNT check simultaneously before any INSERT; the filter-level per-email bucket reduces this window significantly. A SELECT FOR UPDATE guard is noted as a future hardening candidate.

### 8. Token expiry

Reset tokens expire after 1 hour (`AuthConstants.AUTH_RESET_TOKEN_TTL`). Expired or consumed tokens map to 410 with code `AUTH_RST_002`.

---

## Database

### Existing index (no new migration)

`idx_auth_tokens_user_id_type_created_at` on `auth_tokens(user_id, type, created_at)` was already created in V3 for `ResendVerificationUseCase`'s throttle query. The same index covers `ForgotPasswordUseCase.countByUserIdAndTypeAndCreatedAtAfter` — no new Flyway migration is required.

### No new tables or columns

All reset tokens are stored in the existing `auth_tokens` table using `type = 'RESET'`. Consumed tokens are soft-deleted (`consumed_at` timestamp set); the column was added in an earlier migration.

---

## Configuration

### New properties (application.yml)

```yaml
nexus:
  security:
    rate-limit:
      forgot-ip-max-attempts: 10   # POST /api/v1/auth/password/forgot per-IP per window
      reset-ip-max-attempts: 20    # POST /api/v1/auth/password/reset  per-IP per window
  frontend:
    base-url: ${NEXUS_FRONTEND_BASE_URL:http://localhost:2000}  # pre-existing, used in reset URL
  mail:
    from-address: ${NEXUS_MAIL_FROM_ADDRESS:noreply@nexus.example.com}  # pre-existing
```

All other mail and security configuration is pre-existing (US-004 / US-006).

---

## Security Properties

| Property | Implementation | Reference |
|----------|---------------|-----------|
| Anti-enumeration | 202 always + dummy token generation on not-found path | T-I1, T-I2 |
| Token entropy | 32-byte SecureRandom, 256-bit hex | T-S1 |
| Token storage | SHA-256 hash only; raw token never persisted | SEC-3 |
| Single-use | `markConsumed + flush` with optimistic lock | T-S2, T-T2 |
| Token TTL | 1 hour | T-S1 |
| Password policy | `PasswordPolicyService` (length + denylist) + same-password check | T-E3 |
| Session revocation | `revokeAllUserSessions` (REQUIRES_NEW) + `tokenVersion++` | AC-3 |
| Audit trail | `PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET_FAILED`, `PASSWORD_RESET_THROTTLED`, `PASSWORD_CHANGED` | T-R1 |
| PII in logs | Raw email masked via `LogMaskingUtil.maskEmail()`; raw token always `<redacted>` | SEC-3 |
| Token in URL | Stripped from browser history via `router.navigate(replaceUrl:true)` after reading | LOW-1 |
| Rate limiting | Three-tier: filter IP + filter email-HMAC + application DB count | AC-5, SECURITY.md §8 |

---

## Error Codes

| Code | HTTP | Trigger |
|------|------|---------|
| `AUTH_RST_002` | 410 | Token not found, expired, already consumed, or wrong type |
| `AUTH_PWD_001` | 400 | New password too short (< 12 chars) |
| `AUTH_PWD_002` | 400 | New password in common-password denylist |
| `AUTH_RST_003` | 400 | New password same as current password |
| `VALIDATION_FAILED` | 400 | Blank/malformed email in forgot request; blank/wrong-length token |
| `RATE_001` | 429 | Per-IP or per-email rate limit exceeded on either endpoint |

---

## Test Coverage

369 backend tests, 0 failures. See [08-test-audit.md](08-test-audit.md) for full source→test map.

Frontend: 87.46% statement coverage, 82.09% branch coverage. All 13 `ResetPasswordComponent` tests, 9 `ForgotPasswordComponent` tests, and 6 `AuthService` tests pass.
