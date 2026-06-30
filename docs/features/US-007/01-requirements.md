# US-007 — Requirements Analysis: Self-Service Password Reset via Email

_Output of `/analyze-story` (business-analyst) + `feature-discovery` skill. Feeds Gate 1._

---

## 1. Problem Statement

A registered user who has forgotten their password must be able to recover access autonomously via a secure email link without contacting support. This is also the **sole escape path** for accounts locked by brute-force protection (US-006): a locked user who receives AUTH_LCK_001 must be able to click "reset your password" and regain access.

**Bounded context:** `identity` (`com.example.nexus.identity`) — the same context that owns registration, login, refresh, logout, and lockout.

**Non-goals (out of scope per story):**
- Security-question-based recovery
- SMS/TOTP recovery
- Admin-initiated forced reset
- "Change password while logged in" flow (this is an *unauthenticated* reset)

---

## 2. Reuse-First Survey

### What already exists and can be reused directly

| Asset | Location | Reuse |
|-------|----------|-------|
| `AuthTokenType.RESET` | `identity.domain.AuthTokenType` | Enum value already present — no change |
| `AUTH_RESET_TOKEN_TTL = 60 min` | `identity.domain.AuthConstants` | Constant already defined — no change |
| `auth_tokens` table (RESET ENUM) | `V2__identity_schema.sql` | Schema already supports RESET tokens |
| `AuthToken` entity | `identity.domain.AuthToken` | Reuse; add `forReset()` factory only |
| `AuthTokenPort` | `identity.application.port.out` | `save`, `findByTokenHash`, `markConsumed`, `flush`, `countByUserIdAndTypeAndCreatedAtAfter` — all reusable as-is |
| `RefreshTokenPort.revokeByUserId()` | `identity.application.port.out` | Mass-revoke on successful reset — already implemented |
| `PasswordPolicyService.validate()` | `identity.application` | Full denylist + length check — reuse for new password |
| `PasswordHasherPort` | `identity.application.port.out` | Argon2 hashing — reuse |
| `PasswordVerifierPort` | `identity.application.port.out` | Current-password comparison — reuse for "cannot equal current password" check |
| `EmailBlindIndexService.blindIndex()` | `identity.application` | Email lookup — reuse |
| `UserRegistrationPort.findByTenantAndEmailHmac()` | `identity.application.port.out` | User lookup by email — reuse |
| `TokenGenerator` / `TokenHasher` | `identity.application` | 64-char hex token generation + SHA-256 hashing — reuse |
| `SecureEventService` (REQUIRES_NEW) | `identity.application.service` | Auth event recording + session revocation — extend |
| `RateLimitStore` + `InMemoryRateLimitStore` | `identity.infrastructure.security` | Pattern reusable; but per-AC-5 throttle uses auth_tokens count, not sliding window |
| `MailSenderPort` | `identity.application.port.out` | Add one method: `sendPasswordResetEmail` |
| `MailEventListener` | `identity.infrastructure.mail` | Extend to handle `PasswordResetEmailEvent` |
| `PasswordStrengthMeterComponent` | `features/auth/registration-form/` | Reuse in `ResetPasswordComponent` |
| `NxInput`, `NxButton` (shared UI) | `shared/ui` | Reuse in new form components |

### What must be created

| Asset | Type | Reason |
|-------|------|--------|
| `AuthToken.forReset()` | Domain factory method | Symmetric to `forVerification()`, needed for construction |
| `User.unlock()` | Domain method | Reset must ACTIVE-ify LOCKED accounts; distinct from `unlockIfExpired()` (no time check) |
| `User.updatePasswordHash()` | Domain method | Update credential on reset; increment `tokenVersion` to invalidate old JWTs |
| `PasswordResetEmailEvent` | Application event | Spring event for async email dispatch (matches `VerificationEmailEvent` pattern) |
| `ForgotPasswordUseCase` | Application service | Orchestrates forgot-password request |
| `ResetPasswordUseCase` | Application service | Orchestrates token redemption + password update |
| `PasswordResetController` | REST controller | `POST /api/v1/auth/password/forgot` and `POST /api/v1/auth/password/reset` |
| `ForgotPasswordRequest` / `ResetPasswordRequest` DTOs | REST DTOs | Request bodies |
| `ForgotPasswordComponent` | Angular component | Email-entry form |
| `ResetPasswordComponent` | Angular component | Token + new-password form with strength meter |

### What needs extension (not full rewrite)

| Asset | Extension |
|-------|-----------|
| `MailSenderPort` | +`sendPasswordResetEmail(String toEmail, String rawToken)` |
| `SmtpMailSenderAdapter` / `LoggingMailSenderAdapter` | Implement new method |
| `AuthToken` | +`forReset()` static factory |
| `User` | +`unlock()` method, +`updatePasswordHash(String newHash)` method |
| `UserRegistrationPort` | +`findById(UUID)` already present; verify `save(User)` handles hash + tokenVersion update |
| `SecureEventService` | +`revokeAllUserSessions(UUID userId, Instant now)` wrapping `revokeByUserId` in REQUIRES_NEW |
| `auth.routes.ts` | Add `/forgot-password` and `/reset-password` routes |
| `LoginFormComponent` | Add "Forgot password?" link to `/auth/forgot-password` |

---

## 3. Acceptance Criteria — Annotated

| # | Criterion | Status | Implementation Note |
|---|-----------|--------|---------------------|
| AC-1 | `POST /api/v1/auth/password/forgot` always returns 202; timing delta < 50ms | New endpoint | Anti-enumeration: run dummy HMAC lookup regardless of user existence; no branch on found/not-found |
| AC-2 | Reset token single-use, 1h expiry; reused/expired → 410 + `AUTH_RST_002` | Schema ready | `AUTH_RESET_TOKEN_TTL = 60 min` already in `AuthConstants`; `markConsumed` in `AuthTokenPort` |
| AC-3 | Successful reset revokes all refresh token families within 1s | Port ready | `RefreshTokenPort.revokeByUserId()` exists; wrap in `SecureEventService.revokeAllUserSessions()` |
| AC-4 | Reset unlocks LOCKED accounts → ACTIVE | Domain gap | Need `User.unlock()` method (no expiry condition) |
| AC-5 | Max 3 reset requests/account/hour; excess silently 202 but not sent, audited | Logic new | `AuthTokenPort.countByUserIdAndTypeAndCreatedAtAfter(userId, RESET, now-1h)` ≥ 3 → suppress email, record audit event |
| AC-6 | New password passes full policy; cannot equal current password | Service ready | `PasswordPolicyService.validate()` + `PasswordVerifierPort.matches(newPassword, currentHash)` |

---

## 4. API Contract (Preliminary)

### `POST /api/v1/auth/password/forgot`
- **Auth:** `permitAll`
- **Request body:** `{ "email": "user@example.com" }`
- **Response:** `202 Accepted` — always, regardless of account existence
- **Body:** `{ "message": "If an account with that email exists, a reset link has been sent." }`
- **Error:** No 4xx user errors (enumeration prevention); 429 only at infrastructure IP layer if applicable

### `POST /api/v1/auth/password/reset`
- **Auth:** `permitAll`
- **Request body:** `{ "token": "<64-char hex>", "newPassword": "<plaintext>" }`
- **Response 200:** `{ "message": "Password reset successfully. Please sign in." }`
- **Response 410:** RFC 7807 `{ "status": 410, "code": "AUTH_RST_002", "detail": "This reset link has expired or already been used. Please request a new one." }`
- **Response 400:** RFC 7807 `{ "status": 400, "code": "AUTH_PWD_001"|"AUTH_PWD_002"|"AUTH_RST_003", ... }` (policy violations or same-password)

---

## 5. Data Flow

```
User submits email
  → ForgotPasswordUseCase
      1. HMAC lookup (always runs, even if user not found)
      2. If user found AND throttle < 3/hr: create RESET AuthToken, publish PasswordResetEmailEvent
      3. If user found AND throttle ≥ 3/hr: record RESET_THROTTLED audit event (suppress email)
      4. If user not found: no-op (but timing must match found path)
  → Return 202 always

User clicks link → submits token + newPassword
  → ResetPasswordUseCase
      1. Find token by SHA-256 hash
      2. Validate: exists, type=RESET, not consumed, not expired → else 410
      3. Policy-check newPassword (length + denylist)
      4. "Not equal to current" check via Argon2 verify
      5. Mark token consumed (optimistic lock flush)
      6. Update user: new passwordHash, tokenVersion++, status=ACTIVE (unlock), resetFailedAttempts
      7. Revoke all refresh tokens (SecureEventService.revokeAllUserSessions)
      8. Record PASSWORD_RESET_REQUESTED→PASSWORD_CHANGED audit event
  → Return 200
```

---

## 6. Non-Functional Requirements

### Security (flags for Gate 2 / threat model)
- **Anti-enumeration (T-RST-1):** `POST /forgot` timing must be uniform whether or not the email exists. The HMAC lookup itself is fast; the gap arises when email dispatch is skipped. Mitigate: always run `blindIndex()`, use constant-time comparisons.
- **Token entropy (T-RST-2):** `TokenGenerator.generate()` already produces 64-char hex (256-bit entropy via `SecureRandom`) — satisfies ≥ 128-bit requirement.
- **Token stored hashed (T-RST-3):** `TokenHasher` (SHA-256) is already in use for verification tokens — same pattern for reset.
- **Constant-time token comparison (T-RST-4):** `AuthTokenPort.findByTokenHash()` is an exact DB-index equality match on `token_hash` — effectively constant-time at the DB level.
- **Session revocation (T-RST-5):** All refresh token families revoked on reset. Outstanding 15-min access tokens remain valid unless `token_version` validation is added to `JwtAuthenticationFilter` (design decision required — flag for threat model).
- **PII (T-RST-6):** Raw token must never appear in logs (existing `SEC-3` convention). Raw email must not appear in audit events when userId is available.
- **CSRF (T-RST-7):** Both endpoints are stateless / token-based — no CSRF risk. Spring Security stateless mode confirmed.

### Performance
- Email dispatch is async via Spring `ApplicationEventPublisher` + `@Async` listener — no auth-path latency impact (pattern established by `MailEventListener`).
- `revokeByUserId` is a single bulk UPDATE on `refresh_tokens` indexed by `user_id` — O(n) for sessions per user.
- `countByUserIdAndTypeAndCreatedAtAfter` hits `idx_auth_tokens_user_id_type_consumed_at`; `created_at` is not in index — a covering index on `(user_id, type, created_at)` should be added (new Flyway migration V4).

### Observability
- Audit events: `PASSWORD_RESET_REQUESTED`, `PASSWORD_CHANGED`, `PASSWORD_RESET_THROTTLED`, `PASSWORD_RESET_FAILED` (invalid/expired token)
- Log: no raw token, no raw email (SEC-3)
- Metric: email queue backlog via existing async listener

---

## 7. Open Questions / Assumptions

| # | Question | Assumption (if not answered) | Risk |
|---|----------|------------------------------|------|
| OQ-1 | Should `token_version` increment on reset and be validated by `JwtAuthenticationFilter`? This would instantly revoke outstanding 15-min access tokens. | **Assume YES — increment `token_version`; flag as design decision for Gate 2** — the column exists; validation in the filter requires a DB lookup per request (or in-memory cache). | If deferred, reset only invalidates refresh tokens; active sessions persist up to 15 min |
| OQ-2 | Does the 3 resets/hour throttle apply per-account only, or also per-IP? | Per AC-5: per-account. IP-level is covered by the existing login filter; no separate IP throttle for reset requests. | Low |
| OQ-3 | Should "Forgot password?" link in the login form be added as part of this story? | Yes — `LoginFormComponent` already references "reset your password" in error text; adding the link is minimal and part of the frontend scope. | Low |
| OQ-4 | Is a "resend reset link" endpoint needed (analogous to resend-verification)? | No — the story doesn't list it; a user can simply submit the forgot-password form again (subject to the 3/hr throttle). | Low |
| OQ-5 | What tenant context is passed to `POST /forgot`? | Same as login: a fixed dev-default `tenantId` from `APP_CONFIG` until multi-tenancy is implemented (matches US-003 pattern). | Low |
| OQ-6 | Should `ResetPasswordComponent` auto-log the user in on success, or redirect to login? | Redirect to login with a success toast — matches the story's "regain access" framing and avoids issuing a token on a password-reset endpoint. | Low |

---

## 8. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Email delivery delay degrades recovery UX | Med | Med | Provider SLA; async dispatch; queue backlog alerting |
| Timing oracle on forgot endpoint (found vs. not-found path) | Med | High | Always run `blindIndex()`; async email removes the SMTP wait from the request path |
| JWT access tokens remain valid post-reset if token_version not checked | Med | Med | Increment `token_version`; Gate 2 design decision on filter validation |
| Optimistic lock collision on token consumption (two concurrent resets) | Low | Low | `flush()` after `markConsumed` already handles this (mirrors verification pattern) |

---

## 9. Definition of Ready

- [x] Bounded context identified: `identity`
- [x] Existing schema verified: no new migration required except covering index on `auth_tokens`
- [x] Reuse-first survey complete: 15+ assets reusable, 10 to create/extend
- [x] API shape drafted (AC-1 through AC-6 mapped)
- [x] Open questions documented (OQ-1 is the only material design decision)
- [ ] **Gate 1 approval required before proceeding to impact analysis**
