# Release Notes — US-002: Self-Service Registration with Email Verification

**Status:** Ready for release  
**Date:** 2026-06-20  
**Feature flag:** `feature.nexus-us002-auth-registration.enabled`  
**Design reference:** `docs/features/US-002/03-design.md §13`

---

## New Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/v1/auth/register` | None | Register a new account; always returns 201 |
| `POST` | `/api/v1/auth/verify-email` | None | Consume a verification token; returns 200 or 410 |
| `POST` | `/api/v1/auth/resend-verification` | None | Resend verification email; returns 200 or 429 |

All three endpoints return 404 when `feature.nexus-us002-auth-registration.enabled=false`.

---

## Required Environment Variables

### New variables (must be set before enabling the flag)

| Variable | Purpose | Example | Envs required |
|----------|---------|---------|---------------|
| `NEXUS_IDENTITY_DEFAULT_TENANT_ID` | UUID of the default tenant for self-registered users | `00000000-0000-7000-8000-000000000001` | staging, prod |
| `NEXUS_ARGON2_MEMORY_KB` | Argon2id memory cost in KiB. Default `19456` (19 MiB — OWASP min). Increase for higher security at higher CPU cost. | `19456` | staging, prod |
| `NEXUS_ARGON2_ITERATIONS` | Argon2id iteration count. Default `2`. | `2` | staging, prod |
| `NEXUS_ARGON2_PARALLELISM` | Argon2id parallelism factor. Default `1`. | `1` | staging, prod |
| `NEXUS_MAIL_FROM_ADDRESS` | From-address on all transactional emails. Default `noreply@nexus.example.com`. | `noreply@yourdomain.com` | staging, prod |
| `NEXUS_FRONTEND_BASE_URL` | Base URL of the Angular frontend — used to construct the verification link. | `https://app.yourdomain.com` | staging, prod |
| `MAIL_HOST` | SMTP relay hostname. No default — required in staging/prod. | `smtp.sendgrid.net` | staging, prod |
| `MAIL_PORT` | SMTP port. Default `587` (STARTTLS). | `587` | staging, prod |
| `MAIL_USERNAME` | SMTP auth username. | `apikey` | staging, prod |
| `MAIL_PASSWORD` | SMTP auth password / API key. **Inject via secrets manager — never commit.** | `SG.xxxxx` | staging, prod |
| `FEATURE_AUTH_REGISTRATION_ENABLED` | Feature flag. Default `false`. Set to `true` per rollout stage. | `true` | staging, prod |

### Pre-existing variables (unchanged — included for completeness)

| Variable | Purpose | Envs required |
|----------|---------|---------------|
| `NEXUS_IDENTITY_ENCRYPTION_PASSWORD` | AES-256-GCM master password for email encryption (≥ 16 chars) | staging, prod |
| `NEXUS_IDENTITY_ENCRYPTION_SALT` | Hex-encoded KDF salt (≥ 32 hex chars) | staging, prod |
| `NEXUS_IDENTITY_HMAC_KEY` | HMAC-SHA256 key for email blind index (≥ 32 bytes) | staging, prod |
| `DB_URL` | JDBC URL for MySQL | staging, prod |
| `DB_USERNAME` | DB username | staging, prod |
| `DB_PASSWORD` | DB password | staging, prod |

### STARTTLS (SEC-4)

The base `application.yml` enforces STARTTLS for all non-dev environments:

```yaml
spring.mail.properties.mail.smtp.starttls.enable=true
spring.mail.properties.mail.smtp.starttls.required=true
```

Ensure the SMTP relay at `MAIL_HOST` supports STARTTLS on `MAIL_PORT`. Do **not** override these to `false` outside of local dev.

---

## Database Migrations

| Version | File | Change |
|---------|------|--------|
| V3 | `V3__add_password_hash_to_users.sql` | Adds `password_hash VARCHAR(255) NOT NULL DEFAULT ''` to `users`; adds `idx_auth_tokens_user_id_type_created_at` index on `auth_tokens` |

Flyway runs automatically on startup (`spring.flyway.enabled=true`). Migration is additive — safe to apply without downtime on a live `users` table. The `DEFAULT ''` placeholder is overwritten immediately on first write.

---

## Rollout Plan

Feature is off-by-default (`FEATURE_AUTH_REGISTRATION_ENABLED=false`). Enable per environment:

| Day | Traffic | Action | Success criteria |
|-----|---------|--------|-----------------|
| 1 | 1% | Enable flag via API gateway canary (header injection) | Registration p95 < 2 s; error rate < 1% |
| 2 | 10% | Increase canary weight | Error rate < 0.5%; email delivery rate > 99% |
| 3 | 50% | Monitor email deliverability metrics (bounces, spam score) | No increase in SMTP bounce rate |
| 4 | 100% | Full rollout | Error rate < 0.1% sustained for 24 h |
| US-003 | — | Schedule flag removal | See [Flag Removal Criteria](#flag-removal-criteria) |

**Kill switch:** set `FEATURE_AUTH_REGISTRATION_ENABLED=false` in all envs → rolling restart → all three auth endpoints return 404 within one restart cycle (< 1 min).

---

## Smoke-Test Checklist

Run after every deployment before marking the release healthy.

### Prerequisites
- `docker compose up -d` (MySQL + MailHog) or equivalent managed services
- Backend running and healthy: `curl http://localhost:1000/actuator/health/liveness`
- `FEATURE_AUTH_REGISTRATION_ENABLED=true`

### Checklist

- [ ] **Register new account**

  ```bash
  curl -s -X POST http://localhost:1000/api/v1/auth/register \
    -H "Content-Type: application/json" \
    -d '{"email":"smoke@example.com","password":"SmokeTest_99!","consentAccepted":true}' \
    -o /dev/null -w "%{http_code}"
  # Expected: 201
  ```

- [ ] **Verification email delivered**

  Check MailHog UI at `http://localhost:8025` (dev) or your SMTP relay's sent-mail log (staging/prod). Confirm one email addressed to `smoke@example.com` with a `verify-email?token=` link.

- [ ] **Verify email token**

  Copy the 64-char hex token from the email body and:

  ```bash
  curl -s -X POST http://localhost:1000/api/v1/auth/verify-email \
    -H "Content-Type: application/json" \
    -d '{"token":"<paste-token-here>"}' \
    -o /dev/null -w "%{http_code}"
  # Expected: 200
  ```

- [ ] **Duplicate registration (anti-enumeration)**

  Re-register with the same `smoke@example.com`:
  ```bash
  # Expected: 201 (same response — anti-enumeration)
  ```
  Confirm an "account already exists" email is delivered (not a second verification email).

- [ ] **Expired / invalid token returns 410**

  ```bash
  curl -s -X POST http://localhost:1000/api/v1/auth/verify-email \
    -H "Content-Type: application/json" \
    -d '{"token":"'$(python3 -c "print('f'*64)'")'"}'  \
    -o /dev/null -w "%{http_code}"
  # Expected: 410
  ```

- [ ] **Resend throttle returns 429**

  Call resend twice within 60 seconds for the same email:
  ```bash
  curl -s -X POST http://localhost:1000/api/v1/auth/resend-verification \
    -H "Content-Type: application/json" -d '{"email":"smoke@example.com"}' -w "%{http_code}"
  # First call: 200
  # Second call within 60 s: 429 with Retry-After header
  ```

- [ ] **Flag off returns 404**

  Temporarily set `FEATURE_AUTH_REGISTRATION_ENABLED=false` → restart → confirm all three endpoints return 404.

- [ ] **E2E Playwright suite green**

  ```bash
  cd nexus-frontend && npm run e2e -- e2e/auth/registration.spec.ts
  # Expected: 3 passed
  ```

---

## Flag Removal Criteria

The feature flag (`FEATURE_AUTH_REGISTRATION_ENABLED`) may be removed (hardcoded `true`) when **all** of the following are true:

- Flag has been at 100% in production for **≥ 24 hours**
- Registration endpoint error rate (5xx) is **< 0.1%** over that period
- Email delivery success rate is **≥ 99%** (check SMTP relay metrics)
- No `P0` or `P1` bugs open against US-002
- `VerificationTokenIT` concurrent-consumption test (`SEC-6`) is green in CI

**Removal procedure (target: US-003 sprint):**

1. Delete the `@ConditionalOnProperty` guard from `RegistrationController`
2. Remove `feature.nexus-us002-auth-registration.*` from all `application*.yml` files
3. Remove `FEATURE_AUTH_REGISTRATION_ENABLED` from all environment configs and secrets managers
4. Delete `WhenFeatureFlagDisabled` nested class from `RegistrationControllerIT`
5. Run full test suite — confirm green
6. PR review → merge

---

## Security Notes

| Control | Implementation | Reference |
|---------|---------------|-----------|
| SEC-1: HTTPS enforcement | HSTS header (`max-age=31536000; includeSubDomains`) via `SecurityConfig` | `03b-threat-model.md` |
| SEC-2: Email masking in logs | `LogMaskingUtil.maskEmail()` at every log site | `03b-threat-model.md` |
| SEC-3: Token never logged | Raw token omitted from all log statements | `03b-threat-model.md` |
| SEC-4: STARTTLS required | `spring.mail.properties.mail.smtp.starttls.required=true` in base config | `03b-threat-model.md` |
| SEC-5: Anti-enumeration timing | Argon2id hash computed before duplicate check; timing IT asserts `\|mean_new - mean_dup\| < 50 ms` | `RegistrationControllerIT` |
| SEC-6: Concurrent token consumption | Optimistic locking on `AuthToken`; exactly-one-succeeds IT | `VerificationTokenIT` |
| SEC-7: Password policy | Min 12 chars + breach denylist (`common-passwords.txt`) | `PasswordPolicyService` |
