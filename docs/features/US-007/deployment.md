# Deployment Guide — US-007: Self-Service Password Reset

## Prerequisites

- US-004 (mail infrastructure: `NEXUS_MAIL_*` env vars and `SmtpMailSenderAdapter` bean) deployed
- US-006 (password policy, `PasswordPolicyService`) deployed
- Flyway running with `ddl-auto: validate`

---

## Environment Variables

All mail and JWT variables are pre-existing from US-004/US-005. US-007 adds no new required env vars.

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `NEXUS_MAIL_FROM_ADDRESS` | Yes (prod) | `noreply@nexus.example.com` | Pre-existing from US-004 |
| `NEXUS_MAIL_HOST` | Yes (prod) | — | Pre-existing SMTP host |
| `NEXUS_MAIL_PORT` | Yes (prod) | 587 | Pre-existing |
| `NEXUS_MAIL_USERNAME` | Yes (prod) | — | Pre-existing |
| `NEXUS_MAIL_PASSWORD` | Yes (prod) | — | Pre-existing |
| `NEXUS_FRONTEND_BASE_URL` | Yes (prod) | `http://localhost:2000` | Used to build reset link URL; must point to production frontend |

---

## Configuration Changes

### application.yml additions

```yaml
nexus:
  security:
    rate-limit:
      forgot-ip-max-attempts: 10   # tune per traffic profile
      reset-ip-max-attempts: 20    # tune per traffic profile
```

These are added with sensible defaults. Override via env vars or deployment-specific config:

```
NEXUS_SECURITY_RATE_LIMIT_FORGOT_IP_MAX_ATTEMPTS=10
NEXUS_SECURITY_RATE_LIMIT_RESET_IP_MAX_ATTEMPTS=20
```

---

## Database Migration

**No new migration.** US-007 requires no schema change. The index `idx_auth_tokens_user_id_type_created_at` on `auth_tokens(user_id, type, created_at)` was created in V3 (for `ResendVerificationUseCase`) and is shared by the reset throttle query `countByUserIdAndTypeAndCreatedAtAfter`. Flyway runs V1–V3 automatically on a fresh database with no additional steps.

---

## Deployment Order

1. Deploy database migration (Flyway runs on startup — no manual step).
2. Deploy backend JAR — new endpoints `POST /api/v1/auth/password/forgot` and `POST /api/v1/auth/password/reset` become available.
3. Deploy frontend — new routes `/auth/forgot-password` and `/auth/reset-password` become available; "Forgot password?" link appears on login form.

Backend and frontend can be deployed independently (no breaking API contract change). Old frontend works against new backend (no existing routes changed).

---

## Feature Flag

No feature flag. The reset endpoints are always enabled (they are `permitAll` in `SecurityConfig` and have no `@ConditionalOnProperty` guard, consistent with the Gate 2 decision). To disable the feature, remove the `permitAll` entries for the two paths and redeploy.

---

## Smoke Test After Deploy

```bash
# 1. Request a reset (should return 202 for any email)
curl -s -o /dev/null -w "%{http_code}" \
  -X POST https://<host>/api/v1/auth/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email":"smoke-test@example.com"}'
# Expected: 202

# 2. Rate limit fires after configured limit (in-memory store resets on restart)
# 3. Check mail logs or SMTP relay for the reset email delivery

# 4. Frontend: navigate to /auth/forgot-password — page must load
# 5. Frontend: navigate to /auth/reset-password?token=badtoken — page must load and show form
#    (actual submission will return 410 which is expected)
```

---

## Reverse Proxy / CDN Notes

Add `Referrer-Policy: no-referrer` to the response headers for `/auth/reset-password` to prevent token leakage via the Referer header on subsequent navigation. Example (nginx):

```nginx
location /auth/reset-password {
    add_header Referrer-Policy "no-referrer" always;
    try_files $uri /index.html;
}
```
