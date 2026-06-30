# Rollback Plan — US-007: Self-Service Password Reset

---

## Code Rollback

Standard git revert to the previous release tag. No special steps beyond normal deployment rollback.

After rollback:
- `POST /api/v1/auth/password/forgot` and `POST /api/v1/auth/password/reset` return 404.
- Frontend routes `/auth/forgot-password` and `/auth/reset-password` return the Angular 404 page.
- The "Forgot password?" link on the login form disappears (frontend rolled back).
- The `?reset=true` success banner on login disappears.

---

## Database Rollback

### No new migration to roll back

US-007 adds no new Flyway migration. The index `idx_auth_tokens_user_id_type_created_at` on `auth_tokens(user_id, type, created_at)` was created in V3 (for `ResendVerificationUseCase`) and is shared with the reset throttle query; it is not rolled back as part of US-007 rollback.

### Reset tokens in auth_tokens

Any `RESET`-type tokens created while the feature was live will remain in `auth_tokens`. They will not be consumed (the endpoint is down) and will expire naturally after 1 hour. No cleanup is required.

**Irreversible data:** `auth_events` rows with event types `PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET_FAILED`, `PASSWORD_RESET_THROTTLED`, and `PASSWORD_CHANGED` (sourced from the reset flow) cannot be removed without violating audit integrity. These rows are immutable by design.

---

## Partial Rollback (backend only, frontend stays)

If the backend is rolled back but the frontend is not:
- Clicking "Forgot password?" or submitting either form will receive a network error / 404.
- The frontend displays "An unexpected error occurred." which is a safe failure mode.

---

## Kill Switch (without rollback)

To disable the feature without a full deployment:

1. **Remove permitAll entries from SecurityConfig** — re-deploy backend. Both endpoints return 401. Frontend shows "An unexpected error occurred." which is acceptable.

2. **Nginx / CDN block** — add `deny all` rules for the two API paths at the reverse proxy layer. Returns 403. No application redeploy needed.

---

## No Cache Invalidation Required

The `LoginRateLimitFilter` uses an in-memory `RateLimitStore` (default). Rate-limit state is lost on restart; no Redis flush is needed unless the Redis store type is configured (`nexus.security.rate-limit.store-type: redis`). In the Redis case, flush the `FORGOT_IP:*`, `FORGOT_USER:*`, and `RESET_IP:*` key prefixes:

```bash
redis-cli --scan --pattern "FORGOT_IP:*" | xargs redis-cli del
redis-cli --scan --pattern "FORGOT_USER:*" | xargs redis-cli del
redis-cli --scan --pattern "RESET_IP:*" | xargs redis-cli del
```
