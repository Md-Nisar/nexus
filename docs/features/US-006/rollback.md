# US-006 Rollback Plan

## Code rollback

Roll back via standard Git revert + redeploy:

```bash
git revert --no-commit <US-006-merge-commit-sha>
git commit -m "revert: roll back US-006 brute-force lockout"
# deploy the reverted backend + frontend
```

The `nexus-us003-auth-login` feature flag can be set to `false` as an immediate kill switch if a critical issue is found in production — this makes the login endpoint inaccessible, stopping the lockout mechanism from firing at all.

## Data rollback

### What is reversible

- `failed_attempt_count` values in `users` — these are runtime counters and can be reset to 0 for all rows with no user impact:
  ```sql
  UPDATE users SET failed_attempt_count = 0;
  ```

- `locked_until` values — clearing them immediately unlocks all currently locked accounts:
  ```sql
  UPDATE users SET locked_until = NULL;
  ```

- `status = 'LOCKED'` rows — restoring to ACTIVE restores access for locked users:
  ```sql
  UPDATE users SET status = 'ACTIVE' WHERE status = 'LOCKED';
  ```

### What is irreversible

- **Audit events in `auth_events`** (`ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`, `ACCOUNT_LOCKED_WRITE_FAILED`) are append-only. These records are not removed by rollback but do not affect application behaviour.

### If rollback is needed mid-deployment

If the rollback occurs while some accounts are in `LOCKED` status:
1. Run the three SQL statements above in order (reset counter → clear locked_until → set status to ACTIVE).
2. Then redeploy the reverted code.

Accounts unlocked via SQL will not have their counters reset on next login because the reset logic is removed by the rollback. This is acceptable — the accounts are now ACTIVE with a stale counter; the counter will be cleared on the next successful login once a future version re-introduces the reset logic.

## Config rollback

If rolling back to the pre-US-006 config shape, restore the old rate-limit keys:

| New key (US-006) | Old key (pre-US-006) |
|------------------|---------------------|
| `nexus.security.rate-limit.ip-max-attempts` | `nexus.security.rate-limit.max-attempts` |
| `nexus.security.rate-limit.ip-window-seconds` | `nexus.security.rate-limit.window-seconds` |

Remove the new keys `user-max-attempts`, `user-window-seconds`, `refresh-max-attempts`.

## Feature flag kill switch

```bash
# Kubernetes/Helm: patch the configmap
kubectl patch configmap nexus-config --patch '{"data":{"FEATURE_AUTH_LOGIN_ENABLED":"false"}}'
kubectl rollout restart deployment/nexus-backend
```

This disables the login endpoint entirely (HTTP 404 from the feature guard). Existing sessions (JWTs) remain valid until they expire (15 minutes for access tokens). Refresh tokens continue to work at `/api/v1/auth/refresh` — the rate-limit filter is a Servlet filter that does not have a feature-flag check.

## Cache invalidation

`InMemoryRateLimitStore` state lives in JVM heap. On pod restart or redeployment all in-memory counters are discarded — no cache invalidation is required.
