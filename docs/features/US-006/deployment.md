# US-006 Deployment Guide

## No schema migration required

The `users` table columns added by US-006 (`failed_attempt_count`, `locked_until`, `status = LOCKED` enum value) were already present in `V2__identity_schema.sql` from prior sprint planning. No new Flyway migration is needed. Flyway's `ddl-auto: validate` will pass on any database that has already run V2.

## Config changes

### `application.yml` — rate-limit key rename

The following config keys changed from the pre-US-006 shape. **Any deployment that overrides these keys via environment variables or config maps must update them before deploying.**

| Old key | New key | Default |
|---------|---------|---------|
| `nexus.security.rate-limit.max-attempts` | `nexus.security.rate-limit.ip-max-attempts` | `10` |
| `nexus.security.rate-limit.window-seconds` | `nexus.security.rate-limit.ip-window-seconds` | `60` |
| _(new)_ | `nexus.security.rate-limit.user-max-attempts` | `5` |
| _(new)_ | `nexus.security.rate-limit.user-window-seconds` | `900` |
| _(new)_ | `nexus.security.rate-limit.refresh-max-attempts` | `30` |

If the old keys are left in place without the new ones, the application will fail to start with `PlaceholderResolutionException`.

### No new secrets / environment variables

US-006 does not introduce new environment variables. All lockout thresholds are code constants (`AuthConstants`).

## Deployment order

US-006 is a pure application change. Deploy order:

1. Ensure V2 Flyway migration has already run (verify with `SELECT version FROM flyway_schema_history ORDER BY installed_rank DESC LIMIT 1`).
2. Update all config keys (see table above) in your environment.
3. Deploy the new backend JAR.
4. Deploy the new frontend bundle.
5. Run smoke tests (see [runbook.md](runbook.md)).

Backend and frontend can be deployed in either order — the frontend change is additive (a new `case 'AUTH_LCK_001'` in the error handler); the old frontend shows a generic error message for 423 responses until updated.

## Feature flag

US-006 does not have its own feature flag. It is gated by the existing `nexus-us003-auth-login` flag:

```yaml
feature:
  nexus-us003-auth-login:
    enabled: false  # set to true in dev/staging/prod to activate the login flow
```

If `nexus-us003-auth-login` is `false`, the login endpoint is inaccessible and the lockout mechanism never fires.

## Rollback

See [rollback.md](rollback.md).
