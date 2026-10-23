# US-019 Deployment Guide

**Scope:** everything on `feature/US-019` (28 tasks). See [09-technical.md](09-technical.md). Open decisions that gate a production rollout are in [14-pending-items.md](14-pending-items.md).

## 1. Summary

One data-only Flyway migration (V11), one new feature flag (off by default outside `dev` and `test`), two new configuration key groups, no new environment variable, a frontend release, and a CI workflow. Three changes are live on deploy with no flag: B7 (429 `RBAC_011`), the RC-56/RC-57 changes to assign, attach, revoke and role deletion (409 `RBAC_012`), and the platform handlers (400/405/415 instead of 500). Release notes: [CHANGELOG.md](../../../CHANGELOG.md).

## 2. Feature flags

| Property | Default (`application.yml`, so also prod) | `dev` | `test` | Gates |
|---|---|---|---|---|
| `feature.nexus-us019-user-directory.enabled` | `false` | `true` | `true` | `UserDirectoryController` (B1, B2), `CallerAuthorizationController` (B4), `LookupAuthorizationFirst`. Off: those routes are the generic 404 |
| `feature.nexus-us015-rbac-role-management.enabled` | `false` | `true` | `true` | `RoleController` (B3, B8, role and permission management) and `PermissionController` |
| `feature.nexus-us012-rbac-role-assignment.enabled` | `false` | `true` | `true` | `UserRoleController` (assign, revoke, list; the 429 `RBAC_011` lives here) |

`application-prod.yml` has no `feature.*` keys for these, so production resolves `false` unless the environment overrides them. Whether it does is not knowable from the repository (pending item P-7). The console (US-020) must never be released where B1, B3 and B4 are off.

## 3. Configuration

| Key | Default | Notes |
|---|---|---|
| `nexus.rbac.pii-grant-requires-administrator` | `true` | Granting `user:directory:read` (attach, or assign of a role carrying it) requires an administrator. No profile file overrides it, so prod resolves `true`; `PiiPermissionGrantRuleTest` pins that. **`application-prod.yml` was not edited by this story.** Setting `false` logs WARN `RBAC_PII_GRANT_RULE_DISABLED` at startup and each non-administrator grant logs `RBAC_PII_PERMISSION_DELEGATED`. Do not set `false` without Security |
| `nexus.identity.directory.lookup.max-attempts` / `window-seconds` | `30` / `60` | Per (tenant, actor) bucket on the rate-limit store, 429 `USER_DIR_001` |
| `nexus.identity.directory.ceiling.max-attempts` / `window-seconds` | `600` / `60` | Per (tenant, actor), across list, batch, get and lookup, 429 `USER_DIR_002` |

There are no environment-variable placeholders for the directory keys; they are plain properties in `application.yml`. The rate-limit store fails open when it is unavailable, so the ceiling and lookup limits also vanish then.

Existing keys this story relies on, unchanged: `nexus.rbac.denial-throttle.max-denials` (`NEXUS_RBAC_DENIAL_THROTTLE_MAX_DENIALS`, 5) and `window-seconds` (`NEXUS_RBAC_DENIAL_THROTTLE_WINDOW_SECONDS`, 60) for 429 `RBAC_011`; `nexus.rbac.permission-cache-ttl-seconds` (`NEXUS_RBAC_PERMISSION_CACHE_TTL_SECONDS`, 900); `nexus.jwt.access-token-ttl-seconds` (900); `nexus.identity.audit.retry-buffer.enabled` (true).

**Human `application-prod.yml` line still outstanding (from US-018, matters more now):** `nexus.rbac.throttle.require-shared-store: true`. Without it the 429 `RBAC_011` throttle can be per-instance on the in-memory store. The `@Disabled` test `ThrottleSharedStoreStartupAssertionTest` names the same line and is to be enabled once it is added (pending item P-10).

**Frontend:** `supportContact` in `src/environments/environment.ts` is `null`, so the Access Denied page shows no contact link. The value is a product decision (Q-N5, P-8). `parseSupportContact` accepts only `mailto:` and `https://` values.

**Dev only:** the dev profile seeds known-password personas (`DEV_SEED_ACTIVE`). The seeders are guarded by `dev & !break-glass & !prod`; never run a shared environment with the `dev` profile.

## 4. Database

| Order | Migration | Type | Content |
|---|---|---|---|
| 1 | `V11__rbac_user_directory_read_permission.sql` | data only (no DDL, no grant, no index) | Inserts permission `user:directory:read`, then the B7 footer: (a) every live (not soft-deleted) role in any tenant that held all eight pre-V11 permissions gains it, so it stays admin-defining; a role short of one gains nothing; (b) every system `TENANT_ADMIN` gains any permission it lacks. System `MEMBER` gets nothing |

- Applied at startup (`spring.flyway.enabled=true`); in the compose stack `flyway-migrate` applies it as root first. Append-only (ADR-0003): never edit V11 after it has been applied anywhere. Both footer statements are idempotent.
- The catalogue has **nine** rows from V11's commit. Every administrator decision reads the catalogue live, so old and new instances agree without a flag. A role an administrator creates after V11 must carry nine permissions to be admin-defining.
- **Pre-deploy exposure check (ids only; run before V11, when the catalogue has 8 rows):** footer (a) hands the PII permission to every custom role below, in any tenant, and it writes no audit row and bypasses the administrator-only grant rule.

```sql
SELECT BIN_TO_UUID(r.id) AS role_id, BIN_TO_UUID(r.tenant_id) AS tenant_id, r.is_system_role
FROM roles r
WHERE r.deleted_at IS NULL
  AND (SELECT COUNT(*) FROM role_permissions rp WHERE rp.role_id = r.id)
    = (SELECT COUNT(*) FROM permissions);
```

Review the non-system rows with the tenant owner. Keep `feature.nexus-us019-user-directory.enabled` off until done.

## 5. Order of operations

1. **Pre-deploy:** exposure check (section 4). The V11 header and design section 3.3 describe the rest.
2. **Deploy the backend.** V11 runs at startup of the first new instance, so the code is released with V11 (RC-63(d) ordering): old instances keep working because every administrator decision reads the catalogue live. Nothing uses the permission until the flag is on (step 4).
3. **Flush the permission cache.** Delete the keys `{keyPrefix}:rbac:permset:*` and `{keyPrefix}:rbac:roleset:*` (`SCAN` then `UNLINK`; the cache is never authoritative, the cost is one extra database read per next login or refresh). An administrator token minted before V11 lacks `user:directory:read`; the cached permission set lags for up to 900 s and the token for up to 900 s, about 30 minutes.
4. **RC-63(d): enable `feature.nexus-us019-user-directory.enabled` only after one of:**
   - (i) 1,800 s have passed since the flush;
   - (ii) a second flush 900 s after the first;
   - (iii) a freshly refreshed administrator token is verified to carry `user:directory:read` (decode the access token and check its `permissions` claim; log nothing from it).

   A single flush does not shorten the lag reliably: a mint that read the stale set before the flush can write it back after it (US-018 L-4). Enabling early gives an administrator 403 `RBAC_001` on B1 and the SPA sends them to `/access-denied`.
5. Check the zero-admin indicator (`rbacZeroActiveAdmins`) is green after V11 and after the flush.
6. **Frontend:** deployed with the build, no flag.
7. **Staging first:** persona e2e green against staging, dashboards from [monitoring.md](monitoring.md) live, then production per the C3 flag plan (pending P-7). Boolean flags cannot do a percentage rollout (Q-N8).
8. **24 hours watch after enabling in production:** no cross-tenant alert, no directory audit loss, B8 `error` outcome count 0.

## 6. E2E workflow

`.github/workflows/e2e-full-stack.yml` runs on `pull_request` (path-filtered to backend, frontend, `contracts/**`, the compose files and itself), read-only token, no secrets. It starts `backend` and `mailhog` from `docker-compose.yml` plus `docker-compose.e2e.yml` (dev profile, least-privilege `nexus_app` user, raised rate limits that exist only in the override), waits for readiness, then runs the 31 Playwright tests with `E2E_REQUIRE_BACKEND=1`. `assert-executed.mjs` fails on any skipped test or fewer than `E2E_MIN_TESTS` (31; raise it when specs are added). A PII scan (`scan-pii.mjs`) must pass before artifacts are uploaded (7-day retention). The workflow has **not yet run end to end** and is not yet a required check (P-9, P-11).
