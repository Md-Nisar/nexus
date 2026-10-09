# US-018 M2: Deployment Guide

**Scope:** Milestone 2 (A1 to A4 grant-subset core, plus security-review fixes M-1, L-1, L-2, L-5). See [09-technical.md](09-technical.md). Only items that exist on `feature/US-018` are listed.

## 1. Summary

Backend only, one data-only Flyway migration, no new configuration, no new feature flag, no frontend change. The behavioural change is that assigning and revoking roles now needs `user:role:assign` instead of `user:write`, and callers are bounded by what they themselves hold.

## 2. Feature flags

| Property | Default (`application.yml`, so also prod) | `dev` | `test` | Effect |
|---|---|---|---|---|
| `feature.nexus-us012-rbac-role-assignment.enabled` | `false` | `true` | `true` | Gates `UserRoleController`. When `false` the bean is absent and assign, list and revoke return 404 |
| `feature.nexus-us015-rbac-role-management.enabled` | `false` | `true` | `true` | Gates `RoleController` and `PermissionController` (the A3 attach check and the attach L-1 check live behind it) |

**No new flag is introduced by M2** (design §0 decision 29). Both parent flags are `false` in production by default, so M2 is dark in production until an operator turns a parent flag on. Do **not** enable either parent flag in a shared environment before section 5 steps 1 to 4 are done.

## 3. Configuration

No new property or environment variable. Existing properties that M2 denials interact with, unchanged:

| Property | Default | Notes |
|---|---|---|
| `nexus.rbac.denial-throttle.max-denials` (`NEXUS_RBAC_DENIAL_THROTTLE_MAX_DENIALS`) | `5` | A2, A4, revoke-subset and L-1 denials on assign and revoke now count towards this |
| `nexus.rbac.denial-throttle.window-seconds` (`NEXUS_RBAC_DENIAL_THROTTLE_WINDOW_SECONDS`) | `60` | |
| `nexus.rbac.permission-cache-ttl-seconds` (`NEXUS_RBAC_PERMISSION_CACHE_TTL_SECONDS`) | `900` | Governs the stale-cache window after V6 (section 5 step 5) |
| `nexus.security.rate-limit.store-type` | `memory` | Multi-replica deployments get a per-replica throttle (see US-016 runbook) |

Build-only change: `nexus-backend/.mvn/jvm.config` now has `-Dscan=false -Ddevelocity.scan.disabled=true` (Develocity build scans off). No runtime effect.

## 4. Database

| Order | Migration | Type | Content |
|---|---|---|---|
| 1 | `V6__rbac_user_role_assign_permission.sql` | data only (no DDL, no grant, no index) | Inserts permission `user:role:assign` (id `019f6839-1807-7000-8000-000000000008`); then the B7 footer: (a) every role, system or custom, in any tenant that already carried **every** pre-migration permission gains the new one (admin-defining status is preserved); (b) every system `TENANT_ADMIN` in any tenant gains every permission it lacks |

- Applied automatically at startup (`spring.flyway.enabled=true`). Append-only (ADR-0003): never edit V6 after it has been applied anywhere.
- Both footer statements are idempotent (`INSERT ... SELECT ... WHERE NOT EXISTS`). Re-running does nothing.
- Catalogue after V6: 8 permissions. `RbacSchemaMigrationIT` pins the counts.
- `nexus_app` grants are unchanged. The migration runs as the Flyway DDL user.
- Later migrations (V7 to V10) belong to M8 and M9 and are **not** part of this deployment.

## 5. Pre-deploy and post-deploy steps

Run in every environment where the US-012 flag was ever `true`. Output ids only, never names or emails.

1. **A1 detection (before deploy).** Roles that carry `user:write` and were used to assign roles will lose that ability on deploy. Count non-system roles carrying `user:write`, per tenant:
   ```sql
   SELECT HEX(r.tenant_id) AS tenant_id, COUNT(*) AS custom_roles_with_user_write
   FROM roles r
   JOIN role_permissions rp ON rp.role_id = r.id
   JOIN permissions p ON p.id = rp.permission_id AND p.name = 'user:write'
   WHERE r.is_system_role = FALSE
   GROUP BY r.tenant_id;
   ```
   If non-zero in production, escalate to the Product Manager and Security before deploy. After deploy, an administrator attaches `user:role:assign` to each role that was intended to assign roles (A3 allows it, because administrators hold it). There is deliberately **no automatic backfill**.
2. **Custom-admin exposure check (before).** List tenants whose administrators hold only custom roles, not `TENANT_ADMIN` (ids only). These rely on footer statement (a).
3. **Deploy** (V6 applies at startup).
4. **Custom-admin exposure check (after).** Confirm each tenant from step 2 still has at least one user holding a role that carries every permission in the catalogue (8). Statement (a) guarantees this unless a role was one permission short of the pre-migration catalogue. A tenant that ends at zero administrators is recovered only through the break-glass CLI (M5, not yet on this branch) where a system `TENANT_ADMIN` is seeded; until M5 ships it needs an approved direct DB change, see [runbook.md](runbook.md) section 5.
5. **Flush the permission cache.** The cache is fingerprinted on role names only, so existing `TENANT_ADMIN` holders keep a cached permission set that lacks `user:role:assign` for up to 900 s after V6. Delete the keys `{keyPrefix}:rbac:permset:*` in Redis (`SCAN` then `DEL`; the prefix is defined in `RedisPermissionCacheAdapter`). Also, JWTs minted before the deploy carry the old permission list until they expire, so an administrator may need to log in again to get `user:role:assign` into the token (access-token lifetime applies).
6. **Confirm the WARN retention** for the markers listed in [monitoring.md](monitoring.md) section 3 is at least 1 year (design §2.3 merge-checklist item for M2).
7. **Smoke.** In a non-production environment with the flags on: an administrator can assign a role; a user holding only `user:write` gets 403 `RBAC_001` with `requiredPermission` `user:role:assign`.

## 6. Rolling-deploy overlap

During a rolling deploy old instances gate on `user:write` and new ones on `user:role:assign` for a few minutes. Accepted because the parent flag is off in production. If the flag is on in an environment, expect transient 403s for assigners during the overlap.

## 7. Service-level callers

`RoleAssignmentService` and `RoleManagementService` now re-check, against the database, that the acting user still holds the endpoint permission (L-1) and the permissions being granted (A2, A3). Anything that calls them with an actor who holds the permission only in a JWT, or only in a mock, is denied. In this repository the only callers are the REST controllers. Items to remember for later milestones and tooling:

- **M5 break-glass CLI** is designed to use a separate `BootstrapAdminService` that never calls `assign()`, so it is not subject to A4 or A2; this is a design statement, it is not on this branch.
- **M7 and any load or seed script** that creates callers must give them real, DB-held `user:role:assign` (and `role:write` for attach) through an assigned role, not only a token claim. Fixtures were updated accordingly in the integration tests (08-test-audit.md).
- The dev seed (`DevDataInitializer`) assigns through `UserRoleAssignmentPort`, not through the service, so it is not affected.

## 8. Frontend

None.

## 9. Rollback

See [rollback.md](rollback.md).

---

## 10. M7: permission token freshness (A9, A10)

**Feature flag.** None. M7 is always on once deployed; the parent RBAC flags do not gate it.

**Migrations.** None for M7 (Redis keys only; the holder query uses existing tables).

**Merge unit.** M7 merges as **one** PR containing T-009 to T-014. T-009 alone would deploy token freshness without the outage policy, the replay queue and the Redis-auth assertion.

**Required before production traffic**
- [ ] The `prod` profile is active (A-3). `application-prod.yml` sets `nexus.rbac.redis.require-auth: true`, and without `prod` the property defaults to `false` (`NEXUS_RBAC_REDIS_REQUIRE_AUTH` overrides it).
- [ ] Redis authenticates (`spring.data.redis.password`, or credentials in the URL), is configured with `maxmemory-policy noeviction` (ADR-0016) and, where used, TLS.
- [ ] SRE and PM have accepted the availability consequence of RES-30.
- [ ] `/actuator/prometheus` scrapes use a token holding `TENANT_ADMIN`, or are moved to a scrape network (they were open to every authenticated user before).
- [ ] If the deployment relies on per-client IP limits behind a proxy: the default is `server.forward-headers-strategy: none`, so limits are platform-wide (DF-1). Changing it needs `native` and a pinned `server.tomcat.remoteip.internal-proxies`.
- [ ] The k6 gates were run once for the deployment shape: `epoch-check-latency.js` (baseline, then gate), `detach-refresh-storm.js`, `refresh-junk-flood.js`. They write accounts that cannot be deleted: run them against a disposable stack (they refuse non-local targets unless `ALLOW_WRITE_SCENARIO=true`).

**New configuration** (all under `nexus.rbac.epoch`, defaults in `application.yml`; env var form `NEXUS_RBAC_EPOCH_...`)

| Property | Default | Notes |
|---|---|---|
| `command-timeout` | `50ms` | One epoch read, on every authenticated request |
| `bump-timeout` | `500ms` | One bump script call |
| `key-ttl-seconds` | `960` | Must be at least the larger of the token TTL and the permission-cache TTL plus 60 s, or startup fails |
| `fail-open-window` | `PT15M` | Degraded-open until this, then 503 `AUTH_005`; raise only by env var and restart |
| `entry-failure-threshold` / `entry-failure-window` / `recovery-sustain` | `3` / `PT10S` / `PT60S` | State machine |
| `replay-capacity-users` / `replay-capacity-roles` | `100000` / `1000` | Per instance; one tenant may use `last-seen-tenant-percent` of each |
| `last-seen-tenant-percent` | `10` | Share of the last-seen map and of both replay queues per tenant |

**Rolling deploy.** M6 already accepts schema versions 2 and 3, so M6 and M7 instances can share a load balancer: the M7 instance mints v3, and an M6 instance accepts it. Watch `token_rejected{reason=schema_version}` (expected 0) and `epoch.check{outcome=stale}` for an hour. M7b later contracts the accepted set to {3}.

**Post-deploy checks.** `epoch.check{outcome=skipped_error}` stays near 0, `epoch.degraded{state}` is `healthy`, `bump_failed` is 0, `store_regressed` is 0, and a revoke makes the revoked user's next request a 401 (smoke test).

