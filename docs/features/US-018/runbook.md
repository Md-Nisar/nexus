# US-018 M2: Runbook

**Scope:** Milestone 2 (A1 to A4, M-1, L-1, L-2, L-5). **Audience:** on-call engineer with no prior context. Companions: [monitoring.md](monitoring.md), [rollback.md](rollback.md), [09-technical.md](09-technical.md), and the US-016 and US-017 runbooks for the legacy gate, the denial throttle and the zero-administrator procedure.
Never paste emails, names or tokens into tickets: use user, role, permission and tenant UUIDs only. SQL below uses `UNHEX(REPLACE(?, '-', ''))` for UUID parameters.

## 1. A legitimate administrator gets 403 `RBAC_001`

**Symptom.** An administrator or delegated assigner gets 403 with `requiredPermission` `user:role:assign` (assign, revoke) or `role:write` (attach). The 403 body never says why; the reason is in the log and the audit row.

**Diagnose in this order.**

1. Find the request in the logs by trace id and read the `reason` on the `RBAC_001` line, or query the denial row (monitoring.md section 6). Match the reason:

   | `reason` | Marker | Most likely cause | Action |
   |---|---|---|---|
   | `PERMISSION_ABSENT` | `RBAC_ENDPOINT_PERMISSION_NOT_HELD` | Right after the V6 deploy: stale permission cache or old JWT without `user:role:assign`. Otherwise the caller's role was revoked and the token is stale (working as intended) | Step 2 |
   | `GRANT_EXCEEDS_CALLER` | `RBAC_GRANT_EXCEEDS_CALLER` (assign, revoke) or `RBAC_ATTACH_EXCEEDS_CALLER` (attach) | The role being assigned, revoked or attached carries a permission the caller does not hold. This is A2, A3 or revoke-subset working as designed | Step 3 |
   | `SELF_ASSIGNMENT` | `RBAC_SELF_ASSIGNMENT_DENIED` | A non-administrator targeted themselves (A4) | Step 4 |
   | `NOT_TENANT_ADMIN` | `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` or `RBAC_DENIAL_THROTTLE_ENGAGED` | Legacy gate for privileged roles, or the actor is throttled | Section 3 |
   | `CROSS_TENANT_TARGET` | n/a | Target user or role belongs to another tenant | Check ids; do not widen anything |

2. **`PERMISSION_ABSENT`.** Does the caller hold `user:role:assign` (or `role:write`) in the database right now?
   ```sql
   SELECT DISTINCT p.name
   FROM user_roles ur
   JOIN roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id
   JOIN role_permissions rp ON rp.role_id = r.id
   JOIN permissions p ON p.id = rp.permission_id
   WHERE ur.user_id = UNHEX(REPLACE(?, '-', '')) AND ur.tenant_id = UNHEX(REPLACE(?, '-', ''))
     AND ur.revoked_at IS NULL AND p.name IN ('user:role:assign', 'role:write');
   ```
   - **Not returned:** the caller does not hold it. If they should, an administrator attaches `user:role:assign` to a role they hold (or assigns a role that has it). A delegated role created before V6 that carried `user:write` does not get it automatically (no backfill, by design).
   - **Returned** but still 403: the JWT and cache were issued before the change. Flush `{keyPrefix}:rbac:permset:*` if the V6 flush was missed, and ask the user to log in again. If the log shows `RBAC_ENDPOINT_PERMISSION_NOT_HELD`, the token had the permission but the database does not (stale token). If that marker is absent, the token itself lacks the permission (old token or stale cache). The live check passes as soon as the database holds the permission.
3. **`GRANT_EXCEEDS_CALLER`.** Compare the role's permissions with the caller's. Compute the missing set from ids:
   ```sql
   SELECT p.name
   FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
   WHERE rp.role_id = UNHEX(REPLACE(?, '-', ''))
     AND rp.permission_id NOT IN (
       SELECT rp2.permission_id
       FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id
       JOIN role_permissions rp2 ON rp2.role_id = r.id
       WHERE ur.user_id = UNHEX(REPLACE(?, '-', '')) AND ur.tenant_id = UNHEX(REPLACE(?, '-', ''))
         AND ur.revoked_at IS NULL);
   ```
   The audit row's `missingCount` should equal the number of rows returned. Remedy: an actor who holds everything in the role performs the action (an administrator, for example), or the caller is given the missing permissions through a legitimate approval. Do not weaken the check. Note that revoke is also bounded: a delegate cannot revoke a role carrying permissions they lack.
4. **`SELF_ASSIGNMENT`.** The caller is not an administrator, meaning none of their roles carries every permission in the catalogue on its own. Holding the whole catalogue across two roles does not count. Ask an administrator to assign the role instead. If the caller really is an administrator, verify with the query in section 5 that one of their roles holds all 8 permissions (catalogue size after V6; a new permission added later without the B7 footer demotes custom administrator roles).
5. If none of the above explains the 403 and the flags are on, check the audit row for `roleName` null and reason `CROSS_TENANT_TARGET`, and check for `RBAC_GRANT_CHECK_ROLE_NOT_IN_TENANT` (unreachable by design; escalate to Security if present).

**Escalate to Security** if `SELF_ASSIGNMENT` or `GRANT_EXCEEDS_CALLER` repeats for one actor, or the actor's account was created recently (the RES-26 two-account pattern).

## 2. Last-admin 409 (`RBAC_002`)

**Symptom.** `DELETE /api/v1/users/{userId}/roles/{roleId}` returns 409 `RBAC_002` "Cannot revoke the last active TENANT_ADMIN assignment in this tenant".

**What it means.** The revocation would leave the tenant with no distinct active holder of a role able to administer it. The lockout is intact and unchanged by M2; in M2 it still uses the US-017 admin-equivalent definition (re-scoped to admin-defining roles in M3). Authorization is evaluated first, so only a caller allowed to revoke that role ever sees 409.

**Do.**
1. Confirm it is genuine: count active holders of the role (and of other roles that carry every permission) in the tenant.
2. Assign the role to a second, intended administrator first (the caller must be an administrator or hold every permission of that role, A2), then repeat the revoke.
3. Do **not** bypass it with SQL unless a zero-administrator incident is already declared; follow the US-017 runbook for that procedure.

## 3. Throttled actor

**Symptom.** A caller gets 403 on every assign or revoke for up to a minute, even for actions that should be allowed. The audit rows stop appearing for the throttled requests. `nexus_rbac_denial_throttled_total` increases; WARN `RBAC_DENIAL_THROTTLE_ENGAGED` was logged once at the transition.

**Cause.** The actor produced `nexus.rbac.denial-throttle.max-denials` (default 5) gate denials within `window-seconds` (default 60). In M2, A2, A4, revoke-subset and L-1 denials all count. While throttled, requests are rejected before any lock or read, with reason `NOT_TENANT_ADMIN` (a pre-existing label; tidied in M8).

**Diagnose.**
1. Read the preceding durable `ROLE_ASSIGNMENT_DENIED` rows for that actor (monitoring.md section 6) to see which reasons burned the budget. A legitimate operator hitting `GRANT_EXCEEDS_CALLER` five times means they are using the wrong role or lack permissions: fix that, do not raise the limit.
2. Deployments with `nexus.security.rate-limit.store-type: memory` have one counter per replica, so a user may be throttled on one replica and not another (US-016 runbook).
3. Wait for the window to pass. Raising `NEXUS_RBAC_DENIAL_THROTTLE_MAX_DENIALS` is a config-and-restart change and weakens a probe-cost bound; only do it with Security agreement.

## 4. Service-level callers need DB-held permissions

After M2, `RoleAssignmentService` and `RoleManagementService` check the database, not only the token. A caller who has the permission only in a JWT, or whose role was removed after the token was issued, is denied with `PERMISSION_ABSENT`. For operations and tooling:

- **Any script, job or test fixture that creates an actor** must give that actor a real role carrying `user:role:assign` (assign and revoke) or `role:write` (attach) in the `user_roles` and `role_permissions` tables. A claim in a hand-minted token is not enough. This matters for the M7 work (epoch freshness, load and k6 fixtures) and for integration seeds.
- **Break-glass CLI (M5, designed, not on this branch).** The design routes it through `BootstrapAdminService`, which never calls `assign()`, so A2 and A4 do not apply to it. If a future change makes it call `assign()`, the target-is-self and A2 checks would deny it. Check the M5 documents when that milestone lands.
- **Dev seed.** `DevDataInitializer` assigns through `UserRoleAssignmentPort`, not through the services; unaffected.
- A revoked delegate keeps a working token for up to the access-token lifetime for every other endpoint; M2 closes that window only for assign, revoke and attach. M7 is the systemic fix.

## 5. Useful queries

Is a user an administrator (a role carrying every permission)? Returns role ids; ids only.

```sql
SELECT HEX(ur.role_id) AS role_id, COUNT(DISTINCT rp.permission_id) AS permission_count
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id
JOIN role_permissions rp ON rp.role_id = r.id
WHERE ur.user_id = UNHEX(REPLACE(?, '-', '')) AND ur.tenant_id = UNHEX(REPLACE(?, '-', ''))
  AND ur.revoked_at IS NULL
GROUP BY ur.role_id
HAVING COUNT(DISTINCT rp.permission_id) = (SELECT COUNT(*) FROM permissions);
```

Zero-administrator tenants after a deploy: use the `rbacZeroActiveAdmins` health indicator and the US-017 runbook. Until M5 (break-glass) ships, restoring an administrator in a tenant with none is an approved direct database change by the DBA with two-person sign-off.

## 6. Kill switch

Set `feature.nexus-us012-rbac-role-assignment.enabled=false` (assign, list, revoke return 404) or `feature.nexus-us015-rbac-role-management.enabled=false` (role and attach endpoints), then restart. This is an availability lever, not a way back to the old rules; see [rollback.md](rollback.md).

## 7. Redis authentication at startup (M7, T-014)

- [ ] Check that `nexus.rbac.redis.require-auth=true` is resolved in production (the `prod` profile is active and `application-prod.yml` sets it; e.g. `/actuator/env/nexus.rbac.redis.require-auth` where exposed, or the effective config of the deployment). With it false the startup check is inert.

If startup fails with `nexus.rbac.redis.require-auth=true but the "<factory>" Redis connection has no password`, set `spring.data.redis.password`, or put the password in the `spring.data.redis.url` userinfo (with a URL set, Boot ignores the password property). A `Sentinel password` message means `spring.data.redis.sentinel.password` is missing.

## 8. Permission removed outside the API (Flyway or SQL) (M7, T-010)

Revoke and detach make holders' tokens stale and drop their cached permission sets automatically. A permission or role assignment removed by a migration or a direct SQL change does neither: holders keep the permission in their access token (up to 900 s) and in their cached set (up to `NEXUS_RBAC_PERMISSION_CACHE_TTL_SECONDS`, 900 s by default). After such a change, in this order:

- [ ] **Bump the epoch of every affected holder.** List the user ids (for a permission removed from a role, the active holders of that role):
   ```sql
   SELECT BIN_TO_UUID(ur.tenant_id) AS tenant_id, BIN_TO_UUID(ur.user_id) AS user_id
   FROM user_roles ur
   WHERE ur.role_id = UUID_TO_BIN(?) AND ur.revoked_at IS NULL;
   ```
   `BIN_TO_UUID` prints the dashed lower-case form that the Redis keys use; `HEX` would print upper-case ids without dashes, and the script below would then bump keys that nothing reads. Run the same monotonic bump the application runs, for up to 500 keys `{keyPrefix}:rbac:epoch:{tenantId}:{userId}` per call (the last argument is `nexus.rbac.epoch.key-ttl-seconds`, 960 by default):
   ```
   redis-cli EVAL "local t=redis.call('TIME') local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000) local max=9007199254740990 for _,k in ipairs(KEYS) do local r=redis.call('GET',k) local o=0 if r and #r<=16 and string.find(r,'^%d+$') and tonumber(r)<=max then o=tonumber(r) end redis.call('SET',k,string.format('%.0f',math.min(math.max(o+1,now),max)),'EX',ARGV[1]) end return #KEYS" <numkeys> <epoch keys...> 960
   ```
   Each holder's next request then gets 401 `AUTH_003` and the client refreshes. The script applies the application's valid-epoch rule (1 to 16 digits, at most 2^53 - 2; anything else counts as 0, so a corrupt key is replaced by the current time). It does not delete the cached permission sets, hence the flush below.
- [ ] **Flush the permission cache:** `SCAN` with `MATCH {keyPrefix}:rbac:permset:*` and `MATCH {keyPrefix}:rbac:roleset:*`, and `UNLINK` the keys found. The cache is never authoritative; the only cost is one extra database read per next login or refresh.

Not needed after the T-010 deploy itself: cache keys without an epoch suffix are no longer read and expire within the cache TTL.

**Page `nexus.rbac.epoch.bump_failed{operation="detach", reason="holder_read"}`.** A detach committed, but the instance could not read the role's holders after commit, even on a retry (usually pool pressure or a database timeout). The ERROR `RBAC_HOLDER_READ_FAILED` names the tenant and role. Since the M7 part 2 review the instance **queues the role and retries on its 1 s tick**: watch `nexus.rbac.epoch.role_replay_queue_roles` fall to 0 and `nexus.rbac.epoch.role_replayed` rise, and the INFO `RBAC_HOLDER_READ_REPLAYED` for that role. Only act by hand if the queue does not drain within a minute or two (the database is still failing: `bump_failed{operation="role_replay", reason="holder_read"}` keeps rising, with one ERROR `RBAC_HOLDER_READ_FAILED operation=role_replay` per second), or the instance restarted (the queue is in memory), or `bump_failed{reason="role_overflow"}` fired (the role was refused: queue full): then apply the two checklist items above for that role's active holders, within the token TTL (900 s). A role is given up after `key-ttl-seconds` (960 s) without success.

**Ticket `nexus.rbac.epoch.last_seen_dropped{reason="tenant_cap"|"capacity"}`.** The per-instance last-seen map (the defence that keeps a revoked token stale while Redis reads fail) shed read-derived users: one tenant reached its share (`nexus.rbac.epoch.last-seen-tenant-percent`, default 10 of 100,000) or the instance reached 100,000. Only users who are revoked during a Redis read failure and not already in the map lose that defence, so it matters if `epoch.check{outcome=skipped_error}` is also rising. Check the tenant's traffic or a very large detach; raise the percentage only with the heap in mind. **Page `reason="bump_dropped"`:** an own bump could not be remembered locally (a tenant over its own-bump ceiling of 4 times its share, or all tenants over the global 200,000). The store has the bump. The instance logs ERROR `RBAC_LAST_SEEN_BUMP_DROPPED {tenantId}` and fails that tenant **closed** for `key-ttl-seconds`: if Redis reads fail or the instance is DegradedOpen meanwhile, all of that tenant's requests get 401 instead of being skipped (a tenant-wide outage, by design, the alternative being an unknown revocation). Nothing to do with a healthy store; with a degraded one, restore Redis first.

**Ticket on any increase of `nexus.rbac.epoch.check{outcome="unparseable"}`.** A stored epoch is not a number or is out of range (`0 .. 2^53 - 2`): Redis write access, or a foreign client writing under the same `nexus.redis.key-prefix` (RES-32). That user's tokens are stale and the next bump (any detach or revoke of that user, or the script of section 8) replaces the value. The WARN `RBAC_EPOCH_UNPARSEABLE` is logged once per tenant per minute with a `suppressed` count and never names the user; find the key with `SCAN MATCH {keyPrefix}:rbac:epoch:{tenantId}:*` and check who has write access.
