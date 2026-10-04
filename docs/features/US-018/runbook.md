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
