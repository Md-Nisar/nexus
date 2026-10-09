# US-018 M2: Monitoring

**Scope:** Milestone 2 (A1 to A4, M-1, L-1, L-2, L-5). **Audience:** on-call engineer. **Companion:** [runbook.md](runbook.md), [09-technical.md](09-technical.md).
Metric names, tags, event names and log keys below were taken from the source on `feature/US-018` (`GlobalExceptionHandler`, `RoleAssignmentService`, `RoleManagementService`, `RbacAuthEventAdapter`, `DenialReason`). **Every threshold and severity in this document is a suggestion, not a measured or agreed value**, because M2 has not run in a shared environment. Tune after the first staging soak.
No PII: every field is a UUID, an integer or a bounded enum.

## 1. Metrics

M2 adds **no new metric name and no new tag**. It widens the population of an existing counter.

| Metric | Type | Tags | Emitted by | M2 change |
|---|---|---|---|---|
| `nexus.rbac.permission_denied` (Prometheus: `nexus_rbac_permission_denied_total`) | Counter | `permission` (the endpoint permission), `reason` (`DenialReason`) | `GlobalExceptionHandler.handleInsufficientPermission`, the single increment site | New `reason` values `GRANT_EXCEEDS_CALLER` and `SELF_ASSIGNMENT`; `PERMISSION_ABSENT` now also fires from the L-1 live check. `permission` is `user:role:assign` for assign and revoke, `role:write` for attach. Bounded: at most 2 permissions times 6 reasons |
| `nexus.rbac.denial_throttled{operation}` | Counter | `operation` in `{assign, revoke}` | `RoleAssignmentService.requireNotThrottled` | Unchanged. New denial kinds feed the same per-`(tenant, actor)` throttle, so this rises sooner for a probing caller |
| `nexus.rbac.privileged_revoke_lock_hold{operation,outcome}` | Timer | `operation`, `outcome` | `RoleAssignmentService` | Unchanged. Denials by A4, A2, revoke-subset or L-1 on a privileged target happen inside the lock region and record `outcome=denied` |
| `nexus.rbac.audit_write_failed{operation}` | Counter | `operation` | `RbacAuthEventAdapter` | Unchanged. `operation="deny"` is the denial-row write |

Reason matrix for `nexus.rbac.permission_denied` (M2 reasons):

| `reason` | `permission` | Meaning |
|---|---|---|
| `GRANT_EXCEEDS_CALLER` | `user:role:assign` | A2 on assign, or revoke-subset on revoke: the role carries a permission the caller does not hold |
| `GRANT_EXCEEDS_CALLER` | `role:write` | A3: the permission being attached is not held by the caller |
| `SELF_ASSIGNMENT` | `user:role:assign` | A4: a non-administrator assigned a role to themselves |
| `PERMISSION_ABSENT` | `user:role:assign` or `role:write` | The endpoint permission is in the JWT but no longer in the caller's live DB holdings (L-1), or absent from the JWT (the pre-existing `@RequiresPermission` denial) |
| `CROSS_TENANT_TARGET` | `user:role:assign` | Pre-existing; also the defensive empty-M14 branch |
| `NOT_TENANT_ADMIN` | `user:role:assign` | Pre-existing legacy privileged-role gate and a throttled actor |

## 2. Audit trail

- **`auth_events` row, `event_type = 'ROLE_ASSIGNMENT_DENIED'`**, `outcome = 'DENIED'`, written by `RbacAuthEventAdapter.recordRoleAssignmentDenied` in its own transaction (`REQUIRES_NEW`; best effort, never throws). One row per denied assign or revoke request, carrying the **first** reason. `user_id` is the target user, `tenant_id` the actor's tenant. `metadata` JSON keys (omitted when null): `traceId`, `roleId`, `roleName`, `reason`, `operation` (`assign` or `revoke`), `missingCount` (A2 and revoke-subset only, a count, never permission ids), `attemptedBy` (the actor's user id). Role name is null on cross-tenant denials.
- **No audit row** for A3 denials and for L-1 on attach (design Decision 7, matching the shipped AC11 gate). The trail for those is the WARN log and the counter.
- Successful assign and revoke still write `ROLE_ASSIGNED` and `ROLE_REVOKED` (priority lane). M2 does not change that; they become atomic with the mutation in M4.
- `ROLE_ASSIGNMENT_DENIED` is deliberately **not** in the priority retry-buffer lane (`AuthEventType`), so a denial flood cannot displace `ROLE_ASSIGNED` or `ROLE_REVOKED`.

## 3. Log markers (structured, field `event`)

All are WARN and carry ids only. The design requires the denial markers named in section 2.3 of 03-design.md to be retained at least as long as `auth_events` and a minimum of 1 year.

| `event` | Raised by | Fields | Meaning |
|---|---|---|---|
| `RBAC_ENDPOINT_PERMISSION_NOT_HELD` | L-1, on assign, revoke and attach | `tenantId`, `actorUserId`, `roleId`, plus `targetUserId` and `operation` (assign, revoke) or `permissionId` (attach) | Caller's token passed `@RequiresPermission` but the live DB holdings lack the endpoint permission: a stale token after a role was revoked, or a data inconsistency |
| `RBAC_GRANT_EXCEEDS_CALLER` | A2 and revoke-subset | `tenantId`, `actorUserId`, `targetUserId`, `roleId`, `operation`, `missingCount` | Caller tried to hand out or revoke a role carrying permissions they do not hold |
| `RBAC_SELF_ASSIGNMENT_DENIED` | A4 | `tenantId`, `actorUserId`, `roleId` | Non-administrator tried to assign a role to themselves (the RES-1(b) first step) |
| `RBAC_ATTACH_EXCEEDS_CALLER` | A3 | `tenantId`, `actorUserId`, `roleId`, `permissionId` | Attach of a permission the caller does not hold |
| `RBAC_GRANT_CHECK_ROLE_NOT_IN_TENANT` | A2, defensive | `tenantId`, `actorUserId`, `roleId`, `operation` | **Unreachable today**; if seen, an invariant broke (role tenant mismatch). Treat as an incident |
| `RBAC_DENIAL_THROTTLE_ENGAGED` | Pre-existing | `maxDenials`, `windowSeconds`, ... | The actor crossed the denial throttle bound |
| `RBAC_001` (handler log) | `GlobalExceptionHandler` | `reason`, `requiredPermission`, `userId`, `tenantId` | One per 403 of this family |

## 4. Suggested alerts (all thresholds are suggestions)

| Alert | Suggested expression | Suggested severity | Why |
|---|---|---|---|
| `nexus_rbac_self_assignment_denied` | `increase(nexus_rbac_permission_denied_total{reason="SELF_ASSIGNMENT"}[15m]) > 0` | ticket | Any occurrence is the first step of the RES-1(b) pattern or a confused administrator-in-training. Rare by nature |
| `nexus_rbac_grant_exceeds_caller_burst` | `increase(nexus_rbac_permission_denied_total{reason="GRANT_EXCEEDS_CALLER"}[15m]) > 10` | ticket | Probing for what the caller may grant, or a delegated assigner using the wrong role. Tune the number after a week of data |
| `nexus_rbac_endpoint_permission_not_held` | `increase(nexus_rbac_permission_denied_total{reason="PERMISSION_ABSENT",permission=~"user:role:assign|role:write"}[15m]) > 0` | ticket | Stale-token use after a role was revoked, or a missed V6 cache flush (section 5). A burst right after deploy is expected; see the runbook |
| `nexus_rbac_denial_throttled_burst` | `increase(nexus_rbac_denial_throttled_total[5m]) > 0` | ticket | An actor hit the throttle. Page-level handling of throttle engagement is defined in US-016 monitoring and is unchanged |
| `nexus_rbac_audit_write_failed_deny` | `increase(nexus_rbac_audit_write_failed_total{operation="deny"}[5m]) > 0` | ticket | Denial rows are being lost, so the forensic trail for M2 denials is incomplete |
| `nexus_rbac_grant_check_role_not_in_tenant` | log-based, any occurrence of `RBAC_GRANT_CHECK_ROLE_NOT_IN_TENANT` | page | Unreachable by construction; a hit means a tenant-isolation invariant broke |

The existing page alerts from US-016/US-017 (`nexus_rbac_gate_bypass_canary`, `nexus_rbac_privileged_role_change_blocked_dangerous`, the zero-active-admins health signal) are unchanged in M2 and remain the primary escalation signals; their canary mechanism is replaced in M3.

## 5. Post-deploy expectations and dashboard rows

- **Spike right after V6.** Administrators whose cached permission set or JWT lacks `user:role:assign` get 403 until the cache is flushed or they re-login (deployment.md section 5 step 5). Expect `PERMISSION_ABSENT` with `permission="user:role:assign"` to be briefly non-zero; it should fall to near zero within the access-token lifetime.
- **Dashboard row suggestion ("RBAC grant-subset"):** a stacked rate of `nexus_rbac_permission_denied_total` split by `reason` for the two permissions; a single-stat of `increase(...{reason="SELF_ASSIGNMENT"}[24h])`; the `nexus_rbac_denial_throttled_total` rate.
- **Cardinality:** no tenant tag anywhere (design §2.3). Attribute to a tenant through the log fields, not the metric.

## 6. Forensic query (ids only)

Denials for one tenant in the last day, newest first:

```sql
SELECT HEX(id) AS event_id, created_at,
       JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason'))      AS reason,
       JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.operation'))   AS operation,
       JSON_EXTRACT(metadata, '$.missingCount')              AS missing_count,
       JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.attemptedBy')) AS actor_user_id,
       HEX(user_id) AS target_user_id
FROM auth_events
WHERE event_type = 'ROLE_ASSIGNMENT_DENIED'
  AND tenant_id = UNHEX(REPLACE(?, '-', ''))
  AND created_at >= NOW() - INTERVAL 1 DAY
ORDER BY created_at DESC;
```

## 6. Token freshness (US-018 M7), alerts added by the part 2 security review

All suggestions; the full table is design §9.9, the response steps are in the runbook (sections 7 and 8).

| Alert | Suggested expression | Suggested severity | Why |
|---|---|---|---|
| `nexus_rbac_epoch_bump_failed` | `increase(nexus_rbac_epoch_bump_failed_total[5m]) > 0` (reasons `redis`, `overflow`, `holder_read`, `role_overflow`) | page | A revocation was not applied on the request thread. `holder_read` and `role_overflow` concern a detach whose holders could not be read; the role is replayed by the tick unless `role_overflow` or a restart intervened (runbook section 8) |
| `nexus_rbac_epoch_role_replay_stuck` | `nexus_rbac_epoch_role_replay_queue_roles > 0` for 5 min | ticket | A role's holder read keeps failing; revocations of its holders are pending |
| `nexus_rbac_epoch_last_seen_dropped` | `increase(nexus_rbac_epoch_last_seen_dropped_total{reason=~"tenant_cap\|capacity"}[15m]) > 0` | ticket | The last-seen defence is shedding users (one busy tenant or a full map) |
| `nexus_rbac_epoch_last_seen_bump_dropped` | `increase(nexus_rbac_epoch_last_seen_dropped_total{reason="bump_dropped"}[15m]) > 0` | page | An own bump was not remembered locally (tenant ceiling or global bound); that tenant fails closed while Redis reads fail |
| `nexus_rbac_epoch_unparseable` | `increase(nexus_rbac_epoch_check_total{outcome="unparseable"}[15m]) > 0` | ticket | Corrupt or foreign epoch keys in Redis (RES-32); the WARN is limited to one per tenant per minute, so the counter is the full signal |
| `nexus_rbac_epoch_skipped_error_rate_panel` | per-instance request rate next to `outcome="skipped_error"` | dashboard panel | Review 07 M-1 (b): shows whether reads are being pushed past 50 ms |
