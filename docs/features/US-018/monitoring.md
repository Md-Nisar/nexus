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

The existing page alerts from US-016/US-017 (`nexus_rbac_gate_bypass_canary`, `nexus_rbac_privileged_role_change_blocked_dangerous`, the zero-active-admins health signal) were unchanged in M2. M3 replaces them; see section 4a.

## 4a. M3 alert changes (A5: superseded machinery retired)

Suggestions, as above. The name-based gate, the M12 canary and the US-017 counters are gone, so alerts built on them must be re-pointed. No meter carries a tenant tag.

| Alert | Suggested expression | Suggested severity | Replaces / why |
|---|---|---|---|
| `nexus_rbac_gate_bypass_canary` (re-pointed) | `increase(nexus_rbac_self_assign_admin_disagreement_total[5m]) > 0`; log: ERROR `RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT` (`tenantId`, `actorUserId`, `roleId`) | page | An independent per-role statement (M16, non-locking, run before the INSERT of a self-target assign) says the caller is an administrator while A4 said not. A4 and M16 disagree: the "administrator" definition has a bug or the data changed between reads. Never consulted for authorization |
| `self_role_assignment_total` ticket | dropped | n/a | The meter no longer exists. Self-assignment by a non-administrator is `permission_denied{reason="SELF_ASSIGNMENT"}` (section 4) |
| `nexus_rbac_privileged_role_change_blocked_dangerous` | replaced by `increase(nexus_rbac_permission_denied_total{reason="NOT_TENANT_ADMIN"}[15m]) > 0` | ticket | `privileged_role_change_blocked` and `_allowed` no longer exist. `NOT_TENANT_ADMIN` now means only: the caller is not an administrator (one role carrying the whole catalogue) on a revoke of an admin-defining role. Admin-defining assigns by a non-administrator are `GRANT_EXCEEDS_CALLER` |
| `nexus_rbac_attach_escalates_non_admin_assigned` | `increase(nexus_rbac_attach_escalates_non_admin_assigned_total{holders!="0"}[15m]) > 0` | ticket; page when `page="true"` | Every attach, after commit: holders of the role gain the permission. Ticket when some holder was assigned by a non-administrator; `page="true"` when the permission is `user:role:assign` or `role:write` or the attach makes the role admin-defining (RES-26 detective control). Log: WARN `RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS` (`tenantId`, `roleId`, `permissionId`, `holderCount`, `nonAdminAssignedCount`). `holders="unknown"` means the after-commit read failed: treat as non-zero |
| `nexus_rbac_role_became_admin_defining` | `increase(nexus_rbac_role_became_admin_defining_total{holders!="0"}[15m]) > 0` (include `holders="unknown"`) | page | An attach completed the catalogue on a role that has active holders: those holders became administrators. Log: WARN `RBAC_ROLE_BECAME_ADMIN_DEFINING`. With zero holders it is informational |
| `nexus_rbac_attach_provenance_refused` | `increase(nexus_rbac_permission_denied_total{permission="role:write",reason="ATTACH_PROVENANCE"}[15m]) > 0`; log: WARN `RBAC_ATTACH_PROVENANCE_REFUSED` (`tenantId`, `actorUserId`, `roleId`, `permissionId`, `nonAdminAssignedCount`) | ticket | The attach was refused with 409 `RBAC_010`: it would make a role admin-defining while a holder was assigned by a non-administrator. Preventive only for that payoff |
| `nexus_rbac_admin_role_assigned` | `increase(nexus_rbac_admin_role_assigned_total[1h]) > 0` split by `selfTarget` | ticket, never page | An admin-defining role was assigned. `selfTarget="true"` is an administrator assigning it to themselves |
| `nexus_rbac_role_subset_denied` | log: WARN `RBAC_ROLE_SUBSET_DENIED` (`tenantId`, `actorUserId`, `roleId`, `operation`) with `permission_denied{permission="role:write",reason="GRANT_EXCEEDS_CALLER"}` | ticket on a burst | A detach by a caller who does not hold every permission of the role, or who would be detaching from their own only administrator role. No audit row |
| `RBAC_ADMINISTRATOR_REQUIRED_DENIED` | log: WARN, same fields as the other denials | ticket on a burst | A revoke of an admin-defining role by a non-administrator (including a union-holder) |
| `nexus_rbac_last_admin_lockout_blocked` | `increase(nexus_rbac_last_admin_lockout_blocked_total[15m]) > 0` | ticket | **Lost its tag in M3.** Any dashboard or alert that filtered on the old tag must drop the filter. Log: WARN `RBAC_LAST_ADMIN_REVOCATION_BLOCKED` |

Removed meters (zero references; an alert on them goes silent, it does not fail): `nexus.rbac.self_role_assignment`, `nexus.rbac.privileged_role_change_blocked`, `nexus.rbac.privileged_role_change_allowed`, `nexus.rbac.admin_minted_by_non_named_admin`. The zero-active-admins health indicator now means: a tenant has at least one admin-defining role (every catalogue permission) with no active holder.

Retention (RES-6): the four WARN/ERROR events above are a detective control; Ops retention sign-off is deferred to the first deployment.

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
| `nexus_rbac_epoch_last_seen_dropped` | `increase(nexus_rbac_epoch_last_seen_dropped_total{reason="tenant_cap"}[15m]) > 0` | ticket | One busy tenant has used its share of the last-seen map and is shedding users |
| `nexus_rbac_epoch_last_seen_capacity` | `increase(nexus_rbac_epoch_last_seen_dropped_total{reason="capacity"}[15m]) > 0` | page | The whole read-derived map is full: new users get no local bound, so another instance's revocation is not enforced here while Redis reads fail. About ten tenants at their 10% share are enough to fill it (pre-PR security review L-1). Raise the capacity or lower `last-seen-tenant-percent`, and see RES-31 |
| `nexus_rbac_epoch_last_seen_bump_dropped` | `increase(nexus_rbac_epoch_last_seen_dropped_total{reason="bump_dropped"}[15m]) > 0` | page | An own bump was not remembered locally (tenant ceiling or global bound); that tenant fails closed while Redis reads fail |
| `nexus_rbac_epoch_store_regressed` | `increase(nexus_rbac_epoch_store_regressed_total[5m]) > 0` | page | Redis answered a read or a mint below an epoch this instance already knows (a refused or lost bump, a key lost to failover or FLUSH). The local bound is enforced meanwhile, and the replay retries each second. Check Redis `maxmemory` and `noeviction` first, then `bump_failed` (pre-PR security review M-1). No tenant or user tag |
| `nexus_rbac_epoch_unparseable` | `increase(nexus_rbac_epoch_check_total{outcome="unparseable"}[15m]) > 0` | ticket | Corrupt or foreign epoch keys in Redis (RES-32); the WARN is limited to one per tenant per minute, so the counter is the full signal |
| `nexus_rbac_epoch_skipped_error_rate_panel` | per-instance request rate next to `outcome="skipped_error"` | dashboard panel | Review 07 M-1 (b): shows whether reads are being pushed past 50 ms |

## 7. Break-glass CLI (US-018 M5, A7)

Source: `BreakGlassAlertAdapter`, `BootstrapAdminService`, `BreakGlassAdminRunner`, `RbacAuthEventAdapter`. Everything here is a log marker or an audit row: the CLI lives for seconds and is never scraped, so a metric it increments would not reach Prometheus (design section 7.2). Thresholds and severities are suggestions, as above. All fields are UUIDs, a bounded enum or a ticket id; no argument value is logged on `INVALID_ARGUMENT`.

### 7.1 Alerts

| Alert | Source | Suggested severity | Why |
|---|---|---|---|
| `rbac_break_glass_used` | Log-based: any ERROR with `event=RBAC_BREAK_GLASS_USED` | **page** (Platform Security on-call), every occurrence | Every invocation emits it: granted, refused (with `reason`), failed, and the web-context guard (`reason=WEB_CONTEXT`). Fields: `tenantId`, `targetUserId`, `outcome`, `reason`, `changeRef`. `tenantId`, `targetUserId` and `changeRef` are omitted on `INVALID_ARGUMENT`. Must route to a human outside business hours. Expected volume: a handful a year |
| `rbac_break_glass_alert_failed` | Log-based: ERROR `event=RBAC_BREAK_GLASS_ALERT_FAILED` (`tenantId`, `reason`) | page | The GRANTED page failed to send after a committed grant (exit stays 0). The grant is real and unpaged: contact Platform Security manually and check the SUCCESS row |
| `rbac_audit_write_lost` | Log-based: ERROR `event=RBAC_AUDIT_WRITE_LOST` (ids only, no `changeRef`); counter `nexus.rbac.audit_write_failed{operation="breakGlassRefusal", mode="best_effort"}` (the counter is only visible if the process is scraped, so the log is the signal) | ticket (page if it accompanies an unexplained refusal) | A refusal's FAILURE row could not be written. The exit code and the page survive; the durable record of that refusal is missing |
| `rbac_audit_write_failed` | Log-based: ERROR `event=RBAC_AUDIT_WRITE_FAILED` (`operation`, `tenantId`, `roleId`, `actorUserId`) | page if `operation` is the break-glass grant | The atomic (Group A) audit write failed and the surrounding mutation is rolled back. For a break-glass grant it means no grant (exit 1, `UNEXPECTED_ERROR`); runbook 11.3.1 |
| `rbac_break_glass_unpaged_failure` | Job status: a break-glass Job ended with exit 1 and its pod log has no `RBAC_BREAK_GLASS_USED` | page | The one case that is neither audited nor paged (a crash before or outside the grant transaction). Needs a Job-failure alert or a manual page by the operator (runbook 11.3.1). **No such alert is specified in the repository yet** |

### 7.2 Log queries

- All uses, newest first: `event="RBAC_BREAK_GLASS_USED"` (level ERROR), shown with `outcome`, `reason`, `tenantId`, `changeRef`.
- Lost or failed audit writes: `event IN ("RBAC_AUDIT_WRITE_LOST", "RBAC_AUDIT_WRITE_FAILED")`.
- Page not sent after a grant: `event="RBAC_BREAK_GLASS_ALERT_FAILED"`.
- Also present: `RBAC_BREAK_GLASS_FLUSH_WAIT_INTERRUPTED` (the flush wait was interrupted, so the page may not have been shipped) and `RBAC_BREAK_GLASS_CONFLICT` / `RBAC_BREAK_GLASS_GRANT_FAILED` (a failed grant transaction, with `tenantId` and the cause only). The exact fields of these three were not re-verified for this document.

### 7.3 Durable record and daily reconciliation

Rows: `auth_events`, `event_type = 'ROLE_BREAK_GLASS_GRANT'`, `outcome` `SUCCESS` (written in the grant transaction) or `FAILURE` (written on its own after the refusal). Metadata keys: `actorType` (`BREAK_GLASS_CLI`), `reason`, `changeRef` (omitted on `INVALID_ARGUMENT`). `user_roles.assigned_by` equals the target user for these grants.

```sql
SELECT HEX(id) AS event_id, created_at, outcome, HEX(tenant_id) AS tenant_id, HEX(user_id) AS target_user_id,
       JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.changeRef')) AS change_ref,
       JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason'))    AS reason
FROM auth_events
WHERE event_type = 'ROLE_BREAK_GLASS_GRANT'
  AND created_at >= NOW() - INTERVAL 1 DAY
ORDER BY created_at DESC;
```

**Daily reconciliation (deferred; an Ops deliverable, RC-37.4 backstop).** A ticket-severity alert on new `ROLE_BREAK_GLASS_GRANT` rows in `auth_events` so that a lost page is found from the durable row within a day. Design: it covers `SUCCESS` rows (an unpaged crash writes no row, hence the Job-failure alert above). Each SUCCESS row is matched to a ticket under its `changeRef` that records the contact-of-record check and the second approver. **This alert is not implemented in this repository and no environment exists; it is a merge condition and stays open until the first deployment** (STATUS.md). `auth_events` is append-only (BEFORE UPDATE and DELETE triggers), so the rows cannot be altered after the fact.
