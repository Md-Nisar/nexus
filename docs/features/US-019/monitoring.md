# US-019 Monitoring Guide

**Audience:** on-call engineer and Ops. **Companions:** [runbook.md](runbook.md), [09-technical.md](09-technical.md).
Metric names, tags, event names and log keys below were taken from the source on `feature/US-019` (`UserDirectoryController`, `UserDirectoryService`, `DirectoryAccessGuard`, `DirectoryReadAuthEventAdapter`, `LookupAuthorizationFirst`, `CallerAuthorizationService`, `RoleManagementService`, `RoleAssignmentService`, `PiiPermissionGrantRule`, `AdminDefiningRoleProvenanceDetector`, `GlobalExceptionHandler`). **Every threshold and severity is a proposal pending Ops sign-off** (P-1); none has a measured baseline, because the feature has not run in an environment.
No PII: no tag, log field or audit metadata holds an email, a blind index or an id list. No `tenantId` or `userId` is ever a metric tag.

## 1. Metrics

In Prometheus form dots become underscores and counters gain `_total`.

| Metric | Type | Tags | Emitted by |
|---|---|---|---|
| `nexus.identity.directory.requests` | Counter | `operation` (`list`, `batch`, `get`, `lookup`), `outcome` (`ok`, `not_found`, `invalid`, `throttled`, `error`) | `UserDirectoryController`; also `LookupAuthorizationFirst` for a lookup body rejected 400/415 before the handler (`outcome=invalid`). A permission denial (403) is not counted here |
| `nexus.identity.directory.duration` | Timer | `operation` | `UserDirectoryController` |
| `nexus.identity.directory.lookup_result` | Counter | `result` (`hit`, `miss`) | `UserDirectoryController` |
| `nexus.identity.directory.cross_tenant_miss` | Counter | none | `UserDirectoryService`: a by-id miss on an id that exists in another tenant, or a batch that carried foreign ids |
| `nexus.identity.directory.audit_write_failed` | Counter | none | `DirectoryReadAuthEventAdapter`. **See the note in section 4: it does not fire on an audit store outage** |
| `nexus.rbac.caller_authorization.reads` | Counter | `isAdministrator` (`true`, `false`) | `CallerAuthorizationService` (B4) |
| `nexus.rbac.permission_replace` | Counter | `outcome` (`replaced`, `noop`, `precondition_failed`, `precondition_required`, `denied`, `conflict`, `error`), `lockPath` (`role_row`, `set_lock`, `none`) | `RoleManagementService`; `RoleController` counts the 428 (`precondition_required`, `none`). The success label is `replaced`, not the design's `applied` |
| `nexus.rbac.privileged_revoke_lock_hold` | Timer | `operation` (now also `replace`), `outcome` | existing timer, B8 adds `operation=replace` |
| `nexus.rbac.admin_defining_role_non_admin_assigned_holder` | Counter | none | `AdminDefiningRoleProvenanceDetector`, after commit |
| `nexus.rbac.pii_permission_delegated` | Counter | none | `PiiPermissionGrantRule`, after commit |
| `nexus.rbac.role_ceased_admin_defining` | Counter | none | `RoleManagementService`: a B8 demotion of an admin-defining role |
| `nexus.rbac.role_classification_changed` | Counter | `operation` (`assign`, `attach`) | 409 `RBAC_012` |
| `nexus.rbac.denial_throttled` | Counter | `operation` | existing; now counts requests answered 429 `RBAC_011` |
| `nexus.rbac.permission_denied` | Counter | `permission`, `reason` (internal `DenialReason`) | existing; unchanged |

**Not shipped:** the design (section 17) listed `nexus.rbac.permission_replace.changes` (a distribution summary); it is not in the code (P-26). The `RBAC_PERMISSION_REPLACE_PRECONDITION_FAILED` marker is not shipped either: a 412 or 428 is logged at DEBUG with the code as the event.

## 2. Logs

Structured fields; ids only. WARN and ERROR events carry a stable `event` name.

| `event` | Level | Fields | Meaning |
|---|---|---|---|
| `IDENTITY_DIRECTORY_READ` | INFO | `tenantId`, `actorUserId`, `operation` (`LIST`, `BATCH`, `GET`, `LOOKUP`), `resultCount`, `statusFilter`, `requestedCount`/`returnedCount` (batch) | One per successful read |
| `IDENTITY_DIRECTORY_CROSS_TENANT_TARGET` | WARN | `tenantId`, `actorUserId`, `operation` (`GET`, `BATCH`), `omittedCount` (batch) | A read touched an id of another tenant. The response did not change |
| `IDENTITY_DIRECTORY_THROTTLED` | WARN | `tenantId`, `actorUserId`, `bucket` | At most once per window per bucket |
| `IDENTITY_DIRECTORY_AUDIT_WRITE_FAILED` | WARN | `tenantId`, `actorUserId`, `errorType` | The audit row could not be built or handed over |
| `RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER` | WARN | `tenantId`, `roleId`, `holderCount`, `nonAdminAssignedCount` | **Pages.** An admin-defining role has a holder assigned by a non-administrator |
| `RBAC_PII_PERMISSION_DELEGATED` | WARN | `tenantId`, `actorUserId`, `roleId`, `targetUserId` (null on attach) | A non-administrator granted `user:directory:read` (only possible with the rule switched off) |
| `RBAC_PII_PERMISSION_GRANT_DENIED` | WARN | same, plus `operation` | The rule refused the grant |
| `RBAC_PII_GRANT_RULE_DISABLED` | WARN | none | Startup: `nexus.rbac.pii-grant-requires-administrator` is `false` |
| `RBAC_ROLE_CEASED_ADMIN_DEFINING` | WARN | `tenantId`, `roleId`, `holderCount` | A B8 demotion |
| `RBAC_ROLE_CLASSIFICATION_CHANGED` | INFO | `tenantId`, `actorUserId`, `roleId`, `operation`, `targetUserId` or `permissionId` | 409 `RBAC_012` |
| `RBAC_PERMISSION_SET_REPLACED` | INFO | `tenantId`, `roleId`, `replaceId`, `addedCount`, `removedCount`, `lockPath`, `replacedBy` | After a B8 commit |
| `RBAC_REPLACE_EXCEEDS_CALLER` | WARN | `tenantId`, `actorUserId`, `roleId` | B8 refused: an added permission the caller does not hold |
| `RBAC_ATTACH_PROVENANCE_REFUSED` | WARN marker | | 409 `RBAC_010` on attach |
| `RBAC_001` (via `GlobalExceptionHandler`) | WARN | `reason` (caller-facing is in the body; the log has the internal reason), `requiredPermission`, `userId`, `tenantId` | Any denial |
| `DEV_SEED_ACTIVE` / `DEV_SEED_COMPLETED` | WARN / INFO | `profiles`; `created`, `skipped` | Dev profile only. `DEV_SEED_ACTIVE` in a shared environment means the `dev` profile is on: treat as an incident |
| `RBAC_DENIAL_THROTTLE_ENGAGED`, `RBAC_DENIAL_THROTTLED` | WARN | existing | One-time, and once-per-window, throttle markers |

**Retention (RES-6):** `RBAC_PII_PERMISSION_DELEGATED`, `IDENTITY_DIRECTORY_CROSS_TENANT_TARGET` and `RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER` must be retained for at least 1 year (at least as long as `auth_events`). They are detective controls. **Ops retention sign-off is pending** (P-2).

**Audit rows:** `auth_events` `event_type = 'USER_DIRECTORY_READ'`, `outcome = 'SUCCESS'`, `user_id` the actor, `tenant_id`, metadata `operation`, `resultCount`, `statusFilter`, and for lookup `outcome` (`HIT`/`MISS`) and `resolvedUserId`. One row per **successful** read; a by-id miss writes none (P-18). B8 writes the existing atomic `ROLE_PERMISSION_GRANTED` / `ROLE_PERMISSION_REVOKED` rows with `operation=REPLACE` and one `replaceId`.

```sql
SELECT created_at, HEX(user_id) AS actor_user_id,
       JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.operation')) AS operation,
       JSON_EXTRACT(metadata, '$.resultCount')             AS result_count
FROM auth_events
WHERE event_type = 'USER_DIRECTORY_READ'
  AND tenant_id = UNHEX(REPLACE(?, '-', ''))
  AND created_at >= NOW() - INTERVAL 1 DAY
ORDER BY created_at DESC;
```

## 3. Proposed alerts

All thresholds below are proposals from design section 17 (RC-61.1, RC-56.4, RC-60.2, RC-63(f)), adjusted to the names that shipped. Ops confirms or replaces them (P-1).

| Alert | Proposed condition | Severity |
|---|---|---|
| Admin-defining role with a non-administrator-assigned holder | `nexus_rbac_admin_defining_role_non_admin_assigned_holder_total` increases | **Page** |
| B8 errors | `nexus_rbac_permission_replace_total{outcome="error"}` increases (includes audit failure and deadlock victims) | **Page** |
| Directory row volume, high | log-derived sum of `resultCount` per (tenant, actor) above 10,000 rows per hour, or above the tenant's user count in a day | **Page** |
| Directory row volume | same sum above 1,000 rows per hour | Ticket |
| Directory lookup volume | `IDENTITY_DIRECTORY_READ` with `operation=LOOKUP` above 200 per (tenant, actor) per hour | Ticket |
| Cross-tenant probing | `nexus_identity_directory_cross_tenant_miss_total` over 15 minutes above `max(5 x the 7-day baseline, 20)` | Ticket. Alert on rate, not count: one holder can produce up to 600 per minute within the ceiling |
| PII permission delegated | `nexus_rbac_pii_permission_delegated_total` increases | Ticket |
| Role ceased to be admin-defining | `nexus_rbac_role_ceased_admin_defining_total` increases | Ticket |
| Directory audit loss | `nexus_audit_buffer_dropped_total` or `nexus_audit_retry_exhausted_total` increases, or `nexus_audit_buffer_depth` stays above 0 for 5 minutes (see section 4) | Ticket |
| B8 contention | `permission_replace{outcome="precondition_failed"}` above 20% of attempts for 15 minutes | Ticket (UX problem, not security) |
| Throttling | existing `denial_throttled` alerts; plus a sustained rise of `directory.requests{outcome="throttled"}` | Ticket |
| `RBAC_012` rate | `nexus_rbac_role_classification_changed_total` sustained above a handful per hour | Ticket (the console retries once; a high rate means contention on admin-defining roles) |
| Rule disabled | `RBAC_PII_GRANT_RULE_DISABLED` seen at startup | Page |

**Dashboard "Access management":** row 1 directory requests by operation and outcome, p95 duration, lookup hit/miss ratio; row 2 B4 reads; row 3 B8 outcomes, lock path split, `privileged_revoke_lock_hold{operation="replace"}` p95; row 4 `permission_denied` by reason, `RBAC_011` count, cross-tenant misses; row 5 zero-admin indicator.

## 4. Known gap: audit store outage

The directory audit write goes through `SecureEventService.recordEvent`, which is itself best-effort: on a database failure `JpaAuthEventAdapter` logs "Failed to persist auth event [type=USER_DIRECTORY_READ]" and enqueues the row to the `AuthEventRetryBuffer` (standard lane, capacity 800, up to 5 attempts, backoff 1 s to 10 min, while `nexus.identity.audit.retry-buffer.enabled` is true). The exception never reaches `DirectoryReadAuthEventAdapter`, so **`nexus.identity.directory.audit_write_failed` does not fire on an audit store outage**. It counts only a failure to build the row (a serialisation error). The read itself still answers 200 (`UserDirectoryAuditFailureIT`).

So watch the buffer instead: `nexus.audit.buffer.depth`, `nexus.audit.buffer.oldest.age.seconds`, `nexus.audit.retry.success`, `nexus.audit.retry.exhausted`, `nexus.audit.buffer.dropped`, and the log line above. A row that exhausts its attempts or is dropped is a permanent gap in the directory read audit. With the buffer flag off, a failed row is lost with only the WARN.
