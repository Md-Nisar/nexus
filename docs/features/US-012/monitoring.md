# US-012 — Monitoring

**Feature:** Role assignment / revocation API (`POST /DELETE /GET /api/v1/users/{userId}/roles[/{roleId}]`)
**Audience:** on-call engineer
**Source of truth:** this document describes what T-015 actually shipped, verified against the code below — not the design doc's plan. Where verification changed something from `03-design.md` §9, it is called out explicitly.

---

## 1. Metrics

| Metric | Type | Tags | Emitted by | Notes |
|---|---|---|---|---|
| `nexus.domain.conflict` | Counter | `code` | `GlobalExceptionHandler#handleConflict` (`nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java:61`) | Fires on **every** `ConflictException`, not just RBAC's. For this story: `code="RBAC_002"` (last-admin lockout, `LastAdminRoleException`) and `code="RBAC_004"` (duplicate active assignment, `DuplicateRoleAssignmentException`). Prometheus name: `nexus_domain_conflict_total`. |
| `nexus.rbac.permission_denied` | Counter | `permission`, `reason` | `GlobalExceptionHandler#handleInsufficientPermission` (`GlobalExceptionHandler.java:154`) | Pre-existing counter (an earlier story). This story adds two new `reason` values it can carry: `CROSS_TENANT_TARGET` (AC4) and `NOT_TENANT_ADMIN` (AC8) — see `common/security/DenialReason.java`. Prometheus name: `nexus_rbac_permission_denied_total`. |
| `nexus.rbac.audit_write_failed` | Counter | `operation` | `RbacAuthEventAdapter`'s catch-all (`nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java:103`) | `operation` ∈ `{assign, revoke}`. Fires when a role change **committed** but its audit event could not be recorded (JSON serialization failure, or `SecureEventService`/`AuthEventPort` failure). Prometheus name: `nexus_rbac_audit_write_failed_total`. |
| `nexus.audit.buffer.dropped` | Counter | `lane`, `reason` | `AuthEventRetryBuffer` (existing, pre-US-012) | Relevant here because `ROLE_ASSIGNED`/`ROLE_REVOKED` were added to `AuthEventType.PRIORITY` (T-R4 reversal of the design's original D10 — see `identity/domain/AuthEventType.java`), so role-change events use the `priority` lane, not `standard`. `lane="standard"` drops should **not** include role-change events; if they ever do, `PRIORITY` membership has regressed. Prometheus name: `nexus_audit_buffer_dropped_total`. |
| `http.server.requests` | Timer/Counter | `uri`, `method`, `status`, `outcome` | Micrometer auto-instrumentation | Free, standard coverage for the three new URIs: `/api/v1/users/{userId}/roles` (POST, GET) and `/api/v1/users/{userId}/roles/{roleId}` (DELETE). No new instrumentation code needed. |

**Verification note:** all metric names, tag keys, and tag values above were checked directly against the shipped source (`GlobalExceptionHandler.java`, `RbacAuthEventAdapter.java`, `AuthEventRetryBuffer.java`, `DenialReason.java`), not assumed from the design doc. Every metric name assumed in `03-design.md` §9.3 matched what was actually implemented — no renames were needed.

---

## 2. Alerts (Prometheus)

Per `03-design.md` §9.3. Expressions copied verbatim from the design and re-verified against the metric names/tags in §1 above — **all matched**, no adjustments required.

| Alert | Expression | Severity | Meaning |
|---|---|---|---|
| `nexus_rbac_self_escalation_attempt` | `increase(nexus_rbac_permission_denied_total{reason="NOT_TENANT_ADMIN"}[5m]) > 0` | **page** | A non-admin attempted to grant `TENANT_ADMIN` (AC8 denial). Direct signal for T-E1 (privilege escalation); EPIC-002's bar is zero such findings. |
| `nexus_rbac_cross_tenant_attempt` | `increase(nexus_rbac_permission_denied_total{reason="CROSS_TENANT_TARGET"}[15m]) > 0` | ticket | A caller targeted a user/role outside their own tenant on any of the three verbs (AC4 denial). Could be a probe or a broken client. |
| `nexus_rbac_tenant_lockout_blocked` | `increase(nexus_domain_conflict_total{code="RBAC_002"}[15m]) > 0` | ticket | A caller tried to revoke a tenant's last active `TENANT_ADMIN` and was blocked (AC5 guard). Likely an offboarding process gap. |
| `nexus_rbac_audit_write_lost` | `increase(nexus_rbac_audit_write_failed_total[5m]) > 0` | **page** | A committed role assignment/revocation has no audit trail. See runbook — this is a data-completeness incident, not a correctness incident. |
| `nexus_rbac_role_change_error_rate` | `rate(http_server_requests_seconds_count{uri=~"/api/v1/users/\\{userId\\}/roles.*",status=~"5.."}[5m]) / rate(http_server_requests_seconds_count{uri=~"/api/v1/users/\\{userId\\}/roles.*"}[5m]) > 0.01` | **page** | Standard >1%-for-5m 5xx bar on the three endpoints. See runbook — first check is a DB-privilege regression. |
| `nexus_rbac_audit_lane_drops` | `increase(nexus_audit_buffer_dropped_total{lane="standard"}[15m]) > 0` | ticket, informational | Should rarely fire now that `ROLE_ASSIGNED`/`ROLE_REVOKED` are in the `priority` lane (T-R4). A firing alert here does not directly implicate role-change events (they're no longer in `standard`), but tracks general STANDARD-lane pressure as a secondary signal. |

Not re-stated here but already alertable via existing, unrelated infrastructure: `nexus_rbac_permission_cache_unavailable` (informational, cache eviction fail-open) and the standard HikariCP pool-exhaustion alert (D14 already removes the "second connection held behind a row lock" hazard by construction — see §6 of `03-design.md`).

---

## 3. Health indicators

Both are Spring Boot `HealthIndicator` beans, visible on the aggregate `/actuator/health` (neither is added to a liveness/readiness `management.endpoint.health.group.*.include` list — a DB-grant drift or a lockout condition stays UP the overwhelming majority of the time, so neither is treated like Redis's routine-absence exclusion).

### `rbacDbPrivilege` — `RbacDbPrivilegeHealthIndicator`

`nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacDbPrivilegeHealthIndicator.java`

Reports **DOWN** when the live DB connection's privileges on `user_roles` have drifted from the intended least-privilege grant set. Three independent checks, all OR'd:

1. `hasTableDeletePrivilege` / `hasGlobalDeletePrivilege` / `isRoot` — the pre-existing over-grant check (table-scoped or global `DELETE`/`ALL PRIVILEGES`, or connected as `root`).
2. **New in this story (T-015 / threat T-E12):** `hasBareTableUpdatePrivilege` — checks `information_schema.TABLE_PRIVILEGES` for a **bare, table-scoped** `UPDATE` grant on `user_roles`. The intended grant is column-scoped (`UPDATE (revoked_at)`, which only ever appears in `COLUMN_PRIVILEGES`, never `TABLE_PRIVILEGES`). Any row in `TABLE_PRIVILEGES` for `PRIVILEGE_TYPE = 'UPDATE'` means the column scoping has been silently widened — the exact failure mode that would re-permit the multi-column `UPDATE` R-1/D2 was designed to prevent, and which the *original* over-grant check (DELETE/ALL PRIVILEGES only) could not detect.

`Health.down()` details include `dbUser`, `isRoot`, `hasTableDeleteGrant`, `hasGlobalDeleteGrant`, `hasTableScopedUpdateGrant`, and an `issue` string identifying which condition fired. Returns `Health.unknown()` (never DOWN, never UP) if the self-check query itself fails — the check never blocks or crashes the app.

### `rbacZeroActiveAdmins` — `RbacZeroActiveAdminsHealthIndicator`

`nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java`

Reports **DOWN** when any tenant has a seeded `TENANT_ADMIN`-named role with **zero active assignments** (queries `JpaUserRoleRepository.findTenantsWithZeroActiveAssignmentsForRole(RbacRoleNames.TENANT_ADMIN)`). `Health.down()` details include the list of affected `tenantIds`.

This is the only control that catches an AC5 (last-admin lockout) bypass from **any** cause — not just the specific concurrent-revocation race the M1 locking guard in `RoleAssignmentService.revoke` already closes, but also a bug, a future grant change, a `roles.name` casing mismatch, or a raw-SQL path around the API entirely. It is a **detection** control, not a prevention control: by the time it reports DOWN, the tenant is already locked out (see runbook §2 for what to do). Returns `Health.unknown()` on a `DataAccessException`, same never-throws discipline as above.

---

## 4. Dashboard — "RBAC / Role Assignment" row

Per `03-design.md` §9.4:

| Panel | Query source |
|---|---|
| Request rate by endpoint + method | `http_server_requests_seconds_count{uri=~".*/roles.*"}` |
| Status mix (201 / 204 / 200 / 4xx / 5xx) | same series, split by `status` |
| Latency p50 / p95 / p99 by endpoint | `http_server_requests_seconds_bucket` — epic bar: p95 < 300 ms at 200 RPS |
| Authorization denials by `reason` | `nexus_rbac_permission_denied_total` |
| Domain conflicts by `code` | `nexus_domain_conflict_total{code=~"RBAC_00.*"}` |
| Audit-event lag / retry-buffer depth | `nexus_audit_buffer_depth{lane}` and `nexus_audit_buffer_oldest_age_seconds{lane}` (existing `AuthEventRetryBuffer` gauges — Micrometer names `nexus.audit.buffer.depth` / `nexus.audit.buffer.oldest.age.seconds`) |
| Feature-flag state | `feature.nexus-us012-rbac-role-assignment.enabled` via Actuator `/actuator/env` |

The feature flag itself: `@ConditionalOnProperty` on `UserRoleController`, default `false` (`application.yml`), `true` in `dev`/`test` (`application-dev.yml`, `application-test.yml`). If the flag is `false`, all three endpoints 404 and none of the above metrics/logs will appear — check this first if the dashboard row is unexpectedly empty in an environment where the feature is expected to be live.

---

## 5. Log queries (structured fields, for whatever log platform ingests SLF4J's `addKeyValue` output)

| What | Where it's logged | Level | Key fields |
|---|---|---|---|
| Cross-tenant / self-escalation denial (AC4/AC8) | `GlobalExceptionHandler#handleInsufficientPermission` | WARN | `event=api_request`, `errorCode=RBAC_001`, `reason` (`CROSS_TENANT_TARGET` / `NOT_TENANT_ADMIN`), `requiredPermission`, `userId`, `tenantId`, `correlationId` |
| Duplicate active assignment attempted | `RoleAssignmentService.assign` (`RoleAssignmentService.java:113`), ahead of throwing `DuplicateRoleAssignmentException` | DEBUG | `event=RBAC_DUPLICATE_ASSIGNMENT`, `tenantId`, `targetUserId`, `roleId`. Deliberately DEBUG, not WARN — a benign client bug, not a security signal; `nexus.domain.conflict{code="RBAC_004"}` is the trend-line metric. |
| Last-admin lockout blocked | `RoleAssignmentService.revoke` (`RoleAssignmentService.java:192`), ahead of throwing `LastAdminRoleException` | **WARN** | `event=RBAC_LAST_ADMIN_REVOCATION_BLOCKED`, `tenantId`, `targetUserId`, `actorUserId`, `roleId`. WARN, not DEBUG — an operator needs to know which tenant nearly locked itself out and who tried, independent of the `nexus.domain.conflict{code="RBAC_002"}` counter. |
| Role assigned / revoked (operator-visible success confirmation) | `RoleAssignmentService.assign`/`revoke`, inside `registerPostCommitSideEffects` (`RoleAssignmentService.java:147`, `:228`) | INFO | `event=ROLE_ASSIGNED` (`tenantId`, `targetUserId`, `roleId`, `assignedBy`) / `event=ROLE_REVOKED` (`tenantId`, `targetUserId`, `roleId`, `revokedBy`). Independent of the audit table's own availability — fires even if the same post-commit block's `rbacAuditPort` write fails, since that failure is caught and logged separately (see the audit-write-lost row below), not propagated. |
| Generic domain conflict (any `ConflictException`, incl. RBAC_002/RBAC_004) | `GlobalExceptionHandler#handleConflict` | DEBUG | `event=api_request`, `errorCode` (`RBAC_002` / `RBAC_004`), `correlationId` — a second, generic log line alongside the dedicated ones above; not the only signal for these two codes. |
| Audit write lost | `RbacAuthEventAdapter`'s catch-all | **ERROR** | `event=RBAC_AUDIT_WRITE_LOST`, `tenantId`, `targetUserId`, `roleId`, `actorUserId`, `traceId` |
| DB-privilege drift | `RbacDbPrivilegeHealthIndicator` | WARN (on transition to DOWN) | `dbUser`, `isRoot`, `hasTableDeleteGrant`, `hasGlobalDeleteGrant`, `hasTableScopedUpdateGrant` |
| Zero active admins | `RbacZeroActiveAdminsHealthIndicator` | WARN (on transition to DOWN) | affected `tenantIds` |

**Verification note:** re-checked directly against the shipped `RoleAssignmentService.java` as of the Phase 8 test-validate pass — all three dedicated structured log statements planned in `03-design.md` §9.2 (`RBAC_DUPLICATE_ASSIGNMENT` DEBUG, `RBAC_LAST_ADMIN_REVOCATION_BLOCKED` WARN, `ROLE_ASSIGNED`/`ROLE_REVOKED` INFO) are present in the class, at the line numbers cited above. An earlier draft of this document, written before those log statements were added, incorrectly stated they were missing — that has been corrected here.

---

## 6. Baseline metrics

Not yet captured — this story's dashboard has not had production traffic (feature flag defaults `false` outside `dev`/`test`; see `03-design.md` §10.2 rollout gate 2/3). Capture p50/p95/p99 latency and steady-state denial/conflict rates during the staging soak (rollout step 3) and record them here before the flag is flipped to `true` in production.
