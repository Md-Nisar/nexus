# US-015 — Monitoring

**Feature:** Role and permission management API (`POST/GET/DELETE /api/v1/roles[/{roleId}]`, `POST/DELETE /api/v1/roles/{roleId}/permissions[/{permissionId}]`, `GET /api/v1/permissions`)
**Audience:** on-call engineer
**Source:** metric names, alert expressions, and the dashboard panel table below are copied verbatim from `03-design.md` §9.1–§9.3 and §9.6.

---

## 1. Metrics

**Free — no new instrumentation (design §9.1):**

| Signal | Source |
|---|---|
| Rate / error rate / latency per endpoint | Micrometer `http.server.requests{uri, method, status, outcome}` — covers all six new URIs |
| 409 trend lines for `RBAC_003` / `RBAC_005` / `RBAC_006` | `nexus.domain.conflict{code}` in `handleConflict` |
| AC11 denials | `nexus.rbac.permission_denied{permission="role:write", reason="NOT_TENANT_ADMIN"}` + WARN, from `handleInsufficientPermission` |
| Cross-tenant probes | same counter, `reason="CROSS_TENANT_TARGET"` |
| `traceId` / `correlationId` | `CorrelationIdFilter` + MDC; lands in `auth_events.metadata.traceId` |
| `userId` / `tenantId` MDC | `JwtAuthenticationFilter`, via `AuthenticationDetailKeys` |
| Audit-write loss | `nexus.rbac.audit_write_failed{operation}` gains `createRole`, `grantPermission`, `revokePermission`; ERROR log `event=RBAC_AUDIT_WRITE_LOST` |
| Connection pool | HikariCP via Actuator |

**New in this story (design §9.2):**

| Signal | Type | Where | Notes |
|---|---|---|---|
| WARN `event=RBAC_SYSTEM_ROLE_MUTATION_BLOCKED` | Log | `RoleManagementService`, at the `SystemRoleImmutableException` throw site | Fields: `tenantId`, `roleId`, `roleName`, `permissionId`, `actorUserId`. AC7 attempts are invisible at production log levels via `handleConflict`'s DEBUG-level generic log alone |
| WARN `event=RBAC_DANGEROUS_PERMISSION_ATTACH_BLOCKED` | Log | `RoleManagementService`, at the AC11 denial throw site | Fields: `tenantId`, `roleId`, `roleName`, `permissionId`, `permissionName`, `actorUserId` |
| INFO `event=ROLE_CREATED` | Log | post-commit block | Fields: `tenantId`, `roleId`, `roleName`, `createdBy` |
| INFO `event=ROLE_PERMISSION_GRANTED` | Log | post-commit block | Fields: `tenantId`, `roleId`, `roleName`, `permissionId`, `permissionName`, `dangerous` (boolean), `grantedBy` |
| INFO `event=ROLE_PERMISSION_REVOKED` | Log | post-commit block | Fields as above minus `dangerous` |
| **`nexus.rbac.dangerous_permission_granted{permission, tenantId}`** | Counter | post-commit block, grant path only | The compensating control for the D15/R-3 residual risk. `permission` cardinality bounded at 3 (`role:write`/`user:write`/`tenant:write`); `tenantId` added so the RC-7 composed alert below can actually correlate per tenant (security-review fix — see RES-1). Prometheus name: `nexus_rbac_dangerous_permission_granted_total` |
| **`nexus.rbac.self_role_assignment{tenantId}`** | Counter | `RoleAssignmentService.assign()`'s existing post-commit block (RC-7) | Unconditional — increments whenever `actorUserId == targetUserId`, independent of the assigned role's permissions. `tenantId` tag added for the same reason as above. Prometheus name: `nexus_rbac_self_role_assignment_total` |

**No customer PII on any of these paths** — every field is a UUID, a role name, a permission name, or a boolean.

---

## 2. Alerts (Prometheus)

Per `03-design.md` §9.3, copied verbatim:

| Alert | Expression (Prometheus) | Severity | Meaning / action |
|---|---|---|---|
| `nexus_rbac_us015_self_escalation_attempt` | `increase(nexus_rbac_permission_denied_total{permission="role:write",reason="NOT_TENANT_ADMIN"}[5m]) > 0` | **page** | AC11 fired. A non-admin tried to attach a dangerous permission. Identify the actor from the `RBAC_DANGEROUS_PERMISSION_ATTACH_BLOCKED` WARN. EPIC-002's bar is *zero* privilege-escalation findings |
| `nexus_rbac_dangerous_permission_granted` | `increase(nexus_rbac_dangerous_permission_granted_total[15m]) > 0` | **ticket → review within 1 business day** | A legitimate admin attached `role:write`/`user:write`/`tenant:write` to a custom role. **This is the moment the D15 residual becomes reachable in that tenant.** Confirm intent with the tenant; note the role id in the risk register |
| `nexus_rbac_self_role_assignment` (RC-7) | ticket: `increase(nexus_rbac_self_role_assignment_total[5m]) > 0`. page (composed): `increase(nexus_rbac_self_role_assignment_total[5m]) > 0 and on (tenantId) increase(nexus_rbac_dangerous_permission_granted_total[15m]) > 0` | **ticket by default; page if the composed expression matches, i.e. `dangerous_permission_granted` has also fired for the *same* `tenantId`** | Someone assigned themselves a role. Cheap and unconditional by design (no dangerous-permission check at emission time, §9.2) — most firings are benign self-service. **Composed with the mint-side counter via PromQL's `and on (tenantId)` vector match, this is the actual escalation signal:** a tenant where both have fired has a legitimate admin who granted a dangerous permission *and* a self-assignment, which is exactly the D15/R-3 chain. Both counters carry a `tenantId` tag specifically so this join is evaluable (security-review fix — previously neither counter was tenant-tagged and this composition could not actually be expressed) |
| `nexus_rbac_system_role_mutation_blocked` | `increase(nexus_domain_conflict_total{code="RBAC_003"}[15m]) > 0` (RC-5b: lowered from `> 3` — no benign client attempts a system-role write repeatedly by accident, and this is `MEMBER`'s only gate against a dangerous-permission attach) | ticket | AC7 block — probing, a broken client, or (for `MEMBER`/`TENANT_ADMIN`) an attempted escalation that AC7 alone stopped |
| `nexus_rbac_audit_write_lost` | `increase(nexus_rbac_audit_write_failed_total{operation=~"createRole\|grantPermission\|revokePermission"}[5m]) > 0` | **page** | A committed role change has no audit record. Reconstruct from the `RBAC_AUDIT_WRITE_LOST` ERROR log |
| `nexus_rbac_cross_tenant_role_probe` | `increase(nexus_rbac_permission_denied_total{permission=~"role:.*",reason="CROSS_TENANT_TARGET"}[15m]) > 0` | ticket | Cross-tenant probe or a broken client |
| `nexus_rbac_role_mgmt_error_rate` | `rate(http_server_requests_seconds_count{uri=~"/api/v1/roles.*",status=~"5.."}[5m]) / rate(…[5m]) > 0.01` | page | Standard >1%-for-5m bar. **First runbook check: the MySQL error log for `command denied` on `roles`** — that is the R-6 dirty-flush failure mode, which is production-only |
| `nexus_audit_priority_lane_depth` | *existing* depth-critical ≥180 | **page** | Unchanged threshold — see design §9.4 (lane grows from 6 to 8 admitted types; no threshold change, `ROLE_CREATED` deliberately excluded from the priority lane) |

---

## 3. Dashboard — "RBAC / Role Management" row

Per `03-design.md` §9.6, copied verbatim (all 10 panels, including the two RC-7-added rows):

| Panel | Query source |
|---|---|
| Request rate by endpoint + method | `http_server_requests_seconds_count{uri=~"/api/v1/roles.*\|/api/v1/permissions"}` |
| Status mix (201 / 204 / 200 / 4xx / 5xx) | same, by `status` |
| Latency p50 / p95 / p99 | `http_server_requests_seconds_bucket` — epic bar: **p95 < 300 ms at 200 RPS** |
| Authorization denials by `permission` × `reason` | `nexus_rbac_permission_denied_total` |
| Domain conflicts by `code` | `nexus_domain_conflict_total{code=~"RBAC_00[356]"}` |
| **Dangerous-permission grants** | `nexus_rbac_dangerous_permission_granted_total` by `permission` |
| **Self-role-assignment rate (RC-7)** | `nexus_rbac_self_role_assignment_total`, overlaid with `nexus_rbac_dangerous_permission_granted_total`, both grouped `by (tenantId)` |
| Priority-lane depth **by event type** | existing `AuthEventRetryBuffer` gauges — §9.4's review trigger |
| Audit-write failures | `nexus_rbac_audit_write_failed_total{operation}` |
| Roles per tenant (growth watch, D11 revisit trigger) | ad-hoc SQL panel, weekly |
| Feature-flag state | `feature.nexus-us015-rbac-role-management.enabled` via Actuator `/env` |

The feature flag itself: `@ConditionalOnProperty` on both `RoleController` and `PermissionController`, default `false` (`application.yml`), `true` in `dev`/`test`. If the flag is `false`, all six endpoints 404 and none of the above metrics/logs will appear — check this first if the dashboard row is unexpectedly empty in an environment where the feature is expected to be live.

---

## 4. Log queries (structured fields)

| What | Where it's logged | Level | Key fields |
|---|---|---|---|
| System-role mutation blocked (AC7) | `RoleManagementService`, at the `SystemRoleImmutableException` throw site | **WARN** | `event=RBAC_SYSTEM_ROLE_MUTATION_BLOCKED`, `tenantId`, `roleId`, `roleName`, `permissionId`, `actorUserId` |
| Dangerous-permission attach blocked (AC11) | `RoleManagementService`, at the AC11 denial throw site | **WARN** | `event=RBAC_DANGEROUS_PERMISSION_ATTACH_BLOCKED`, `tenantId`, `roleId`, `roleName`, `permissionId`, `permissionName`, `actorUserId` |
| Role created | post-commit block | INFO | `event=ROLE_CREATED`, `tenantId`, `roleId`, `roleName`, `createdBy` |
| Role permission granted | post-commit block | INFO | `event=ROLE_PERMISSION_GRANTED`, `tenantId`, `roleId`, `roleName`, `permissionId`, `permissionName`, `dangerous` (boolean), `grantedBy` |
| Role permission revoked | post-commit block | INFO | `event=ROLE_PERMISSION_REVOKED`, same fields minus `dangerous`, plus `revokedBy` |
| Audit write lost | `RbacAuthEventAdapter`'s catch-all | **ERROR** | `event=RBAC_AUDIT_WRITE_LOST`, `tenantId`, `roleId`, `actorUserId`, `traceId` |
| DB-privilege drift (`roles`/`role_permissions`, D9) | `RbacDbPrivilegeHealthIndicator` | WARN (on transition to DOWN) | `dbUser`, `isRoot`, per-table grant detail fields |

**Forensic note:** `ROLE_CREATED`/`ROLE_PERMISSION_GRANTED`/`ROLE_PERMISSION_REVOKED` audit rows carry `auth_events.user_id = NULL` (the subject is the role, not a user) — see the runbook §6 for the mandatory JSON-path query needed to find these by actor.

---

## 5. Baseline metrics

Not yet captured — this story's dashboard has not had production traffic (feature flag defaults `false` outside `dev`/`test`; see `03-design.md` §12.1 rollout gates 2–3). Capture p50/p95/p99 latency and steady-state denial/conflict rates during the staging soak and record them here before the flag is flipped to `true` in production.

---

## Cross-reference

- `docs/features/US-015/runbook.md` — incident procedures for the alerts above.
- `docs/features/US-015/03-design.md` §9 (observability), §12.1 (rollout).
