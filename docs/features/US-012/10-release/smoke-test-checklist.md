# US-012 - Smoke Test Checklist

**Feature:** Role assignment / revocation API (POST/GET /api/v1/users/{userId}/roles, DELETE /api/v1/users/{userId}/roles/{roleId})
**Full context:** docs/features/US-012/09-technical.md section 5 (API surface), monitoring.md (metrics/health/log reference), 08-test-audit.md (the automated suite this checklist mirrors a subset of). This checklist is the manual/scripted execution sequence to run immediately after every deploy of this feature - it does not repeat the automated suite, it spot-checks the same behaviors against the real target environment.

Run this twice per environment, per deployment-checklist.md section 3: once immediately after the code deploy with the flag false, and again immediately after any later flag flip to true.

---

## 0. Preconditions

- [ ] Confirm which environment this run targets and its current feature.nexus-us012-rbac-role-assignment.enabled value before starting. Owner: [ASSIGN: On-call Engineer]
- [ ] Have on hand a valid JWT for a TENANT_ADMIN in a test tenant, a valid JWT for a plain MEMBER in the same tenant, a valid JWT for a user in a different tenant, and the UUIDs of an existing user plus the TENANT_ADMIN/MEMBER role ids in that tenant (seeded fixtures per 03-design.md section 11.1). Owner: [ASSIGN: QA Lead]

---

## 1. Healthcheck endpoint

- [ ] GET /actuator/health returns 200, top-level status UP. Owner: [ASSIGN: On-call Engineer]
- [ ] rbacDbPrivilege component present and UP. If DOWN, stop and escalate per runbook.md section 1. Owner: [ASSIGN: On-call Engineer]
- [ ] rbacZeroActiveAdmins component present and UP. If DOWN, escalate per runbook.md section 2 before proceeding. Owner: [ASSIGN: On-call Engineer]
- [ ] Note the M-1 caveat: until management.endpoint.health.roles is restricted, the detail payload above is readable by any authenticated user of any tenant, not just an operator - perform this check but do not treat its current exposure as acceptable for production. Owner: [ASSIGN: Security Reviewer]

---

## 2. While the flag is false - confirm the feature is genuinely absent

- [ ] POST /api/v1/users/{userId}/roles (any body, any valid auth) returns 404, not 403/401/500. Owner: [ASSIGN: On-call Engineer]
- [ ] GET /api/v1/users/{userId}/roles returns 404. Owner: [ASSIGN: On-call Engineer]
- [ ] DELETE /api/v1/users/{userId}/roles/{roleId} returns 404. Owner: [ASSIGN: On-call Engineer]
- [ ] Confirm the "RBAC / Role Assignment" dashboard row (monitoring.md section 4) shows zero traffic on these three URIs. Owner: [ASSIGN: On-call Engineer]
- [ ] Do not proceed to section 3 in this environment until the flag has actually been flipped true there per the rollout gate in deployment-checklist.md. Owner: [ASSIGN: Release Manager]

---

## 3. While the flag is true - happy path

- [ ] POST /api/v1/users/{userId}/roles with body roleId = MEMBER role id, authenticated as a TENANT_ADMIN in the same tenant as userId, returns 201, response carries a Location header, and body's assignedAt is non-null. Owner: [ASSIGN: QA Engineer]
- [ ] GET /api/v1/users/{userId}/roles (same tenant, same caller) returns 200, data envelope, and the assignment just created appears with correct roleId/roleName/non-null assignedAt. Owner: [ASSIGN: QA Engineer]
- [ ] Confirm assignedBy is populated in the response above (caller holds an active TENANT_ADMIN assignment) - mirrors RoleAssignmentSecurityIT#should_includeAssignedBy_when_callerIsActiveTenantAdmin. Owner: [ASSIGN: QA Engineer]
- [ ] Repeat the same GET authenticated as a plain MEMBER (not an admin) in the same tenant, returns 200 but assignedBy is null (present-but-null, not absent) - mirrors RoleAssignmentSecurityIT#should_omitAssignedBy_when_callerIsNotActiveTenantAdmin. Owner: [ASSIGN: QA Engineer]
- [ ] DELETE /api/v1/users/{userId}/roles/{roleId} for the assignment created above, as the TENANT_ADMIN, returns 204, empty body. Owner: [ASSIGN: QA Engineer]
- [ ] Re-run the GET from above - the revoked assignment no longer appears in data. Confirm via direct DB read that the underlying user_roles row still exists with revoked_at set (not physically deleted). Owner: [ASSIGN: QA Engineer] / [ASSIGN: DBA]
- [ ] Re-assign the same role to the same user after the revoke above, returns 201 again (reassign-after-revoke), mirroring RoleAssignmentIT's reassign scenario. Owner: [ASSIGN: QA Engineer]

---

## 4. Error paths

- [ ] POST the same active assignment twice in a row (no intervening revoke) - second call returns 409 with code RBAC_004, and the error body's detail does not echo any raw constraint name or hex fragment (closes T-T7). Owner: [ASSIGN: QA Engineer]
- [ ] DELETE the only active TENANT_ADMIN assignment left in a test tenant - returns 409 with code RBAC_002, and the assignment remains active afterward (confirm via GET). Mirrors LastAdminLockoutIT. Owner: [ASSIGN: QA Engineer]
- [ ] As a caller in tenant A, target a userId known to belong to tenant B on all three verbs - returns 403 (not a silent 404 or empty 200) on each. Mirrors RoleAssignmentSecurityIT's cross-tenant assertions (T-E8). Owner: [ASSIGN: QA Engineer]
- [ ] As a caller holding user:write but not an active TENANT_ADMIN assignment, attempt to POST a TENANT_ADMIN grant to another user - returns 403 with reason NOT_TENANT_ADMIN (AC8 self-escalation guard, T-E1). Confirm this increments nexus.rbac.permission_denied{reason="NOT_TENANT_ADMIN"} and, in staging only, deliberately trigger the paging alert once (nexus_rbac_self_escalation_attempt) to confirm it actually pages - see monitoring-checklist.md section 2. Owner: [ASSIGN: QA Engineer] / [ASSIGN: Security Reviewer]
- [ ] POST/DELETE with a syntactically malformed roleId (not a UUID) - returns 400, not 500 (D15's validate-before-parse guard). Owner: [ASSIGN: QA Engineer]
- [ ] GET/POST/DELETE against a nonexistent userId or roleId - returns 404, distinct from the cross-tenant 403 above (D8 - deliberately not collapsed to a uniform 404). Owner: [ASSIGN: QA Engineer]
- [ ] Confirm all of the above denial/conflict responses are RFC 7807 problem documents carrying code and traceId, with no stack trace or internal detail leaked. Owner: [ASSIGN: QA Engineer]

---

## 5. Critical pre-existing flows (regression, not RBAC-specific)

- [ ] Login flow completes successfully (the app restarted for this deploy; confirm no regression). Owner: [ASSIGN: QA Engineer]
- [ ] Token issuance/refresh still resolves roles/permissions correctly for a user with no role changes from this deploy. Owner: [ASSIGN: QA Engineer]
- [ ] Dashboard/basic authenticated navigation loads. Owner: [ASSIGN: QA Engineer]
- [ ] Payment: N/A - no payment feature exists in this platform. Owner: [ASSIGN: QA Engineer]
- [ ] Any existing endpoint gated by @RequiresPermission still enforces correctly (spot-check one) - confirms TenantAwarePermissionEvaluator was not regressed by this story's changes to DenialReason/GlobalExceptionHandler. Owner: [ASSIGN: QA Engineer]

---

## 6. Error monitoring shows no spike

- [ ] Check the error-rate dashboard/log aggregator for the 15 minutes surrounding this deploy/flag-flip - no spike above the environment's normal baseline, and specifically nexus_rbac_role_change_error_rate is at/near 0 (alert threshold is greater than 1% over 5 min - monitoring.md section 2). Owner: [ASSIGN: On-call Engineer]

## 7. Logs flowing

- [ ] Confirm the new structured log events are visible in the log platform for the actions exercised above: RBAC_DUPLICATE_ASSIGNMENT (DEBUG), RBAC_LAST_ADMIN_REVOCATION_BLOCKED (WARN), ROLE_ASSIGNED/ROLE_REVOKED (INFO) - field names per monitoring.md section 5. Owner: [ASSIGN: On-call Engineer]

## 8. Metrics flowing

- [ ] Confirm nexus.domain.conflict{code="RBAC_002"}, nexus.domain.conflict{code="RBAC_004"}, and nexus.rbac.permission_denied{reason="CROSS_TENANT_TARGET"|"NOT_TENANT_ADMIN"} all incremented as expected from the error-path checks in section 4, visible on /actuator/metrics or /actuator/prometheus. Owner: [ASSIGN: On-call Engineer]
- [ ] Confirm http.server.requests shows entries for all three new URIs with correct status tags matching the checks above. Owner: [ASSIGN: On-call Engineer]

---

## Overall Pass / Fail

PASS = every check above passes for the flag state(s) exercised in this run, including all section-4 error-path status codes and the section-1 health-indicator checks.
FAIL = any single check fails - do not sign off the deploy/flag-flip; go to rollback-checklist.md.

Known limitation of this checklist as of this release-prep pass: it has not yet been executed end-to-end against a real environment (no environment currently has both the code deployed and the flag true outside dev/test) - treat the first real execution (during the staging soak, deployment-checklist.md section 2) as the first live run, not a formality re-confirming prior work. Owner: [ASSIGN: QA Lead]

---

## Cross-references

- docs/features/US-012/monitoring.md - metric/alert/health-indicator/log-field reference used throughout this checklist
- docs/features/US-012/runbook.md - escalation procedures if any check fails
- docs/features/US-012/08-test-audit.md - the automated test names each manual check above mirrors
- docs/features/US-012/10-release/deployment-checklist.md, rollback-checklist.md, monitoring-checklist.md, production-readiness-report.md
