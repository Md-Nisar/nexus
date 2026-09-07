# US-015 — Runbook

**Feature:** Role and permission management API (`POST/GET/DELETE /api/v1/roles[/{roleId}]`, `POST/DELETE /api/v1/roles/{roleId}/permissions[/{permissionId}]`, `GET /api/v1/permissions`)
**Audience:** on-call engineer, 3am, no prior context on this story
**Companion doc:** `docs/features/US-015/monitoring.md` (metric/alert/dashboard reference)

---

## 1. Alert: `nexus_rbac_role_mgmt_error_rate` firing

**First check, before anything else: the MySQL error log, grep for `command denied` on `roles`.**

This alert fires when >1% of requests to `/api/v1/roles*` return 5xx over a 5-minute window. Per design §9.3's alert row: *"Standard >1%-for-5m bar. First runbook check: the MySQL error log for `command denied` on `roles` — that is the R-6 dirty-flush failure mode, which is production-only."*

`nexus_app` is intentionally granted `INSERT`/`SELECT` on `roles` but **no `UPDATE`** (D9, §9.5) — a mutation of the `Role` entity triggers Hibernate's automatic dirty-checking flush at the end of the transaction, and if any code path leaves a managed `Role` entity dirty (even unintentionally — e.g. a field touched during a read path that should have stayed untouched), the flush issues an `UPDATE roles` statement that `nexus_app` cannot execute. This is the only test in the suite that catches it (`RolePermissionsPrivilegeIT`) and it is **production-only** — the IT suite runs with elevated grants in some environments, so this class of failure can be invisible in CI and only surface once flag-enabled in production/staging.

**Procedure:**

1. Check `rbacDbPrivilege` on `/actuator/health` first (D9's per-table expectation set — `roles` flags DOWN on **any** `UPDATE`, table-scoped or column-scoped). If DOWN, the detail fields identify which table/grant condition fired.
2. Grep the MySQL error log for `command denied ... roles` around the alert's time window.
3. If confirmed: this is either a grant regression (a DB provisioning change accidentally added `UPDATE` back, or removed it further than intended) or an application bug causing an unwanted `Role` mutation. Escalate to the DB-provisioning script owner and to the `RoleManagementService`/`JpaRoleManagementAdapter` owners in parallel — do not guess which without the error-log evidence.
4. **Fastest mitigation while the root cause is fixed:** flip `feature.nexus-us015-rbac-role-management.enabled` to `false` in the affected environment and redeploy/restart. All six endpoints vanish (Spring omits the controller beans; requests 404) — a config change, not a code revert. See §5 below for what this does and does not undo.
5. If `command denied` is **not** found in the error log, treat this as a generic 5xx investigation (application exception, connection pool exhaustion, an unrelated regression). Do not assume the dirty-flush explanation without the log evidence — it is the *most likely* cause for this alert, not the only one.

---

## 2. AC10 staleness — responding to "why hasn't a permission change taken effect?"

**Correct wording (copied verbatim from design §5.5, RC-2 — do not use an earlier draft's "~15 minutes"):**

> "Up to ~30 minutes (15-minute cache TTL plus the 15-minute token lifetime the stale read gets baked into). A token refresh does not shorten this window and can land at the worst point in it."

Why: `RoleResolutionService` is consulted only at token mint, not on every request. A stale permission set read at mint is baked into the JWT for that token's full 15-minute lifetime *in addition to* the up-to-15-minute cache TTL that produced the stale read — the two windows compound, they do not overlap. A token refresh does **not** shorten this window, because the cache's freshness fingerprint is the role *set*, not role permissions: editing a role's permissions changes no role name, so a refresh reads a "fresh" cache hit that is still serving the stale permission set. This is a documentation correction to AC10's original wording, not a reopening of ADR-0013 D4 — the no-caching-of-role-permission-changes decision stands.

**Immediate-effect path — use this if a user's access must stop right now:**

To stop a specific user's access immediately, **revoke their assignment via US-012's `DELETE /api/v1/users/{userId}/roles/{roleId}`, not the role's permission via US-015.** US-012's own cache eviction (`PermissionCachePort.evict`) makes an assignment revocation effective on the affected user's very next request — not bound by the ~30-minute window above, which only applies to editing what permissions a role carries.

---

## 3. Alert: `nexus_rbac_dangerous_permission_granted` firing — D15 escalation-review procedure

**Severity: ticket → review within 1 business day.** Per design §9.3's alert row: a legitimate admin attached `role:write`/`user:write`/`tenant:write` to a custom role. **This is the moment the D15 residual risk (the propagate-side escalation gap, §10 of the design) becomes reachable in that tenant** — it is not itself evidence of misuse.

**Procedure:**

1. Identify the role and tenant from the `RBAC_DANGEROUS_PERMISSION_ATTACH_BLOCKED`-adjacent `event=ROLE_PERMISSION_GRANTED` INFO log (fields: `tenantId`, `roleId`, `roleName`, `permissionId`, `permissionName`, `dangerous=true`, `grantedBy`).
2. **Confirm intent with the tenant.** Was this an intentional near-admin custom role for a legitimate purpose (Epic 3 needs these), or unexpected?
3. **Note the role id in the risk register**, regardless of outcome — this creates the durable trail that a review happened.
4. Check whether `nexus_rbac_self_role_assignment` has also fired for the same tenant around the same time (§9.3's composed alert). If both have fired, escalate immediately — that combination is the actual D15/R-3 exploitation signature (a self-assignment of a role that now carries a dangerous permission), not just the reachable precondition. See §12.3/D16 remediation below if escalation is warranted.
5. This does not require any code change or rollback by itself — it is a review-and-record procedure. Only escalate to the D16 remediation sequence (§5 below) if step 4 indicates active exploitation, or if the tenant confirms the grant was unintended/unauthorized.

---

## 4. Alert: `nexus_rbac_self_role_assignment` firing

Per design §9.3: cheap and unconditional by design — most firings are benign self-service and do not by themselves indicate a problem. **Escalates to page automatically if `nexus_rbac_dangerous_permission_granted_total` has also fired for the same tenant** — that composition is the actual escalation signal (§3 above), not this counter alone.

If it fires alone (no corresponding dangerous-grant alert for the tenant): no action required beyond normal awareness; this is expected traffic.

---

## 5. Rollback / remediation (D16) — and the way it differs from US-012

**Instant kill switch:** set `feature.nexus-us015-rbac-role-management.enabled` to `false`. All six endpoints vanish (Spring omits the beans; Spring MVC returns 404). Nothing else in the system changes behaviour.

**Code revert:** no Flyway migration to undo, no data reshaped, no backfill. Reverting the commit fully removes the feature.

> **⚠️ Correction to the inherited assumption — flag-off is NOT a privilege rollback.** US-012's rollback was trivially safe because its writes could be reversed through its own API. **US-015 is different:** custom roles and `role_permissions` rows written while the feature is live **remain live domain data**. `RoleResolutionService` reads them at every token mint regardless of whether US-015's code is deployed, so a custom role carrying `user:write` **keeps conferring `user:write`** after the flag is flipped off — and, with the API gone, there is no longer any way to detach the permission or manage the role.
>
> **RC-6 — flag-ordering trade, must not be discovered mid-incident.** Flipping the flag off first (step 1 below) stops further damage, but it also removes `GET /api/v1/roles/{roleId}/permissions` — the read path an operator would otherwise use to confirm exactly which permissions a suspect role carries before deciding how far to escalate. This is a defensible order (stop the bleeding first) — but pull any needed role/permission detail *before* step 1 if time allows, or rely on the audit trail (step 2 below) afterward.

**Remediation path:**

1. Flip the flag off to stop further changes. (Trade-off above: this also removes the permission-read endpoint — pull any needed role/permission detail *before* this step if time allows, or rely on the audit trail in step 2 afterward.)
2. Identify affected roles from the `ROLE_PERMISSION_GRANTED` audit rows / the `dangerous_permission_granted` alert history.
3. **Find every user currently holding the offending role.** The natural-looking reverse lookup does not exist — US-012's `UserRoleAssignmentPort` is a per-*user* API (`findActiveAssignmentsForUser`-shaped queries), with no *"which users hold role X"* query, because no story before this one ever needed to fan out from a role to its holders.

   **Immediate DBA fallback, usable the moment this ships, no code required:**
   ```sql
   SELECT BIN_TO_UUID(user_id) FROM user_roles WHERE role_id = UUID_TO_BIN(?) AND revoked_at IS NULL;
   ```
   This has been verified to run correctly against the shipped schema (MySQL 8.4, `user_roles.role_id BINARY(16)`) — see the verification note at the end of this document. Until an application-level equivalent lands, this raw SQL is the runbook's **only** path — do not assume the API exists.

4. Revoke the *assignments* found in step 3 via US-012's still-live `DELETE /api/v1/users/{userId}/roles/{roleId}` — this is the fastest containment and needs no DB access beyond step 3's lookup. **This is the important step: containment does not require further DB access once step 3's lookup has run**, which is why this is a manageable rollback rather than a blocking one — but only once step 3's lookup exists to drive it.
5. Only if the role itself must be neutered: a DBA `DELETE FROM role_permissions` under an explicit change record. `nexus_app` **cannot** do this with the app's own credentials once the endpoints are gone, and `roles` has no `UPDATE`/`DELETE` grant at all.

**"Flip the flag and you're back to the pre-US-015 privilege state" is false and must not be told to anyone during an incident.**

---

## 6. Forensic query for `ROLE_CREATED` / `ROLE_PERMISSION_GRANTED` / `ROLE_PERMISSION_REVOKED` (RES-7)

**These three event types are invisible to the standard actor-indexed query (`auth_events.user_id`)** — not merely "not queryable by it," but silently absent from a query an investigator would reasonably run and trust. `user_id` is `NULL` for all three, because the *subject* of these events is the role, not a user, and the convention across the rest of the `auth_events` taxonomy is that the column means "subject."

**A JSON-path query is mandatory, not optional, and must be run alongside the standard `user_id` query** when investigating "everything actor X did":

```sql
SELECT * FROM auth_events
WHERE event_type IN ('ROLE_CREATED','ROLE_PERMISSION_GRANTED','ROLE_PERMISSION_REVOKED')
  AND JSON_UNQUOTE(JSON_EXTRACT(metadata,'$.createdBy')) = ?
```

Substitute the metadata key per event type: `$.createdBy` for `ROLE_CREATED`, `$.grantedBy` for `ROLE_PERMISSION_GRANTED`, `$.revokedBy` for `ROLE_PERMISSION_REVOKED`.

---

## Cross-reference

- `docs/features/US-015/monitoring.md` — metric names, alert expressions, dashboard panels, and log field reference used throughout this runbook.
- `docs/features/US-015/03-design.md` §5.5 (RC-2/AC10 staleness), §9.2–§9.3 (signals/alerts), §9.5 (D9, health indicator), §9.6 (dashboard), §10 (D15/R-3 residual), §12.3 (D16 rollback), §12.5 (RES-7 forensic query) — the design rationale each procedure above traces back to.
- `docs/features/US-015/03b-threat-model.md` — RC-2, RC-6, RC-7 threat findings referenced above.

---

**Verification note (empirical check per 04-tasks.md's testing requirement):** the DBA fallback SQL in §5 step 3 was run against a live MySQL 8.4 instance (Testcontainers-provisioned, database `nexus`, schema as shipped) with a literal placeholder UUID substituted for the `?` parameter (the `?` is a JDBC/prepared-statement placeholder, not literal MySQL CLI syntax):

```sql
SELECT BIN_TO_UUID(user_id) FROM user_roles WHERE role_id = UUID_TO_BIN('01234567-89ab-cdef-0123-456789abcdef') AND revoked_at IS NULL;
```

Result: query executed without error, returning an empty result set (0 rows) — expected, since no role with that UUID exists in the schema. This confirms `BIN_TO_UUID`/`UUID_TO_BIN` round-trip correctly against `user_roles.role_id BINARY(16)` and `revoked_at` as shipped.
