# US-012 — Runbook

**Feature:** Role assignment / revocation API (`POST /DELETE /GET /api/v1/users/{userId}/roles[/{roleId}]`)
**Audience:** on-call engineer, 3am, no prior context on this story
**Companion doc:** `docs/features/US-012/monitoring.md` (metric/alert/dashboard reference)

---

## 1. Alert: `nexus_rbac_role_change_error_rate` firing

**First check, before anything else: the MySQL error log, grep for `command denied`.**

This alert fires when >1% of requests to `/api/v1/users/{userId}/roles*` return 5xx over a 5-minute window. Per the design's own threat analysis (`03-design.md`, threat findings T-E12/R-1/R-4), **the single most likely cause is a DB-privilege regression** — the application's DB user (`nexus_app`) lost, or never had, the exact grants this feature depends on:

- `UPDATE (revoked_at)` on `user_roles` (column-scoped) — needed by revocation (`JpaUserRoleRepository`'s M6 query).
- `SELECT ... FOR UPDATE` / `FOR SHARE` locking reads on `user_roles` — needed by the last-admin lockout guard (M1) and the live-admin check (M5).

If either grant is missing, widened incorrectly, or the connection has drifted to a different DB user (e.g. accidentally connecting as a superuser instead of `nexus_app`, or the reverse), MySQL rejects the specific statement with `ERROR 1142 (42000): command denied to user ...` and the request surfaces as a 500 (this class of failure is invisible to most of the IT suite, which historically ran as a superuser — see `UserRolesPrivilegeIT` for the regression test that guards against it in CI, which does **not** run in production).

**Procedure:**

1. Check `rbacDbPrivilege` on `/actuator/health` first — if it reports **DOWN**, the `hasTableScopedUpdateGrant`/`hasTableDeleteGrant`/`hasGlobalDeleteGrant`/`isRoot` detail fields tell you exactly which grant condition is wrong. This is the fastest confirmation.
2. Grep the MySQL error log for `command denied` around the time window the alert covers.
3. If confirmed: this is a grant/provisioning regression, not an application bug. Escalate to whoever owns the DB provisioning scripts (`nexus-database/mysql/init/02-grants-post-schema.sql` per `03-design.md` §5.5) — do **not** attempt to patch it by relaxing application code, since the column-scoping is the actual security control (R-1).
4. **Fastest mitigation while the grant is fixed:** flip `feature.nexus-us012-rbac-role-assignment.enabled` to `false` in the affected environment's config and redeploy/restart. This removes the three endpoints entirely (Spring omits the controller bean, requests 404) — a config change, not a code revert. See `03-design.md` §10.3 for the full rollback rationale.
5. If `command denied` is **not** found in the error log, treat this as a generic 5xx investigation (application exception, connection pool exhaustion — check HikariCP metrics — or an unrelated regression). Do not assume the DB-privilege explanation without checking; it is the *most likely* cause, not the only one.

---

## 2. `RbacZeroActiveAdminsHealthIndicator` firing (`rbacZeroActiveAdmins` DOWN)

This means one or more tenants have **zero active `TENANT_ADMIN` assignments** — the tenant is locked out of any `user:write`-gated action (including this very API), and no one in that tenant can self-service a fix.

**There is no self-service recovery path via the API by design.** `RoleAssignmentService.assign` requires the caller to already hold an active `TENANT_ADMIN` assignment before granting `TENANT_ADMIN` to anyone else (AC8) — that is precisely the control this incident means has (for some reason) resulted in zero admins. A tenant in this state cannot use `POST /api/v1/users/{userId}/roles` to fix itself: every caller in that tenant will get `403 NOT_TENANT_ADMIN`.

**What to actually do:**

1. Check `/actuator/health`'s `rbacZeroActiveAdmins` detail for the affected `tenantIds`.
2. Confirm the finding directly: `SELECT tenant_id, COUNT(*) FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE r.name = 'TENANT_ADMIN' AND ur.revoked_at IS NULL AND ur.tenant_id = '<tenant>' GROUP BY tenant_id;` — expect zero rows for the affected tenant.
3. Determine how this happened before touching anything: was it a legitimate but reckless self-revocation chain (a bug in this feature would be a *different* incident — check `nexus_rbac_tenant_lockout_blocked`/`RBAC_002` history first; if that alert fired and was correctly blocking attempts, this DOWN state predates this feature or came from a path that bypasses it), a bulk/offline data operation, or a support action gone wrong.
4. **Recovery requires a direct, `nexus_app`-privileged DB intervention or a support escalation process** — there is no UI or API-level fix. This is a deliberate consequence of the design (AC8 has no bootstrap/break-glass path in this story) and should be treated as such, not as a bug to route back to engineering as a defect against this API. Concretely, recovery is an `INSERT` of a new active `user_roles` row for a real, already-existing user in that tenant, assigning them the tenant's `TENANT_ADMIN` role id, done by whoever holds production DB write access (this is intentionally **not** something the on-call engineer should do unilaterally from a personal DB session — follow your team's existing production-data-change approval process for a manual insert of this kind, since it is functionally a privilege grant).
5. After remediation, confirm `rbacZeroActiveAdmins` returns to UP, and confirm with the tenant that the newly-designated admin can now perform `user:write` actions normally.
6. This is the kind of finding worth a retro: if it recurs, it may indicate `03-design.md`'s O-5 residual (a non-admin `user:write` holder revoking one of *two* admins one at a time, each individually passing the "not the last one" check) is now reachable — currently accepted as unreachable pre-US-015, but worth re-checking if a tenant has custom roles with `user:write`.

---

## 3. Alert: `nexus_rbac_audit_write_lost` firing

**This is a data-completeness incident for compliance/audit purposes — it is NOT a correctness incident for the RBAC state itself.**

By design (`03-design.md` §6.4, audit is post-commit/best-effort — see Res. 9), the role assignment or revocation **already committed successfully** before the audit write was attempted. The transaction is not, and cannot be, rolled back because of an audit failure that happens after commit. The user's roles are correct; what's missing is the audit *record* of the change.

**What happened:** `RbacAuthEventAdapter`'s catch-all fired (`nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java`), meaning either the metadata JSON failed to serialize, or `SecureEventService.recordEvent` (and everything behind it, including `AuthEventRetryBuffer`'s own retry mechanism) still failed to persist the `auth_events` row after all retries.

**What to do:**

1. Find the `RBAC_AUDIT_WRITE_LOST` ERROR log line(s) for the alert's time window. Each one carries `tenantId`, `targetUserId`, `roleId`, `actorUserId`, and `traceId` — everything needed to manually reconstruct what happened for compliance/audit purposes.
2. Cross-reference `traceId` against the application/access logs for that request to recover the full context (timestamp, IP, user agent) if needed.
3. Manually create the missing audit trail entry (through whatever your team's compliance process requires for a "known-missing" audit record) using the reconstructed fields — do not silently drop it; the whole point of paging on this alert is that `auth_events` must remain a complete record for RBAC changes.
4. Investigate *why* the write failed — check for a broader `auth_events` availability incident (is `AuthEventRetryBuffer`'s depth gauge climbing? Is the underlying MySQL connection unhealthy?) rather than treating each occurrence in isolation. If this is part of a wider audit-infrastructure outage, that is the actual incident to resolve; this alert is just RBAC's window into it.
5. Do **not** attempt to "fix" this by re-running the role assignment/revocation — the RBAC state is already correct and re-running would either no-op (duplicate/already-revoked) or, worse, create a confusing double audit trail once the underlying issue is fixed.

---

## 4. Alert: `nexus_rbac_self_escalation_attempt` firing

**This is a potential active-attack signal, not routine noise.** Per this story's own threat model (finding T-E1), a non-admin user attempting to grant themselves or someone else `TENANT_ADMIN` without already holding an active `TENANT_ADMIN` assignment is exactly the privilege-escalation scenario this entire feature exists to prevent. EPIC-002's stated success bar is **zero** such findings in steady state — this alert firing at all is worth treating as a genuine finding, not dismissing as background noise, even though the request was correctly blocked (403 `NOT_TENANT_ADMIN`).

**What to do:**

1. Find the WARN log line(s) for the denial (`GlobalExceptionHandler#handleInsufficientPermission`, `errorCode=RBAC_001`, `reason=NOT_TENANT_ADMIN`). It carries `userId` and `tenantId` — identify the actor and their tenant directly from these fields.
2. Determine whether this is: (a) a single confused/misconfigured legitimate client repeatedly retrying a request it isn't authorized for, or (b) a deliberate attempt to escalate privileges — check request volume/pattern from the same `userId`/IP around the same time, and whether the same actor is also showing up in `nexus_rbac_cross_tenant_attempt`.
3. If it looks deliberate: treat as a security incident per your standard incident-response process — this may warrant disabling the actor's account/session, not just noting it.
4. Note that the caller's JWT may have carried `user:write` legitimately (they passed the coarse `@RequiresPermission("user:write")` check) — this alert is specifically about the finer-grained AC8 check (`RoleAssignmentService.assign`'s live DB read via `hasActiveAdminAssignment`) rejecting them because they are not *currently* an active `TENANT_ADMIN`. This finer check is deliberately a live, locking DB read rather than a JWT claim, specifically to catch an actor whose admin status was revoked out-of-band but who still holds a valid, unexpired token (see `RoleAssignmentService.assign`'s Javadoc, threat T-E7) — so this alert can also legitimately fire for a *recently-demoted* admin who hasn't refreshed their mental model of their own permissions yet, not only for a never-was-admin attacker. Use judgment; don't treat every occurrence as confirmed malicious, but do not ignore it either.

---

## Cross-reference

- `docs/features/US-012/monitoring.md` — metric names, alert expressions, health indicator details, dashboard panels, and log field reference used throughout this runbook.
- `docs/features/US-012/03-design.md` §6.3–§6.4, §9 — the design rationale each procedure above traces back to.
- `docs/features/US-012/03b-threat-model.md` — T-E1, T-E7, T-E12, R-1, R-4, O-5 — the specific threat findings referenced above.
