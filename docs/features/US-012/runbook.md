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

**Widened by US-017 (FR-2) — read this section as current, not the original T-015 shape.** This means one or more tenants have **zero active holders of any admin-equivalent role** — the literally-named `TENANT_ADMIN`, **or** a custom role carrying any of `role:write`/`user:write`/`tenant:write` — so the tenant is locked out of any `user:write`-gated action (including this very API), and no one in that tenant can self-service a fix.

**There is no self-service recovery path via the API by design.** `RoleAssignmentService.assign` requires the caller to already hold an active admin-equivalent assignment before granting a privileged role to anyone else — that is precisely the control this incident means has (for some reason) resulted in zero holders. A tenant in this state cannot use `POST /api/v1/users/{userId}/roles` to fix itself: every caller in that tenant will get `403 NOT_TENANT_ADMIN`.

**What to actually do:**

1. **Fixed (US-017): the health detail no longer carries the affected `tenantIds` — it never has since M-1 replaced the list with a count.** Get the affected tenant ids from the **`RBAC_LAST_ADMIN_REVOCATION_BLOCKED`/zero-active-admins WARN log lines** instead (`docs/features/US-012/monitoring.md` §3/§5: the health indicator itself logs `tenant(s) with zero active caller-qualifying holders detected: tenantIds={}` on the transition to DOWN — that WARN, not the actuator response, is where the ids live). `/actuator/health`'s `rbacZeroActiveAdmins` detail gives you only `affectedTenantCount` and the free-text `issue` — useful to confirm *that* something is wrong and roughly how widely, not *which* tenant.
2. **Confirm the finding directly, using the caller-qualifying form of the query (ALL three dangerous permissions, not any one of them), not the literal-name-only form this step used before US-017, and not the ANY-based form an earlier revision of this runbook used before `06-code-review.md` H-1 (2026-09-24):**
   ```sql
   SELECT tenant_id, COUNT(*) AS active_caller_qualifying_holders
   FROM user_roles ur
   JOIN roles r ON ur.role_id = r.id
   WHERE ur.revoked_at IS NULL
     AND ur.tenant_id = UUID_TO_BIN('<tenant>')
     AND (
       r.name = 'TENANT_ADMIN'
       OR (
         SELECT COUNT(DISTINCT p.name) FROM role_permissions rp
         JOIN permissions p ON p.id = rp.permission_id
         WHERE rp.role_id = r.id
           AND p.name IN ('role:write', 'user:write', 'tenant:write')
       ) = 3
     )
   GROUP BY tenant_id;
   ```
   Expect **zero rows** for the affected tenant. **`WHERE r.name = 'TENANT_ADMIN'` alone is now wrong** — post-US-017 widening, a tenant can be legitimately zeroed-out on a custom caller-qualifying role while still holding an unrelated, un-zeroed literal `TENANT_ADMIN` role (or vice versa); the literal-name-only form will both miss real incidents and false-positive on healthy tenants. **The `OR EXISTS (... IN (...))` (ANY) form is also now wrong** (H-1): a role carrying only one or two of the three dangerous permissions is not caller-qualifying and must not be counted here — using ANY instead of `COUNT(DISTINCT) = 3` would make this confirmation query disagree with what the health indicator and the lockout guard actually protect.
3. Determine how this happened before touching anything: was it a legitimate but reckless self-revocation chain (a bug in this feature would be a *different* incident — check `nexus_rbac_tenant_lockout_blocked`/`RBAC_002` and, since US-017, `nexus_rbac_last_admin_lockout_blocked` history first; if either alert fired and was correctly blocking attempts, this DOWN state predates this feature or came from a path that bypasses it), a bulk/offline data operation, or a support action gone wrong. **If a remediation ticket or written acceptance already exists for this tenant from the pre-deploy forensic sweep (below), start there** — this may be a known, already-triaged finding, not a new incident.
4. **Recovery requires a direct, `nexus_app`-privileged DB intervention or a support escalation process** — there is no UI or API-level fix. This is a deliberate consequence of the design (there is no bootstrap/break-glass path in this story or in US-017) and should be treated as such, not as a bug to route back to engineering as a defect against this API. Concretely, recovery is an `INSERT` of a new active `user_roles` row for a real, already-existing user in that tenant, assigning them an admin-equivalent role id (the tenant's `TENANT_ADMIN` role, or another admin-equivalent role already provisioned for that tenant), done by whoever holds production DB write access (this is intentionally **not** something the on-call engineer should do unilaterally from a personal DB session — follow your team's existing production-data-change approval process for a manual insert of this kind, since it is functionally a privilege grant).
5. After remediation, confirm `rbacZeroActiveAdmins` returns to UP, and confirm with the tenant that the newly-designated admin can now perform `user:write` actions normally.
6. **First-class since US-017, not speculative:** a non-admin `user:write` holder revoking one of *two or more* admin-equivalent holders one at a time, each individually passing the "not the last one" check, is exactly the scenario FR-1's tenant-wide distinct-holder guard now closes — including for custom roles carrying `role:write`/`user:write`/`tenant:write`, not only the literal `TENANT_ADMIN`. If this DOWN condition recurs on a *custom* admin-equivalent role with a very large holder population, cross-check `nexus.rbac.admin_equivalent_lock_set_size`'s p99 (`docs/features/US-016/monitoring.md` §4) and US-016's **RES-1(b)** (the attach-after-assign pre-positioning primitive, `docs/features/US-017/03-design.md` §12.3) — a widely-held role becoming dangerous is the most likely way a tenant accumulates that large a population in the first place.
7. **Expect a DOWN on first deploy of US-017's FR-2 in any environment where either `feature.nexus-us012-rbac-role-assignment` or `feature.nexus-us015-rbac-role-management` was ever `true` (`docs/features/US-017/03-design.md` §10.3 step 3).** FR-2 widens what this indicator can see; a tenant that was silently zeroed out on a custom admin-equivalent role **before** US-016's privilege gate existed (when `revoke()` had no admin check at all) becomes visible on FR-2's very first poll. **If the pre-deploy forensic sweep below was run and this tenant already carries a remediation ticket or written acceptance, this DOWN is expected — triage it as "known, already accepted," not as a regression in new code.** If it carries neither, treat it as a new incident and follow steps 1–5 above.

---

### Pre-deployment forensic sweep (RC-21, US-017) — run once, before flipping either feature flag `true` in production

**Why this exists.** FR-2 (the widened health indicator above) is *detection*. The population it can newly see may **already be zeroed** by the time FR-2 first runs — and that population may not be innocent: **before US-016's privilege gate shipped, `revoke()` had no admin check at all**, so a historical zeroing of a custom admin-equivalent role could have been performed by any `user:write` holder, not only an administrator making an offboarding mistake. Detection without attribution just produces a list; this sweep produces attribution, evidence, and a required action per `docs/features/US-017/03-design.md` §10.3 step 3 and `03b-threat-model.md` RC-21. Per US-015 RC-6's discipline, this is executable DBA SQL — an operator cannot invoke a Java port method.

**Scope: run in every environment where either `feature.nexus-us012-rbac-role-assignment.enabled` or `feature.nexus-us015-rbac-role-management.enabled` has ever been `true`** — dev, test, and staging, not production alone. Production's flags are `false`, so the population most likely to already exist is in the lower environments.

**Step 1 (DBA) — detect tenants with a caller-qualifying role but zero active holders, right now:**

```sql
SELECT BIN_TO_UUID(a.tenant_id) AS tenant_id
FROM (
    SELECT DISTINCT r.tenant_id
    FROM roles r
    WHERE r.name = 'TENANT_ADMIN'
       OR (
            SELECT COUNT(DISTINCT p.name) FROM role_permissions rp
            JOIN permissions p ON p.id = rp.permission_id
            WHERE rp.role_id = r.id
              AND p.name IN ('role:write', 'user:write', 'tenant:write')
          ) = 3
) a
LEFT JOIN (
    SELECT DISTINCT r.tenant_id
    FROM roles r
    JOIN user_roles ur ON ur.role_id = r.id AND ur.tenant_id = r.tenant_id AND ur.revoked_at IS NULL
    WHERE r.name = 'TENANT_ADMIN'
       OR (
            SELECT COUNT(DISTINCT p.name) FROM role_permissions rp
            JOIN permissions p ON p.id = rp.permission_id
            WHERE rp.role_id = r.id
              AND p.name IN ('role:write', 'user:write', 'tenant:write')
          ) = 3
) b ON b.tenant_id = a.tenant_id
WHERE b.tenant_id IS NULL;
```

This is `03-design.md` §8.2's own tenant-set predicate, translated into raw SQL against the shipped schema (`roles`, `role_permissions`, `permissions`, `user_roles`) — the same "tenants with a caller-qualifying role" minus "tenants with an active caller-qualifying holder" logic the widened health indicator runs internally. **Re-scoped from ANY (`OR EXISTS ... IN (...)`) to ALL (`COUNT(DISTINCT ...) = 3`) per `06-code-review.md` H-1 (2026-09-24)** — a role carrying only one or two of the three dangerous permissions is not caller-qualifying and must not be counted here; using ANY would find a different, wrong population than what the shipped health indicator and lockout guard actually protect.

**Step 2 (DBA) — for each `tenant_id` from step 1, attribution: every `ROLE_REVOKED` event ever recorded for that tenant, in order, so the revocation(s) that took it to zero (and who performed them) can be identified — a point-in-time query against `auth_events`, not a comparison against the tenant's current admin set** (per US-016 RC-13's discipline that a current-set comparison produces false negatives on the escalation case — the actor may since have become an admin themselves):

```sql
SELECT
    BIN_TO_UUID(ae.id)                                       AS event_id,
    ae.created_at,
    BIN_TO_UUID(ae.user_id)                                  AS revoked_user_id,
    JSON_UNQUOTE(JSON_EXTRACT(ae.metadata, '$.revokedBy'))   AS revoked_by_user_id,
    JSON_UNQUOTE(JSON_EXTRACT(ae.metadata, '$.roleId'))      AS role_id,
    JSON_UNQUOTE(JSON_EXTRACT(ae.metadata, '$.roleName'))    AS role_name
FROM auth_events ae
WHERE ae.tenant_id  = UUID_TO_BIN(?)     -- one tenant_id from step 1
  AND ae.event_type = 'ROLE_REVOKED'
ORDER BY ae.created_at;
```

Read the output in order: the revocation(s) nearest the point the tenant's admin-equivalent holder count reached zero, and `revoked_by_user_id`, are the attribution this sweep exists to produce. `auth_events` is append-only and unfiltered by feature-flag era, so this query surfaces revocations from **before** US-016's gate existed just as readily as after.

**Step 3 — retain the output as dated evidence.** Save the full result of **both** queries above (the affected-tenant list from step 1, and the per-tenant attribution from step 2), dated, per `docs/features/US-017/03-design.md` §9.4's retention mandate (**≥ 1 year**, `docs/observability-standards.md`: "Retention: minimum 1 year"). The widened indicator begins reporting this same population on its very first poll after deploy; this dated "before" snapshot is the only way to distinguish a pre-existing, already-triaged tenant from a genuinely new incident (step 6 above).

**Step 4 — a stated action, per affected tenant, before the production deploy step.** For every tenant identified in step 1: either open a remediation ticket with a DBA owner, **or** obtain and record written acceptance that no action will be taken. **Do not proceed to production deploy (`03-design.md` §10.3 step 5) with an affected tenant that has neither** — an unowned finding at that point becomes an unowned page for a condition the team already knew about, which is the fastest way to train operators to ignore this indicator.

**Verification status of this SQL:** written and reviewed against the shipped schema (`V2__identity_schema.sql`'s `auth_events`, `V5__rbac_schema.sql`'s `roles`/`role_permissions`/`permissions`/`user_roles`) and the shipped audit adapter (`RbacAuthEventAdapter`'s `ROLE_REVOKED` metadata shape: `traceId`, `roleId`, `roleName`, `revokedBy`). **Not yet executed against a real staging database** — that execution, and recording its result here or in the deployment record, is required before this sub-item's Definition of Done is satisfied.

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
