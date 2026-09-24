# US-016 — Runbook

**Feature:** Privilege-based role-assignment gate on `assign()`/`revoke()`, the denial throttle (D14), the composed lock-hold timer (D18), and the mint-side holder-count signal (D13).
**Audience:** on-call engineer, no prior context on this story.
**Companion doc:** `docs/features/US-016/monitoring.md` (metric/alert reference); `docs/features/US-012/monitoring.md` and `docs/features/US-015/monitoring.md` (the pre-existing signals this story extends).

---

## 1. Alert: `nexus_rbac_gate_bypass_canary` firing — the gate-bypass procedure

**Severity: page.**

**Mandatory caveat before you do anything else, quoted from the design (§9.3(b), RC-11.2), extended by US-017 (D24/RC-17.3) to name the one thing still shared:** *"this canary can only ever detect a bypass **inside** the gate's own logic — M5[b] answering the wrong question (T-E22's two fail-open axes, or an M8 resolution bug). It cannot detect a bypass **around** the gate,* because on the success path `privileged="true"` implies the gate ran and passed."* **Do not treat a *non*-firing canary as proof the gate cannot be bypassed by some new code path that skips `RoleAssignmentService` entirely — it says nothing about that.** As of US-017, one further thing is shared between the gate and the canary and must be named the same way: **the ANY/ALL combinator itself, `RbacAdminEquivalence.isFullyAdminEquivalent`** — both the gate (via M10's tenant-scoped read) and the canary (via M12's user-scoped read, below) call the same domain predicate, so a defect **in that predicate** corrupts both together and this canary stays silent. Everything else about the gate's decision — which rows are read, from which index, with which scoping — is now independently re-derived by the canary and *is* covered by "inside" above; the shared combinator is the one exception, and it is a small, dedicated-unit-tested, pure domain function, not a query.

**Re-derived twice, in two different eras — read both, not just the most recent:**

**Fixed per M-2 (`docs/features/US-016/07-security-review.md`):** `callerIsAdmin` used to be inferred from `privileged` (the gate's own control-flow variable), making `"false"` unreachable by construction. It was changed to an independent, name-based re-derivation via `callerHoldsActiveTenantAdmin(actor)` — a non-locking M4 projection over the caller's own active role names — so it could disagree with the gate's locking read and surface a T-E22-class bug.

**Re-derived again per US-017 (D24/RC-17.3), because FR-3 made the name-based re-derivation itself produce false positives:** after US-017, a fully admin-equivalent caller (one holding all three dangerous permissions, not the literal `TENANT_ADMIN`) legitimately passes the gate while the *name-based* helper still says `false` — which would have made this canary page on a **legitimate** operation. `callerIsAdmin` is therefore re-derived a second time, against the caller-side predicate the gate now actually asks: a **new, independent, non-locking read — M12 (`findPermissionNamesForActiveAssignmentsOfUser`)**, keyed by the caller's own user id and driven off `fk_user_roles_user` — a different index, a different statement and a different scoping from the gate's own M10 (tenant-scoped, driven off `r.tenantId`). The canary then applies `RbacAdminEquivalence.isFullyAdminEquivalent` to its own M12 result, independently of the gate's M10-derived caller-qualifying set. **No input is shared with the gate** — only the combinator (see the caveat above). `callerIsAdmin="false"` on the `privileged="true"` series remains a **genuinely reachable, meaningful signal**: it now fires only when the gate's M10-derived decision and the canary's own M12-derived decision disagree about the *same* caller, which is exactly what an over-broad M10 result (US-017 T-E29) or a T-E22-class fail-open bug would look like. Treat a firing the same way as before (maximally anomalous, first response step below unchanged).

**Procedure:**

1. Identify the tenant and actor from `nexus.rbac.self_role_assignment{privileged="true", callerIsAdmin="false"}`'s labels (the counter carries `tenantId`; correlate `actorUserId` from the `RBAC_SELF_ROLE_ASSIGNMENT` WARN emitted at the same call site, `RoleAssignmentService.java:234-239`).
2. **First response step (mandatory, do this before anything else):** query `auth_events` for whether the actor held an active `TENANT_ADMIN` assignment at the instant of the self-assignment:
   ```sql
   SELECT ur.assigned_at, ur.revoked_at
   FROM user_roles ur JOIN roles r ON r.id = ur.role_id
   WHERE ur.user_id = UUID_TO_BIN(?) AND r.tenant_id = UUID_TO_BIN(?) AND r.name = 'TENANT_ADMIN'
     AND ur.assigned_at <= ?
     AND (ur.revoked_at IS NULL OR ur.revoked_at > ?);
   ```
   (`?` in order: actor's user id, tenant id, the self-assignment's `assignedAt`, the same timestamp twice.) Zero rows means the actor was **not** an active admin at that instant — a live gate bypass.
3. **If step 2 confirms no active admin assignment:** flip `feature.nexus-us012-rbac-role-assignment.enabled` to `false` in the affected environment and page Security immediately. This is the fastest kill switch — see §5 below for exactly what it does and does not undo.
4. **If step 2 confirms the actor *was* an active admin:** the tag's control-flow assumption was violated somehow (a code change, a race, or a bug in this very instrumentation) even though the authorization outcome was correct. This is still worth escalating — it means the canary's own reliability is compromised — but it is not itself evidence of an authorization bypass. Escalate to the `RoleAssignmentService` owner to investigate the tagging code, not the gate logic.
5. Do **not** close this out as a false positive without completing step 2. The alert's entire value is that, as far as this task's code review could determine, it should not be able to fire from any currently-reachable path — an occurrence deserves the same scrutiny as a canary that should never sing.

---

## 2. Alert: `nexus_rbac_dangerous_permission_granted_to_holders` firing — the D13 holder-count review procedure

**Severity: ticket.** Per `docs/features/US-015/monitoring.md` §2: an admin attached a dangerous permission (`role:write`/`user:write`/`tenant:write`) to a role that **already had active holders** at that instant — every one of them is now silently admin-equivalent, with no gate re-evaluation (this is US-016's RES-1(b)/T-E21 residual, mitigated by visibility, not closed).

**Procedure:**

1. Identify the role, tenant, and grantor from the `RBAC_DANGEROUS_PERMISSION_GRANTED_TO_EXISTING_HOLDERS` WARN (`RoleManagementService.java:221-230`; fields `tenantId`, `roleId`, `roleName`, `permissionId`, `permissionName`, `grantedBy`, `holderCount`).
2. List the holders using §6's Step 2 SQL below, with this `role_id`.
3. For each holder, confirm with the tenant whether they are expected to now carry this permission. This is a **review-and-record** procedure, not an incident by default — the attach itself is a legitimate, admin-gated action (D13 does not block it).
4. If any holder's new admin-equivalent authority is **not** expected: treat it as a live escalation and revoke that holder's assignment of the role via the still-live `DELETE /api/v1/users/{userId}/roles/{roleId}` (US-012). No flag flip is required — the API remains functional; only the specific offending assignment needs to change.
5. Note the outcome of the review in whatever tracking this org uses for security review records, regardless of outcome — this creates the durable trail that a review happened, following the precedent in `docs/features/US-015/runbook.md` §3.

---

## 3. Alert: `nexus_rbac_denial_throttle_engaged` firing — the throttle procedure, including RES-11

**Severity: page** *(promoted from ticket — `docs/features/US-016/07-security-review.md` M-1)*. Per `docs/features/US-012/monitoring.md` §2: one actor produced ≥ `max-denials` (default 5) gate denials inside `window-seconds` (default 60) and is now being short-circuited to 403 before the gate itself runs.

**Why this is now page, not ticket:** the throttle key `(tenantId, actorUserId)` is the attacker's own identity, so the attacker — not the defender — chooses when suppression begins. Burning a few cheap `matchedOn="ROLE_NAME"` denials first enters the suppressed state before ever attempting a `DANGEROUS_PERMISSION` change; every such attempt for the rest of the window then produces **no** WARN, **no** `privileged_role_change_blocked` increment, and **no** durable `ROLE_ASSIGNMENT_DENIED` row — the page-severity `nexus_rbac_privileged_role_change_blocked_dangerous` alert cannot fire on it. Do **not** assume, as this runbook previously did, that a `DANGEROUS_PERMISSION` attempt always precedes the throttle trip and therefore always pages separately on its own — nothing forces that order. Promoting this alert closes the gap: on-call is now paged the moment suppression begins, regardless of what the attacker attempted first, even though which specific denials were suppressed (and whether any were the dangerous-permission shape) is still only recoverable by correlating the durable rows in step 2 below.

**Procedure:**

1. Identify the actor from the single `RBAC_DENIAL_THROTTLE_ENGAGED` WARN (`RoleAssignmentService.java:497-504`; fields `tenantId`, `actorUserId`, `operation`, `maxDenials`, `windowSeconds`) — emitted exactly once, on the transition into the throttled state, not per suppressed request.
2. Correlate to the ≤ `maxDenials` durable `ROLE_ASSIGNMENT_DENIED` audit rows that precede it (these were fully processed before the throttle engaged — WARN, `privileged_role_change_blocked` counter, and audit row all exist for each). If any carried `matchedOn="DANGEROUS_PERMISSION"`, they already triggered `nexus_rbac_privileged_role_change_blocked_dangerous` separately. **Do not stop here if none did** — treat this page itself as the primary detection for whatever the actor attempted *after* the trip, since those attempts left no durable row of their own to inspect.
3. **RES-11(a), expected and self-clearing — do not treat this as a bug:** because the throttle check runs before M7 (which is what lets it bound the lock and the reads), the same actor is also denied `assign()`/`revoke()` of **benign** roles for the remainder of the window, even ones that would have succeeded. This is accepted collateral, bounded at `windowSeconds` (default 60s), and clears automatically. If a legitimate operator reports being unable to make an unrelated, benign role change during this window, this is the expected explanation — no intervention needed, it resolves itself. It is not, on its own, a reason to stand down from this page.
4. Escalate always if: the pattern repeats across multiple windows for the same actor (possible sustained probing — treat as RES-8's privilege-oracle risk), or if any of the preceding denials were the dangerous-permission shape, or if step 2 cannot rule out a suppressed dangerous-permission attempt.

**Multi-replica deployments — RES-11(c), `07-security-review.md` M-3.** The `max-denials`/`window-seconds` bound in `monitoring.md` §3 is enforced per replica under the default `InMemoryRateLimitStore` (`nexus.security.rate-limit.store-type` unset): in an N-replica deployment the actual bound is `max-denials × N` fully processed denials per window, not the single-replica figure. Before running this story's flags `true` in any multi-replica environment, either set `nexus.security.rate-limit.store-type=redis` (makes the denial count cluster-wide; the throttled-until transition map stays per-replica regardless, per RES-11(a)) or divide `max-denials` by the replica count to hold the documented single-replica bound.

> **Cited as a deployment prerequisite by US-017 §7.3, not general guidance — read this instruction as load-bearing, not optional, for any multi-replica deployment of that design.** After US-017 D7 ships, `assign()` takes the same union lock `revoke()` does, **before** the authorization decision, on both verbs — so this throttle is the **only** bound on US-017 RES-19 (a tenant-wide exclusive lock forced by any `user:write` holder who is about to be denied). That makes RES-11(c)'s per-replica caveat above load-bearing for US-017's design specifically, not just a nice-to-have optimisation: on a multi-replica deployment, `store-type=redis` (or dividing `max-denials` by replica count) is a **precondition for the documented throttle bound to hold at all** once both flags are `true`, not a tuning knob to revisit later. See `docs/features/US-017/03-design.md` §7.3 and `docs/features/US-017/monitoring.md` (Phase 8) for the corresponding `{operation="assign", outcome="denied"}` series this throttle bounds.

---

## 4. RES-5 — what pool pressure looks like on the revoke path, and what it does not do

**Under connection-pool exhaustion or contention, the observable symptom is a slow 403 plus `RBAC_AUDIT_WRITE_LOST` — never a hang, and never a wrong authorization outcome.** Quoted from the threat model (`03b-threat-model.md` line 396): *"`RbacAuditPort`'s never-throw contract means pool exhaustion degrades to a slow 403 plus `RBAC_AUDIT_WRITE_LOST`, never a hang or a wrong authorization outcome (RES-5)."*

Why this is the shape, not something worse: `revoke()`'s privilege-gate denial writes its audit row inline, in a `REQUIRES_NEW` transaction on a **second** pooled connection, while M1's X lock on the tenant's admin rows is still held (§7.5). If the pool is under pressure at that moment, borrowing the second connection is what's slow — and `RbacAuditPort`'s contract is to never throw, so a slow or failed audit write degrades to `RBAC_AUDIT_WRITE_LOST` (ERROR) plus a slightly slower 403, not to an exception that changes the authorization decision or leaves the request hanging indefinitely. D14 bounds how often this path is reachable at all — a throttled actor never gets far enough to acquire M1 or attempt the second-connection audit write.

**If you see this symptom (slow 403s on `assign()`/`revoke()` correlated with `RBAC_AUDIT_WRITE_LOST` and/or HikariCP pool-exhaustion signals):** this is a capacity/availability issue, not a security incident — the gate's authorization outcome is unaffected. Investigate pool sizing and concurrent privileged-revoke volume for the affected tenant(s); do not treat it as a candidate for the kill switch below unless request latency itself becomes the incident.

---

## 5. Kill switch — and why flag-off is an availability lever, not a security one

**No new feature flag exists in this story (D10).** Both affected endpoints sit behind the pre-existing kill switches:

- `feature.nexus-us012-rbac-role-assignment.enabled` — gates `UserRoleController` (both `assign`/`revoke` verbs). Default `false` (`application.yml:223`).
- `feature.nexus-us015-rbac-role-management.enabled` — gates `RoleController`, including `attachPermission` (D13's signal). Default `false` (`application.yml:228`).

**To stop the gate (or the throttle, or the D13 signal) from being reachable at all:** flip the relevant flag to `false` and redeploy/restart. Spring omits the controller beans; requests 404.

> **⚠ Flag-off is not a privilege rollback — it is an availability lever, not a security one (§10.3 rollback note, handed over from T-013).** Assignments already granted **stay effective** — flipping the flag does not re-validate or revoke anything. Disabling the flag **re-opens** the pre-US-016 escalation path (no privilege gate on assign/revoke) rather than closing it. If the gate itself is suspected of a bypass (§1 above), flipping the flag stops *new* privileged role changes from reaching the gate's own code at all — it does not undo any change already made, and it does not make the tenant's current role assignments any safer than they already were.

**Consequence for §1's escalation path:** the kill switch in §1 step 3 is the right immediate action *because* it removes the entire code path the suspected bypass runs through — not because it reverses anything the bypass may have already done. Follow §6's exposure audit separately if a bypass is confirmed.

---

## 6. Forward-only, and the exposure audit (§10.4) — the complete SQL, why the point-in-time check matters, and the accepted blind spots

**Release-note sentences — both required, verbatim from the design, because shipping only the first invites "the escalation gap is closed" to be misread as "existing escalated assignments were revoked":**

> Pre-existing assignments of admin-equivalent roles survive this deployment and keep conferring their permissions. This change gates **new** assign/revoke operations only; it does not re-validate or revoke anything already granted.

> This change does **not** prevent a role that a user already holds from later being given an admin-equivalent permission by an administrator. That path remains open by design (US-016 RES-1(b) / T-E21); what changes is that it is now recorded and alertable at the moment it happens (holder count on `ROLE_PERMISSION_GRANTED`).

**No backfill, no remediation, no migration exists for this. The audit below is the one-off tool for the historical component (RES-1(a)); it does nothing for the standing primitive (RES-1(b)), which D13's signal (§2 above) is the only mitigation for.**

**The one-off exposure audit — executable by a DBA, no Java, no endpoint, no admin console in the loop:**

```sql
-- Step 1: every role in every tenant currently carrying an admin-equivalent permission.
SELECT r.tenant_id, r.id AS role_id, r.name, p.name AS permission
FROM roles r
  JOIN role_permissions rp ON rp.role_id = r.id
  JOIN permissions p       ON p.id = rp.permission_id
WHERE p.name IN ('role:write', 'user:write', 'tenant:write');

-- Step 2: for each role_id from step 1, its current active holders.
SELECT BIN_TO_UUID(user_id) AS user_id
FROM user_roles
WHERE role_id = UUID_TO_BIN(?) AND revoked_at IS NULL;

-- Step 3a: POINT-IN-TIME legitimacy check against ROLE_ASSIGNED history -- NOT against the
-- current admin set. For each (role_id, user_id) from step 2, find the grant event.
SELECT ae.created_at,
       JSON_UNQUOTE(JSON_EXTRACT(ae.metadata, '$.roleId'))     AS role_id,
       JSON_UNQUOTE(JSON_EXTRACT(ae.metadata, '$.assignedBy')) AS grantor_user_id,
       BIN_TO_UUID(ae.user_id)                                 AS target_user_id
FROM auth_events ae
WHERE ae.event_type = 'ROLE_ASSIGNED'
  AND ae.tenant_id  = UUID_TO_BIN(?)
  AND JSON_UNQUOTE(JSON_EXTRACT(ae.metadata, '$.roleId')) = ?
ORDER BY ae.created_at;

-- Step 3b: for each grantor_user_id / created_at pair from step 3a, the
-- admin-status-at-that-time question.
SELECT ur.assigned_at, ur.revoked_at
FROM user_roles ur JOIN roles r ON r.id = ur.role_id
WHERE ur.user_id = UUID_TO_BIN(?) AND r.tenant_id = UUID_TO_BIN(?) AND r.name = 'TENANT_ADMIN'
  AND ur.assigned_at <= ?                                 -- the grant's created_at
  AND (ur.revoked_at IS NULL OR ur.revoked_at > ?);       -- the grant's created_at
-- Zero rows ⇒ the grantor was NOT an admin when they made the grant ⇒ exposure-window artefact.
```

**Why the point-in-time check (step 3) replaced comparing grantors against the tenant's *current* admin set — state this so nobody reverts to the simpler query:**

Comparing `assigned_by` against the tenant's *currently active* `TENANT_ADMIN` holders produces two distinct failure modes, not one:

1. **False negatives on exactly the escalation case.** An attacker who has since *become* an admin — legitimately, or via the very escalation this audit is hunting for — is present in the current admin set, so their historical illegitimate grants are silently cleared by a current-set comparison. This is the worse of the two failures: it hides the exact thing the audit exists to find.
2. **False positives on legitimate history.** An administrator who has since offboarded is no longer in the current set, so every grant they ever legitimately made while they *were* an admin gets flagged as suspicious, burying the real signal in noise and training reviewers to ignore the audit's output.

The point-in-time check (steps 3a/3b) asks the only question that is actually meaningful: was the grantor an active admin **at the moment they made the grant**? That is invariant to what has happened to their admin status since.

**Accepted blind spots — no query fixes these, so do not go looking for one (RC-13.4):**

1. **Currently-active-only visibility.** The audit sees only currently active assignments (`user_roles.revoked_at IS NULL`). A revoked escalation leaves no row to find in step 2 — the actor may have held admin-equivalent authority for a period and given it up. Only `ROLE_ASSIGNED`/`ROLE_REVOKED` history shows this, and only within retention.
2. **Currently-dangerous-only visibility.** Step 1 finds only roles that are **currently** carrying a dangerous permission. A role that was dangerous and has since had the permission detached is invisible to step 1 — reconstructing that requires `ROLE_PERMISSION_GRANTED`/`ROLE_PERMISSION_REVOKED` history, which (post-D13) at least now carries the holder count at grant time going forward.
3. **This audit is a one-off.** It discharges the historical component, RES-1(a). It does nothing about RES-1(b)'s standing primitive (the attach-after-assign path) — that is D13's job (§2 above), and D13 is detection, not prevention.

**Verification note (this task, T-022, 2026-09-16):** all four statements above were run once, exactly as written with literal placeholder UUIDs substituted for the `?` JDBC parameters, against a local MySQL 8.4 instance provisioned via this repo's `docker-compose.yml` `mysql` service, with `V1`–`V5` Flyway migrations applied. All four executed without SQL error (0 rows for steps 2/3a/3b, since no seeded data matched the placeholder UUIDs used; step 1 returned the seeded `TENANT_ADMIN` system role's three dangerous-permission rows, confirming the join is correct against real data). **This is a local validation that the SQL is executable against the shipped schema — it is not the staging-database run this task's own testing requirement calls for**, because no staging environment was available in this session. Re-run against actual staging data before relying on this audit for a real investigation; do not treat this note as satisfying that requirement.

---

## Cross-reference

- `docs/features/US-016/monitoring.md` — metric names, alert expressions, the lock-hold baseline (pending measurement), and the canary's mechanism caveat referenced in §1 above.
- `docs/features/US-016/03-design.md` §7.5 (D18 timer), §9.3 (alerting, the canary's "inside, not around" caveat), §10.2–§10.4 (rollout, kill switch, exposure audit), §12.3 (residual risks, RES-1(b)/RES-4+RES-5/RES-11).
- `docs/features/US-016/03b-threat-model.md` — T-E21, T-E22, RES-1(b), RES-4+RES-5, RES-11, RES-5's slow-403 note.
- `docs/features/US-012/monitoring.md`, `docs/features/US-015/monitoring.md` — the pre-existing signals this story extends; read together with this document for the full observability picture.
