# US-012 — Rollback Checklist

**Feature:** Role assignment / revocation API (`POST`/`GET`/`DELETE /api/v1/users/{userId}/roles[/{roleId}]`)
**Full rationale:** `docs/features/US-012/rollback.md` (detailed reasoning per lever), `03-design.md` §10.3, `runbook.md` (per-alert response procedures). This checklist is the execution sequence.

---

## 1. Trigger conditions

Any of the following should trigger an immediate rollback decision (do not wait for a post-mortem to justify it — per `docs/deployment-process.md`, rollback is a normal operation, not a failure):

| Condition | Threshold | Source |
|---|---|---|
| 5xx error rate on the three RBAC endpoints | `nexus_rbac_role_change_error_rate` alert fires: 5xx/total > 1% over 5 min | `monitoring.md` §2 |
| Latency regression | p95 > 2x the captured staging baseline (or > 600 ms if no baseline captured yet) sustained 5 min | `docs/deployment-process.md` Rollback Policy; `monitoring.md` §6 |
| Self-escalation signal | `nexus_rbac_self_escalation_attempt` fires and, after triage (`runbook.md` §4), is judged a genuine bypass rather than a stale-JWT/benign case | `monitoring.md` §2, `runbook.md` §4 |
| Audit completeness failure | `nexus_rbac_audit_write_lost` fires and points to a broader `auth_events` outage, not an isolated blip | `monitoring.md` §2, `runbook.md` §3 |
| Tenant lockout | `rbacZeroActiveAdmins` health indicator reports DOWN for any tenant and is traced to a bug in this feature | `monitoring.md` §3, `runbook.md` §2 |
| DB privilege regression | `rbacDbPrivilege` reports DOWN, `command denied` found in the MySQL error log correlated with these endpoints | `runbook.md` §1 |
| Any Sev-1/Sev-2 incident traced to this feature | n/a | Standard incident process |

- [ ] Confirm the trigger against the specific alert/health indicator/log line before deciding — do not roll back on a vague "looks off" impression. Owner: **[ASSIGN: On-call Engineer]**

---

## 2. Owner for the rollback decision

- [ ] Decision owner: **[ASSIGN: On-call Engineering Lead / Incident Commander]** — has sole authority to declare a rollback for this feature during the watch period. Two-person rule still applies for the execution step (one executes, one confirms), per `docs/deployment-process.md`.
- [ ] If the trigger is ambiguous (e.g. `nexus_rbac_self_escalation_attempt` firing for a plausibly-benign stale-JWT case), the decision owner consults `runbook.md` §4's triage steps before declaring — this alert is explicitly "not routine noise" but also not an automatic rollback trigger on its own. Owner: **[ASSIGN: On-call Engineering Lead]**

---

## 3. Primary lever: feature-flag kill switch (fastest, no redeploy)

- [ ] Flip `feature.nexus-us012-rbac-role-assignment.enabled` to `false` in the affected environment's config. Owner: **[ASSIGN: Deploy Engineer]**
- [ ] Restart/redeploy the config change (not the code) — or confirm it takes effect without a restart if externalized via a config server. Owner: **[ASSIGN: Deploy Engineer]**
- [ ] Confirm all three endpoints now return `404` (Spring omits `UserRoleController` entirely when the property is absent/`false` — `@ConditionalOnProperty`). Owner: **[ASSIGN: On-call Engineer]**
- [ ] Confirm the "RBAC / Role Assignment" dashboard row traffic drops to zero on the three URIs within a few minutes. Owner: **[ASSIGN: On-call Engineer]**
- [ ] Target: rollback completed in under 5 minutes from decision to confirmed effect, per `docs/deployment-process.md`. Owner: **[ASSIGN: On-call Engineer]**

What this does and does not undo (`rollback.md` §1):
- Removes the three endpoints immediately — no new assignments/revocations possible via this API.
- Does not touch any `user_roles` row already written while the feature was live.
- Does not require a Redis cache flush (see §6 below).
- Existing JWTs minted with roles resolved before the flip remain valid until normal expiry/refresh.

---

## 4. Secondary lever: code rollback (previous artifact)

- [ ] Only invoke if the flag alone is insufficient — e.g. the bug is in a shared dependency this feature exercises differently than before (`TenantAwarePermissionEvaluator`, `RoleResolutionService`), not in this feature's own code. Owner: **[ASSIGN: Backend Lead]**
- [ ] Redeploy the previous artifact: **[ASSIGN: Deploy Engineer to record the pre-US-012 merge commit SHA / prior nexus-backend jar here at deploy time]** — the last artifact deployed to the target environment before this feature's merge commit. Owner: **[ASSIGN: Deploy Engineer]**
- [ ] Same jar/artifact goes to the affected environment — per `docs/deployment-process.md`, artifacts are immutable and SHA-tagged; do not rebuild from source for a rollback. Owner: **[ASSIGN: Deploy Engineer]**
- [ ] No special cross-service sequencing required — this story has zero cross-service dependents (`02-impact.md` §8/§12, modular monolith, additive-only). Owner: **[ASSIGN: Release Manager]**

---

## 5. DB rollback strategy

- [ ] No Flyway migration to reverse. `V5__rbac_schema.sql` predates this story and is untouched by it (`02-impact.md` §2.1) — there is nothing to reverse-migrate. A code revert alone is schema-safe. Owner: **[ASSIGN: DBA / DB Platform Owner]** (confirm, do not action)
- [ ] Irreversible / not undone by any rollback lever: every `user_roles` row written (assigned or revoked) while the feature was live. `user_roles` is append-only by design (`BEFORE DELETE` trigger, no `DELETE` grant for `nexus_app`) — no code path, rolled back or not, un-revokes a row or un-assigns a grant. This is by design, not a gap: each row represents a real administrative action, correct at the time it was written (`rollback.md` §3). Owner: **[ASSIGN: Backend Lead]** (documented, not actioned)
- [ ] If a specific assignment/revocation needs manual correction (e.g. an admin's genuine mistake, not a bug), route through the standard production-data-change approval process — this is an ordinary data correction, not a rollback procedure. Owner: **[ASSIGN: DBA / DB Platform Owner]**
