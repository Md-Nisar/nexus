# US-012 — Deployment Checklist

**Feature:** Enable role assignment and revocation API (`POST`/`GET /api/v1/users/{userId}/roles`, `DELETE /api/v1/users/{userId}/roles/{roleId}`)
**Epic:** EPIC-002 RBAC Foundation
**Type of change:** Additive-only. No new Flyway migration, no new env vars, no new DB grants, zero frontend changes. Primary risk surface is a new, genuinely privileged endpoint gated by a feature flag defaulted `false`.
**Full context:** `docs/features/US-012/deployment.md` (detailed rationale), `03-design.md` section 10 (rollout/rollback plan), `07-security-review.md`, `08-test-audit.md`. This checklist is the execution sequence; it cross-references those documents rather than repeating their reasoning.

---

## 0. Outstanding precondition (must close before this checklist starts)

- [ ] BLOCKING - nothing on `feature/US-012` is committed to git yet. Commit all working-tree changes, push the branch, and open the PR against `main`. Owner: **[ASSIGN: Feature Author]**
- [ ] PR reviewed and approved (standard code review, separate from the Phase 6/7 audits already done pre-commit). Owner: **[ASSIGN: Code Reviewer]**
- [ ] Confirm `06-code-review.md` (APPROVE WITH NITS) and `07-security-review.md` (APPROVED) verdicts are still current against the final commit. Owner: **[ASSIGN: Release Manager]**

---

## 1. Pre-deploy

### Build artifacts
- [ ] Merge PR to `main`. Record the merge commit SHA — this is the **backend build artifact identifier** (`nexus-backend-<version>-<sha>.jar`, per `docs/deployment-process.md` "Build Artifacts": Maven produces an immutable jar tagged with the commit SHA, same jar promotes dev to staging to prod). Owner: **[ASSIGN: Release Manager]**
- [ ] Confirm CI pipeline green end-to-end on the merge commit: Build, Unit Tests (226), Integration Tests (203, Testcontainers MySQL+Redis), JaCoCo coverage gates, SpotBugs (0 bugs), Checkstyle, Security Scan. Owner: **[ASSIGN: CI/Build Owner]**
- [ ] Run `.github/workflows/security.yml` via `workflow_dispatch` for authoritative NVD-backed A06 dependency evidence — the Phase 7 review's backend scan did not complete locally (no NVD API key configured) and substituted a manual CVE inventory (198 artifacts, zero new/drifted, no CVSS >= 7 found manually). This is security-review Condition 4 (`07-security-review.md` §4) and should complete before merge if the workflow run fits the timeline; otherwise complete before the flag is flipped to `true` in any environment beyond `dev`/`test`. Owner: **[ASSIGN: Security Reviewer]**
- [ ] Frontend: no build required. `02-impact.md` §1.6 and `08-test-audit.md` both confirm zero frontend files touched by this story. Record "N/A — no frontend artifact" explicitly so the deploy record isn't misread as an omission. Owner: **[ASSIGN: Release Manager]**

### Database / Flyway (ADR 0003, `ddl-auto=validate`)
- [ ] No new Flyway migration ships with this story. `V5__rbac_schema.sql` already carries every column/index/constraint/trigger this feature needs on `user_roles` (`id`, `user_id`, `role_id`, `tenant_id`, `assigned_by`, `assigned_at`, `revoked_at`, `active_key`, `uq_user_role_active`, the `revoked_at >= assigned_at` CHECK, `BEFORE DELETE` trigger). Confirm no new `V<N>__*.sql` file is present in the merge diff. Owner: **[ASSIGN: Backend Lead]**
- [ ] Non-additive-change review: not applicable. This is a pure additive/behavioral change against existing schema — no expand/contract review is triggered (`docs/deployment-process.md` "Schema Management"). Record this explicitly rather than silently skipping it. Owner: **[ASSIGN: Backend Lead]**
- [ ] Confirm `nexus_app` DB grants are unchanged and already cover every operation this story performs (`SELECT` on `roles`/`permissions`/`user_roles`/`users`, `INSERT` on `user_roles`, column-scoped `UPDATE (revoked_at)` on `user_roles`, `INSERT`/`SELECT` on `auth_events`) — no `GRANT` statement runs as part of this deploy. Verify via `UserRolesPrivilegeIT` (already green in CI) plus a manual `SHOW GRANTS FOR 'nexus_app'@'%'` check against the target environment before flipping the flag there. Owner: **[ASSIGN: DBA / DB Platform Owner]**
- [ ] Post-deploy (flag still `false`), confirm `rbacDbPrivilege` on `/actuator/health` reports UP in the target environment before proceeding to flag enablement. Owner: **[ASSIGN: Deploy Engineer]**

### Config / feature flag
- [ ] Confirm `feature.nexus-us012-rbac-role-assignment.enabled` is present with the correct value per environment (no new env var — this is a config property only):

  | Environment | Required value | Source |
  |---|---|---|
  | `dev` | `true` | `application-dev.yml` (already committed) |
  | `test` | `true` | `application-test.yml` (already committed) |
  | `staging` | `true` (per rollout step 2, `03-design.md` §10.2) | Staging config override |
  | `production` | `false` at initial deploy | `application.yml` default — do not override at first deploy |

  Owner: **[ASSIGN: Deploy Engineer]**
- [ ] Known trap, documented in `deployment.md` §3: the flag must be set via profile YAML / externalized config, not via a `DynamicPropertyRegistrar`-style mechanism — `@ConditionalOnProperty` on a `@Component` bean evaluates during component scan, before such contributions are visible. If this trap is hit, the controller silently stays absent even with the "flag" apparently set. Owner: **[ASSIGN: Deploy Engineer]**
- [ ] No other new config / env vars for this story (`deployment.md` §1, §6 — confirmed zero). Record "N/A" explicitly. Owner: **[ASSIGN: Release Manager]**

### Secrets
- [ ] None rotated or added. No new Vault path, no new credential, no new key material (`07-security-review.md` §0 — no key material, no hashing, no encryption touched). Record "N/A" explicitly. Owner: **[ASSIGN: Security Reviewer]**

### Rollout gate before flipping the flag to `true` beyond `dev`/`test` (carried from `07-security-review.md` M-1/M-2 — tracked as staging-to-production exit criteria, not merge blockers)
- [ ] Set `management.endpoint.health.roles` to an operator-only role so `/actuator/health`'s detail payload (cross-tenant `tenantIds` from `rbacZeroActiveAdmins`, DB account name from `rbacDbPrivilege`) is not readable by every authenticated user of every tenant (M-1). Owner: **[ASSIGN: Security Reviewer]** / **[ASSIGN: Platform Config Owner]**
- [ ] Set `management.endpoint.health.cache.time-to-live` (or move `RbacZeroActiveAdminsHealthIndicator`'s query to a `@Scheduled` gauge) so the cross-tenant admin scan does not re-run on every unauthenticated `/actuator/health` hit (M-2). Owner: **[ASSIGN: Backend Lead]**
- [ ] Confirm both fixes above are live in the target environment before the flag is set `true` there. Owner: **[ASSIGN: Release Manager]**

### Communication
- [ ] Notify stakeholders (Product Manager, Tenant Admin support/CS if applicable, on-call rotation) of the deploy window, the flag-gated rollout plan (dev/test to staging soak to production, per `03-design.md` §10.2), and that production traffic will see no behavior change at merge time (flag stays `false`). Owner: **[ASSIGN: Release Manager]**
- [ ] Share this checklist set (`10-release/*`), `runbook.md`, and `monitoring.md` links with the on-call rotation before the staging soak begins. Owner: **[ASSIGN: Release Manager]**
- [ ] Notify EPIC-002 owner / PM that M-3 (`07-security-review.md`) — AC8 gates the role name, not the privilege — must be a blocking entry criterion for the custom-roles story (US-015), not silently forgotten. Owner: **[ASSIGN: Product Manager]**

### Smoke test plan
- [ ] Confirm `smoke-test-checklist.md` (this directory) is reviewed and the on-call/deploy engineer executing the deploy knows how to run it before proceeding. Owner: **[ASSIGN: QA Lead]**

---

## 2. During deploy

- [ ] Deploy the merge-commit artifact to `dev` (auto, per CI/CD pipeline) — flag already `true` there; this is continuous, not a discrete event for this story. Owner: **[ASSIGN: CI/Build Owner]**
- [ ] Promote to `staging` manually. Flip `feature.nexus-us012-rbac-role-assignment.enabled=true` in staging only after confirming the app connects as `nexus_app`, not a superuser (`03-design.md` §10.2 step 2). Owner: **[ASSIGN: Deploy Engineer]**
- [ ] In staging, verify: manual assign + revoke succeed; MySQL error log free of `command denied`; `revoked_at >= assigned_at` with non-zero microseconds; `EXPLAIN` on the AC5 lock query shows the `role_id`-driven index, not a full scan. Owner: **[ASSIGN: Backend Lead]**
- [ ] Run the staging soak (`03-design.md` §10.2 step 3): the 8-thread concurrent-revocation harness equivalent against staging, plus an Epic-3-style client walkthrough. Gate to proceed: zero 5xx, zero tenants with 0 active admins, p95 under 300 ms at 200 RPS (the epic's inferred bar — see `production-readiness-report.md` for the caveat that this has not yet been load-tested). Owner: **[ASSIGN: QA Lead]** / **[ASSIGN: Backend Lead]**
- [ ] Execute the rollback drill in staging before production enablement — flip the flag back to `false` in staging, confirm all three endpoints return `404`, confirm no data corruption, confirm dashboard traffic drops to zero on the three URIs. See `rollback-checklist.md`. This has not yet been performed as of this release-prep pass — treat as a hard gate, not a formality. Owner: **[ASSIGN: Release Manager]**
- [ ] Deploy the same artifact to `production` with the flag `false` (default in `application.yml` — no override needed). This step is low-risk: it adds a conditionally-absent controller bean and touches no existing behavior. Two-person rule applies per `docs/deployment-process.md` (one deploys, one watches dashboards). Owner: **[ASSIGN: Deploy Engineer]** (deploying) / **[ASSIGN: On-call Engineer]** (watching)
- [ ] Confirm no deploy occurs on a Friday or during business peak hours (08:00-10:00, 17:00-19:00 local) without sign-off, per `docs/deployment-process.md` Deployment Rules. Owner: **[ASSIGN: Release Manager]**
- [ ] Flip the flag to `true` in production only after: staging soak green, the M-1/M-2 config fixes are live in production, the rollback drill (above) has been performed at least once, dashboard + all 5 alerts (`monitoring.md` §2) are live, and `runbook.md` is merged and linked from the on-call rotation's tooling (`03-design.md` §10.2 step 4). Owner: **[ASSIGN: Release Manager]** (decision) / **[ASSIGN: Backend Lead]** (technical confirmation)

---

## 3. Post-deploy

- [ ] Run `smoke-test-checklist.md` in full against production immediately after the code deploy (flag `false`) and again immediately after any later flag flip to `true`. Owner: **[ASSIGN: On-call Engineer]**
- [ ] Confirm `rbacDbPrivilege` and `rbacZeroActiveAdmins` both report UP in `/actuator/health` for the deployed environment. Owner: **[ASSIGN: On-call Engineer]**
- [ ] Confirm the "RBAC / Role Assignment" dashboard row (`monitoring.md` §4) renders with zero traffic while the flag is `false`, and begins showing traffic once the flag flips `true` — an unexpectedly-empty dashboard after a flag flip is the first sign the flag-in-YAML trap (§1 above) was hit. Owner: **[ASSIGN: On-call Engineer]**
- [ ] Watch period: minimum 24h after each flag flip (dev/test excluded), per `docs/deployment-process.md` and `03-design.md` §10.2 step 5. Full detail in `monitoring-checklist.md`. Owner: **[ASSIGN: On-call rotation]**
- [ ] Capture baseline p50/p95/p99 latency and steady-state denial/conflict rates during the staging soak and record them in `monitoring.md` §6 (currently marked "not yet captured") before flipping the flag to `true` in production. Owner: **[ASSIGN: Backend Lead]**
- [ ] Confirm a production Jira deployment record is created, per `docs/deployment-process.md`. Owner: **[ASSIGN: Release Manager]**
- [ ] Close the loop with stakeholders notified in §1: confirm deploy completed, flag state per environment, and the production rollout timeline (steps 1-5 pace is evidence-gated, not calendar-gated). Owner: **[ASSIGN: Release Manager]**

---

## Cross-references

- `docs/features/US-012/deployment.md` — full deployment rationale (DB, flag, SpotBugs exclusions, observability wiring)
- `docs/features/US-012/03-design.md` §10 — rollout/rollback plan this checklist executes
- `docs/features/US-012/07-security-review.md` — M-1/M-2/M-3/L-7 follow-up items referenced above
- `docs/features/US-012/08-test-audit.md` — CI run results (429/429 tests, JaCoCo/SpotBugs/Checkstyle)
- `docs/deployment-process.md` — org-wide deployment process, environments, deployment rules
- `docs/features/US-012/10-release/rollback-checklist.md`, `smoke-test-checklist.md`, `monitoring-checklist.md`, `production-readiness-report.md`
