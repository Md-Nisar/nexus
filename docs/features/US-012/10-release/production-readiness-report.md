# US-012 - Production Readiness Report

_Phase 10 (/release-prep) deliverable - final gate before release. Feature: EPIC-002 RBAC Foundation - US-012, "Enable role assignment and revocation API" (POST/GET /api/v1/users/{userId}/roles, DELETE /api/v1/users/{userId}/roles/{roleId}) - the platform's first genuinely privileged runtime surface and the only control against a Critical self-escalation threat (T-E1, 09-technical.md section 1)._

---

## Gate answers

| Question | Answer | Evidence |
|---|---|---|
| **Is the code reviewed and approved?** | **Yes.** | docs/features/US-012/06-code-review.md - verdict **APPROVE WITH NITS** (2 Medium, 4 Low, zero Blocker/High). |
| **Is the security review passed?** | **Yes, with tracked conditions.** | docs/features/US-012/07-security-review.md - verdict **APPROVED** (3 Medium, 10 Low, zero Blocker/High). All 16 threats from the Gate-2 threat model verified present in the shipped code, not just claimed. Conditions M-1/M-2 are explicitly staging-to-production rollout gates, not merge blockers - see below for why this report treats them as still open. |
| **Are tests green?** | **Yes.** | docs/features/US-012/08-test-audit.md - **429/429 passing** (226 unit + 203 integration, Testcontainers MySQL 8.4 + Redis 7.4). JaCoCo bundle and package gates all met. SpotBugs 0 bugs. Checkstyle clean. One real concurrency bug (TOCTOU escape in the assign path) was found and fixed during this audit, with a regression test added - see 08-test-audit.md section "Bug found and fixed". |
| **Is the migration safe?** | **N/A - no migration ships with this story.** | deployment-checklist.md section 1: V5__rbac_schema.sql (US-009) already carries every column/index/constraint/trigger this feature needs. Confirmed no new V<N>__*.sql file is present in the working tree. Pure additive/behavioral change against existing schema - no expand/contract review triggered. |
| **Is there a rollback path, and what is its actual risk profile?** | **Yes, trivially reversible by design - but not yet exercised.** | rollback-checklist.md / 03-design.md section 10.3: the feature flag is the primary lever (flip to false, endpoints vanish, no redeploy). No Flyway migration to reverse. The only irreversible artifact is user_roles rows written while the feature was live - by design (append-only, real administrative actions correct at the time written), not a gap. **However:** the rollback drill (flip flag to false in staging, confirm all three endpoints 404, confirm no data corruption, confirm dashboard traffic drops to zero) has not actually been performed as of this pass - see "Rollback tested" row below and the Verdict section. |
| **Are DB grants correctly provisioned and verified end-to-end?** | **Yes.** | UserRolesPrivilegeIT (green in CI) connects as nexus_app and asserts the column-scoped UPDATE(revoked_at) grant, FOR UPDATE/FOR SHARE locking behavior, and the exact SHOW GRANTS shape. Deployment-checklist.md section 1 requires a manual SHOW GRANTS re-check against the target environment before flipping the flag there - per-environment, not one-and-done, same caveat US-009's report carried forward. |
| **Are there any open items that must be resolved before or shortly after this ships?** | **Yes - several, all named and owned.** | (1) M-1/M-2 (health-endpoint role restriction, health-cache TTL) must land before the flag is set true in any shared environment - not yet applied anywhere. (2) M-3/T-E9 (AC8 gates the role name, not the privilege) is documented and accepted as unreachable pre-US-015, but is a **blocking entry criterion** for the custom-roles story - flagged to the PM. (3) The rollback drill has not been performed. (4) The NVD-backed dependency scan (security-review Condition 4) did not complete locally (35 min, no NVD API key, cold cache) - a manual CVE inventory was substituted (198 artifacts, zero new/drifted, no CVSS >= 7 found manually), and `.github/workflows/security.yml` should be run via workflow_dispatch for authoritative evidence before merge or, at latest, before the flag is set true beyond dev/test. (5) L-1 (no DataAccessException to 409 handler for lock-wait timeouts) and L-3 (JpaUserDirectoryAdapter materializes a full entity to read one column) are small, well-scoped, non-blocking follow-ups. |
| **Are there any known issues outside this story's scope the deploy team should be aware of?** | **Yes - one.** | L-7 (security review, pre-existing, not introduced by this story): `pom.xml`'s failBuildOnCVSS is 9, above this review's own CVSS>=7 bar, and the security workflow is cron/dispatch-only, not a PR gate. Platform-wide fix tracked separately; the deploy team should not assume merge-time CI enforces the same CVSS bar this review used. |

---

## Standard readiness gate (framework checklist)

| Item | Status | Note |
|---|---|---|
| SLOs defined? (availability, latency, error rate) | **Partially - inferred from the epic, not independently validated for this story** | EPIC-002's own success metrics (docs/story/2-rbac/EPIC-002.md) state "200 RPS on a permission-guarded endpoint, p95 < 300ms" and "RBAC overhead adds < 5ms to p95 API response time" as epic-level bars. This story's own AC set does not restate a numeric SLO, and 08-test-audit.md explicitly skipped load scenarios ("no story AC requires >10 RPS for these three endpoints... no capacity target was set for this story"). The error-rate SLO used operationally is the alert threshold itself: nexus_rbac_role_change_error_rate pages at >1% 5xx over 5 min (monitoring.md section 2), and 03-design.md section 10.2 step 5's watch-period target is <0.1% 5xx sustained. Treat the epic's 200 RPS/p95<300ms figure as the working target, not yet independently confirmed against this specific implementation - see the capacity row below. |
| Capacity validated? (load test results vs. expected traffic) | **No - not yet run.** | No load test has been executed against this feature's three endpoints. 08-test-audit.md's "Load scenarios" section explicitly and deliberately skipped this, consistent with the project's own skill guidance (add load scenarios only where a story AC calls for it) - a reasonable call for the Phase 8 audit's scope, but it leaves the epic's 200 RPS/p95<300ms bar untested at the point this report is written. deployment-checklist.md section 2 and 03-design.md section 10.2 step 3 both name this as a required staging-soak gate before production enablement - it has not happened yet. |
| Dependencies healthy? (downstream service SLAs) | **Yes, N/A for new dependencies** | Zero new dependencies (198 artifacts, byte-identical to the design-phase count, per 07-security-review.md section 3). No new downstream service calls introduced - the feature's only collaborators (MySQL via nexus_app, Redis for cache eviction, the existing auth_events audit pipeline) are pre-existing and already monitored. |
| Backups in place? | **Yes, inherited** | user_roles is an existing table (US-009) already covered by the platform's standing MySQL backup policy - this story adds no new table and no new backup mechanism is needed. |
| Disaster recovery tested? | **Inherited, not independently tested for this story** | Same DR posture as the rest of the schema - no story-specific DR test performed, consistent with this being a behavior-only change with no new data structures. |
| Runbook written? | **Yes** | docs/features/US-012/runbook.md - 4 operational scenarios (DB-privilege-regression 5xx spike, zero-active-admins lockout, audit-write-lost, self-escalation-attempt), each with a concrete first-check and procedure, written for a 3am on-call engineer with no prior context. |
| Security review signed off? | **Yes** | docs/features/US-012/07-security-review.md - **APPROVED**, with the M-1/M-2/M-3/Condition-4 follow-ups tracked as above. |
| Privacy review complete (if applicable)? | **Yes** | 07-security-review.md section 0: grep for email/firstName/lastName/getPasswordHash across the entire rbac package - zero matches. Every DTO field audited; only UUIDs, a role label, and a timestamp are ever returned. No PII exposure introduced. |
| Accessibility review complete (frontend)? | **N/A** | Zero nexus-frontend/ files touched (02-impact.md section 1.6, re-confirmed by 08-test-audit.md by inspecting git status/diff --stat for this branch). |
| i18n complete (if applicable)? | **N/A** | No new user-facing strings; no frontend surface. |
| Feature flag plan defined? | **Yes** | feature.nexus-us012-rbac-role-assignment.enabled, default false (application.yml), true in dev/test only. This is the platform's fastest kill switch for a Critical self-escalation threat (D11, 03-design.md section 10.1) and the primary rollback lever. Rollout plan is evidence-gated, not calendar-gated (03-design.md section 10.2, 5 steps). |
| **Rollback tested at least once in staging?** | **No - not tested.** | See the dedicated discussion below; per this report's own operating rule, an untested rollback is treated as a hard gate, not a soft caveat. |

### On the untested rollback and the uncommitted branch - explicit reasoning, not a default

Weighing this honestly rather than waving it through, the way US-009's report did for its own (structurally different, lower-consequence) rollback gap:

- **This is not the same shape of gap US-009 carried.** US-009's untested rollback was a *hypothetical, never-drafted* DB down-migration for a schema with zero real consumer data - low consequence by construction. US-012's rollback mechanism (the feature flag) is simple and well-reasoned on paper (03-design.md section 10.3: flip to false, Spring omits the controller bean, 404 on all three routes, no data reshaping), but it is the **primary defense mechanism for a Critical, already-shipped-adjacent privilege-escalation surface** - deployment-checklist.md itself calls the drill "a hard gate, not a formality," and this report agrees. A kill switch that has never actually been flipped in anger, against this specific code, carries meaningfully more risk than an unused schema-rollback script for an inert table.
- **The drill is cheap and well-specified** (flip the flag false in staging, confirm 404 on all three URIs, confirm no data corruption, confirm dashboard traffic drops to zero, target under 5 minutes) - there is no reason it should remain untested through to production enablement. This is a same-day fix, not a structural limitation of the codebase (unlike US-009's Flyway-append-only constraint).
- **Separately, and even more fundamentally:** as of this pass, nothing on feature/US-012 is committed to git - deployment-checklist.md section 0 flags this as BLOCKING. There is no PR, no merge commit, no CI-verified artifact SHA to deploy in the first place. Every other green light in this report (code review, security review, test results) was evaluated against the working tree, not against a merged, CI-verified commit - that gap must close before any of the above evidence can be treated as pinned to a real, promotable artifact.
- **Conclusion: this combination is a genuine NOT READY, not a caveat.** Per this report's own operating rule, an untested rollback in staging is a hard NOT READY on its own; combined with a branch that has not even been committed or opened as a PR, there is nothing yet to promote through the pipeline this report's other findings describe. This is squarely different from US-009's situation, where the code was already reviewed against a real diff and the only gap was a low-consequence, structurally-inherited rollback limitation.

---

## Verdict

## **NOT READY**

### Reasoning

The engineering work itself is in strong shape: code review APPROVE WITH NITS, security review APPROVED with all 16 threat-model findings independently re-verified against the actual shipped code (not just the document's claims), 429/429 tests passing with a real concurrency bug found and fixed during the test audit, zero SpotBugs findings, and a rollback mechanism that is well-designed on paper. If the two blockers below were the only gaps, this would likely land at READY WITH CAVEATS.

It is **NOT READY**, not READY WITH CAVEATS, because of two items this report's own rules treat as hard gates rather than caveats:

1. **The rollback has not been tested in staging.** This is the platform's sole kill switch for a Critical self-escalation threat (T-E1) and deployment-checklist.md itself already names the drill a hard gate. An unexercised kill switch for the highest-severity threat this feature exists to contain is not an acceptable caveat to ship past.
2. **Nothing on feature/US-012 is committed to git.** There is no PR, no merge commit, no CI-verified build artifact. This is a structural precondition, not a quality gap - there is no artifact yet to release.

### Blockers (must close before this can move to READY WITH CAVEATS or better)

1. **Commit all working-tree changes, push the branch, open and merge the PR against main.** Record the merge commit SHA as the backend build artifact identifier. Owner: **[ASSIGN: Feature Author]** / **[ASSIGN: Release Manager]**
2. **Execute the rollback drill in staging** (flip feature.nexus-us012-rbac-role-assignment.enabled to false, confirm all three endpoints 404, confirm no data corruption, confirm the dashboard's RBAC traffic drops to zero, confirm completion under 5 minutes) before the flag is set true in any shared environment. Owner: **[ASSIGN: Release Manager]**
3. **Apply the M-1/M-2 config fixes** (management.endpoint.health.roles restricted to an operator role; management.endpoint.health.cache.time-to-live set or the zero-active-admins check moved off the request path) in the target environment before the flag is set true there. Owner: **[ASSIGN: Security Reviewer]** / **[ASSIGN: Backend Lead]**

### Additional caveats to carry forward once the blockers above close (not release-blocking on their own, but must not be lost)

1. **Capacity/latency against the epic's inferred bar (200 RPS, p95 < 300ms) has not been validated** - deliberately out of this story's own test scope (no AC required it), but still an open item before the staging-soak gate in 03-design.md section 10.2 step 3 can be called green. Capture real numbers during the soak per monitoring-checklist.md section 5, not before.
2. **The NVD-backed dependency scan (security-review Condition 4) has not completed** - a manual CVE review was substituted (198 artifacts, zero new/drifted, no CVSS >= 7 found). Run `.github/workflows/security.yml` via workflow_dispatch for authoritative evidence before merge, or at the latest before the flag is set true beyond dev/test.
3. **M-3/T-E9** (AC8 gates the role name, not the privilege) is correctly unreachable today, but must be a blocking entry criterion for the custom-roles story (US-015) - flagged to the PM, not silently carried as generic tech debt.
4. **L-1/L-3** (no 409 handler for lock-wait timeouts; a full entity materialized to read one column) are small, well-scoped, non-blocking follow-ups worth picking up opportunistically.

### Top 3 things the deploy team must not miss

1. **Do not deploy anything for this feature until the branch is committed, pushed, PR'd, merged, and the resulting merge-commit artifact has passed the full CI pipeline (429/429 tests, JaCoCo, SpotBugs, Checkstyle) on that exact commit** - every review and test result in this report was evaluated against the working tree, not a pinned artifact, until that happens.
2. **Do not flip the feature flag to true in any environment beyond dev/test until the rollback drill has actually been performed in staging and the M-1/M-2 config fixes are live there** - both are explicit rollout gates in deployment-checklist.md, not optional polish, and this feature is the platform's only defense against a Critical privilege-escalation threat.
3. **Watch nexus_rbac_self_escalation_attempt as a real signal, not noise, from the first minute the flag is true anywhere** - EPIC-002's own bar is zero such findings in steady state, and runbook.md section 4 gives the triage steps; do not let this alert's page get silently dismissed as routine.

---

## Cross-references

- docs/features/US-012/06-code-review.md, 07-security-review.md, 08-test-audit.md - the three phase gates this report's gate answers are drawn from
- docs/features/US-012/03-design.md section 10 - rollout/rollback plan
- docs/story/2-rbac/EPIC-002.md - the epic-level SLO/capacity figures referenced above
- docs/features/US-012/10-release/deployment-checklist.md, rollback-checklist.md, smoke-test-checklist.md, monitoring-checklist.md
