# US-012 - Monitoring Checklist

**Feature:** Role assignment / revocation API (POST/GET /api/v1/users/{userId}/roles, DELETE /api/v1/users/{userId}/roles/{roleId})
**Full reference:** docs/features/US-012/monitoring.md (what the metrics/alerts/dashboards/health indicators ARE, verified against shipped code) and runbook.md (per-alert response procedures). This document is different in kind: it is the pre-flight setup checklist to confirm all of that observability is actually wired, live, and paging the right people BEFORE the feature flag is flipped true anywhere beyond dev/test - not a description of what exists.

---

## 1. Dashboard

- [ ] Confirm the "RBAC / Role Assignment" dashboard row (monitoring.md section 4: request rate by endpoint+method, status mix, latency p50/p95/p99, denials by reason, domain conflicts by code, audit-buffer lag/depth, feature-flag state) exists in the target environment's dashboard tool and actually renders (not just defined-but-empty) once test traffic is sent to the three endpoints in a lower environment. Owner: [ASSIGN: Backend Lead]
- [ ] Confirm the feature-flag-state panel correctly reads feature.nexus-us012-rbac-role-assignment.enabled via Actuator /actuator/env and reflects the true per-environment value - this is the fastest way to catch the config-precedence trap called out in deployment-checklist.md section 1 if the dashboard row is unexpectedly empty after a flag flip. Owner: [ASSIGN: Backend Lead]
- [ ] Confirm the dashboard row is linked from wherever the on-call rotation's tooling points (per 03-design.md section 10.2 rollout step 4 - "dashboard + the five alerts live" is an explicit gate before production enablement). Owner: [ASSIGN: Release Manager]

---

## 2. Alerts wired into the paging system

monitoring.md section 2 defines six Prometheus alert rules for this feature (note: 03-design.md's own rollout gate at section 10.2 step 4 refers to "the five alerts" - this is a minor internal inconsistency between the design doc and the verified-against-code monitoring.md; treat all six rows below as in scope, do not silently drop one because of the mismatched count).

| Alert | Severity | Wired? | Owner |
|---|---|---|---|
| nexus_rbac_self_escalation_attempt | page | [ ] | [ASSIGN: On-call Engineering Lead] |
| nexus_rbac_audit_write_lost | page | [ ] | [ASSIGN: On-call Engineering Lead] |
| nexus_rbac_role_change_error_rate | page | [ ] | [ASSIGN: On-call Engineering Lead] |
| nexus_rbac_cross_tenant_attempt | ticket | [ ] | [ASSIGN: Backend Lead] |
| nexus_rbac_tenant_lockout_blocked | ticket | [ ] | [ASSIGN: Backend Lead] |
| nexus_rbac_audit_lane_drops | ticket, informational | [ ] | [ASSIGN: Backend Lead] |

- [ ] Confirm each Prometheus rule expression above (exact expressions in monitoring.md section 2) is loaded into the target environment's Prometheus/Alertmanager config, not just documented. Owner: [ASSIGN: Backend Lead]
- [ ] Confirm the three "page" severity alerts actually reach the on-call rotation's paging tool (send one deliberate test-fire of each, in a non-production environment, and confirm a real page arrives - do not just confirm the Alertmanager route exists on paper). Owner: [ASSIGN: On-call Engineering Lead]
- [ ] Confirm the three "ticket" severity alerts create a real ticket in whatever tracker the team uses, not just a log line. Owner: [ASSIGN: Backend Lead]
- [ ] Confirm alert firing does not double-fire or storm - e.g. nexus_rbac_audit_write_lost firing once per failed write, not once per retry attempt inside AuthEventRetryBuffer. Owner: [ASSIGN: Backend Lead]
- [ ] Confirm the runbook.md procedure for each alert is linked directly from the alert's own annotation/description in Alertmanager, so a 3am on-call engineer with no prior context can reach the right runbook section in one click. Owner: [ASSIGN: On-call Engineering Lead]

---

## 3. Health indicators added to on-call aggregation

- [ ] Confirm rbacDbPrivilege and rbacZeroActiveAdmins (both on the aggregate /actuator/health, monitoring.md section 3) are included in whatever synthetic/external health-check monitor the on-call rotation already watches - neither is in a liveness/readiness management.endpoint.health.group.*.include list by design, so confirm they are still visible to whatever polls the aggregate endpoint. Owner: [ASSIGN: DevOps/SRE on-call]
- [ ] BLOCKING before the flag is set true in any shared environment - confirm the M-1 fix (management.endpoint.health.roles restricted to an operator role) is live, so the detail payloads (cross-tenant tenantIds, DB account name) are not readable by every authenticated user. Do not wire monitoring on top of an intentionally-still-open information disclosure; fix M-1 first. Owner: [ASSIGN: Security Reviewer] / [ASSIGN: Platform Config Owner]
- [ ] BLOCKING before the flag is set true in any shared environment - confirm the M-2 fix (management.endpoint.health.cache.time-to-live set, or the zero-active-admins check moved to a scheduled gauge) is live, so the cross-tenant admin scan does not re-run on every unauthenticated /actuator/health hit. Owner: [ASSIGN: Backend Lead]
- [ ] Confirm a transition of either health indicator to DOWN triggers a visible signal to on-call (not just a silent status change nobody watches) - per monitoring.md section 5, both log a WARN on transition to DOWN; confirm that WARN is actually alertable/searchable in the target log platform. Owner: [ASSIGN: DevOps/SRE on-call]

---

## 4. Log queries pre-configured

- [ ] Load the seven structured log queries from monitoring.md section 5 (cross-tenant/self-escalation denial WARN, duplicate-assignment DEBUG, last-admin-lockout-blocked WARN, ROLE_ASSIGNED/ROLE_REVOKED INFO, generic conflict DEBUG, audit-write-lost ERROR, DB-privilege-drift WARN, zero-active-admins WARN) as saved searches/queries in the log platform the on-call rotation actually uses, so no one has to reconstruct field names from memory during an incident. Owner: [ASSIGN: On-call Engineering Lead]
- [ ] Confirm at least one saved query surfaces the traceId field correctly for cross-referencing against a specific request, per runbook.md section 3's audit-write-lost procedure. Owner: [ASSIGN: On-call Engineering Lead]

---

## 5. Baseline capture plan (staging soak)

- [ ] monitoring.md section 6 explicitly records baseline p50/p95/p99 latency and steady-state denial/conflict rates as "not yet captured" - this must be captured during the staging soak (03-design.md section 10.2 rollout step 3) and recorded back into monitoring.md section 6 before the flag is flipped true in production. Owner: [ASSIGN: Backend Lead]
- [ ] During the soak, also capture the actual 5xx rate and confirm it is well under the 1%-over-5-min alert threshold at realistic load, not just in the absence of traffic. Owner: [ASSIGN: Backend Lead]
- [ ] Record whether the soak's traffic pattern actually reached anything close to the epic's inferred 200 RPS / p95 < 300ms bar (EPIC-002, story success metrics) - 08-test-audit.md explicitly notes no load scenarios were added for this story (no AC required it), so this bar has not been validated at any point in the pipeline before the soak. If the soak does not include a deliberate load-generation step reaching this rate, say so explicitly rather than letting an untested capacity assumption ride into production - see production-readiness-report.md. Owner: [ASSIGN: Backend Lead] / [ASSIGN: QA Lead]

---

## 6. On-call rotation contact

- [ ] Confirm the on-call rotation has been notified this feature is landing, has reviewed runbook.md and monitoring.md before the staging soak begins (per deployment-checklist.md section 1 communication step), and knows this is the platform's first genuinely privileged endpoint (09-technical.md section 1). Owner: [ASSIGN: Release Manager]
- [ ] On-call contact: [ASSIGN: current on-call engineering lead / rotation tool link - no RBAC-specific rotation exists, this uses the standing platform on-call schedule]

---

## 7. Watch period

- [ ] Minimum 24-48h of active watch after each flag flip to true (dev/test excluded), per deployment-checklist.md section 3 and 03-design.md section 10.2 rollout step 5. During this window, treat any single firing of nexus_rbac_self_escalation_attempt as a finding worth triage (runbook.md section 4), not routine noise - EPIC-002's stated bar is zero such findings in steady state. Owner: [ASSIGN: On-call rotation]
- [ ] At the end of the watch period, confirm the 5xx rate target from 03-design.md section 10.2 step 5 (< 0.1%) was met, and record the result alongside the baseline captured in section 5 above. Owner: [ASSIGN: Backend Lead]

---

## Cross-references

- docs/features/US-012/monitoring.md - the metrics/alerts/health-indicators/dashboard/log-query reference this checklist verifies is actually wired
- docs/features/US-012/runbook.md - per-alert response procedures linked from Alertmanager per section 2 above
- docs/features/US-012/03-design.md section 10 - rollout/rollback plan and gates this checklist supports
- docs/features/US-012/07-security-review.md - M-1/M-2 follow-ups this checklist treats as blocking before flag-true in any shared environment
- docs/features/US-012/10-release/deployment-checklist.md, rollback-checklist.md, smoke-test-checklist.md, production-readiness-report.md
