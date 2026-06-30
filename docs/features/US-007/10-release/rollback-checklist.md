# Rollback Checklist — US-007: Self-Service Password Reset via Email

Reference: [rollback.md](../rollback.md) (source plan) · [monitoring-checklist.md](monitoring-checklist.md) for trigger evidence

**STATUS WARNING: this rollback plan has not been executed as a drill in staging.** No artifact in docs/features/US-007 (deployment.md, rollback.md, runbook.md, test-audit.md) records a staging rollback rehearsal. Treat the steps below as reviewed-but-unverified until a dry run is performed. See production-readiness-report.md for the verdict impact.

---

## 1. Trigger Conditions

| # | Condition | Threshold | Data Source | Owner to Monitor |
|---|-----------|-----------|--------------|-------------------|
| T1 | Elevated 5xx rate on either new endpoint | 500 responses on POST /api/v1/auth/password/forgot or /reset exceed 1% of requests to that endpoint over a rolling 5-minute window | APM / access logs | [ASSIGN: On-Call Engineer] |
| T2 | Elevated 5xx on unrelated auth endpoints (login/refresh/logout) after this deploy | Any sustained increase versus the pre-deploy 24h baseline, correlated with this deploy's timestamp | APM dashboards | [ASSIGN: On-Call Engineer] |
| T3 | Mail delivery failure spike | SmtpMailSenderAdapter ERROR log rate exceeds 10 in 5 minutes, or downstream SMTP relay reports >5% bounce/failure rate | Application logs / mail relay dashboard | [ASSIGN: On-Call Engineer] |
| T4 | SESSION_REVOCATION_PARTIAL WARN log appears more than 5 times in 1 hour | Any sustained rate above baseline (baseline = 0; this is a new code path) | Application logs (grep SESSION_REVOCATION_PARTIAL) | [ASSIGN: On-Call Engineer] |
| T5 | Rate limiter misfiring on legitimate traffic | 429 rate on /forgot or /reset exceeds 5% of total requests to that endpoint, with confirmed legitimate (non-attack) traffic pattern | APM + manual IP review | [ASSIGN: On-Call Engineer] |
| T6 | Database load anomaly traced to the throttle query | auth_tokens query latency p95 exceeds 200ms or CPU on the DB instance increases >20% correlated with this deploy | DB monitoring (e.g. RDS/Cloud SQL dashboard) | [ASSIGN: DBA / Backend Lead] |
| T7 | Application fails to start / CrashLoopBackOff after deploy | Any instance failing health checks for more than 3 consecutive minutes post-deploy | Orchestrator (k8s/ECS) health status | [ASSIGN: DevOps / SRE] |
| T8 | Security incident: evidence of active token brute-forcing or enumeration exploit in progress | High-confidence SOC/SIEM alert correlated with PASSWORD_RESET_FAILED volume per the monitoring-checklist thresholds | SIEM | [ASSIGN: Security Engineer] |

---

## 2. Rollback Decision Owner

| Role | Responsibility |
|------|-----------------|
| [ASSIGN: Release Manager] | Final go/no-go call on a full rollback. Convened within 15 minutes of any T1-T8 trigger firing during the watch period. |
| [ASSIGN: On-Call Engineer] | Pages the Release Manager and Backend Lead when a trigger condition is met; executes the rollback once authorized. |
| [ASSIGN: Security Engineer] | Sole decision authority for T8 (security incident) -- may authorize an immediate kill-switch (section 5) without waiting for the full Release Manager rollback call, given the unauthenticated nature of both endpoints. |

---

## 3. Code Rollback

| # | Step | Detail | Owner |
|---|------|--------|-------|
| 3.1 | Identify previous good artifact | Previous backend artifact = the production-deployed JAR immediately prior to this release (record actual SHA/tag at deploy time in deployment-checklist.md section 0; placeholder until then: commit 02e9ee2, US-006, last known-good main tip before this feature). Previous frontend artifact = the corresponding prior frontend build. | [ASSIGN: Release Manager] |
| 3.2 | Standard git revert / redeploy previous artifact | No special steps beyond the normal deployment rollback process -- this release has no schema migration to reconcile (see section 4). Redeploy the previous backend JAR and previous frontend bundle through the standard CD pipeline. | [ASSIGN: DevOps / SRE] |
| 3.3 | Verify rollback effect | POST /api/v1/auth/password/forgot and POST /api/v1/auth/password/reset return 404. Frontend routes /auth/forgot-password and /auth/reset-password resolve to the Angular 404 page. The Forgot password? link disappears from the login form. The ?reset=true success banner no longer renders. | [ASSIGN: QA Engineer] |
| 3.4 | Confirm unrelated auth flows still function | Login, refresh, logout, registration must be unaffected -- these are pre-existing flows not modified at the contract level by this rollback. Run the pre-existing smoke suite for those flows. | [ASSIGN: QA Engineer] |

---

## 4. Database Rollback

| # | Step | Detail | Owner |
|---|------|--------|-------|
| 4.1 | No migration to roll back | US-007 ships zero Flyway migrations. The index idx_auth_tokens_user_id_type_created_at used by the throttle query was created in V3 for US-006 (ResendVerificationUseCase) and remains in place after this rollback -- it is not specific to US-007 and must NOT be dropped. | [ASSIGN: Backend Lead] |
| 4.2 | RESET-type tokens already issued | Any auth_tokens rows with type=RESET created while the feature was live remain in the table after rollback. They cannot be consumed (the endpoint returns 404) and expire naturally within 1 hour (AUTH_RESET_TOKEN_TTL). No manual cleanup required. | [ASSIGN: Backend Lead] |
| 4.3 | Irreversible data -- explicitly called out | auth_events rows with event types PASSWORD_RESET_REQUESTED, PASSWORD_RESET_FAILED, PASSWORD_RESET_THROTTLED, and PASSWORD_CHANGED generated during the live window are immutable audit records and are NOT deleted or reversed by rollback. This is by design (audit integrity) -- do not attempt to purge them. | [ASSIGN: Security Engineer] |
| 4.4 | User-state changes are not reversed | Any user whose password was actually changed via a successful reset before rollback keeps the new password and the ACTIVE status (including accounts that were unlocked via reset, AC-4). Rollback does not revert passwordHash, tokenVersion, or status. If a malicious reset is suspected, handle via the security-incident path (T8), not via rollback. | [ASSIGN: Security Engineer] |

---

## 5. Feature Flag Kill Switch

There is no feature flag for this release (Gate 2 decision -- 03-design.md section 10). Two kill-switch options exist that do not require a full artifact rollback:

| # | Option | Effect | Steps | Owner |
|---|--------|--------|-------|-------|
| 5.1 | SecurityConfig code change + redeploy | Endpoints return 401 instead of 404 once the permitAll entries for /api/v1/auth/password/forgot and /api/v1/auth/password/reset are removed from SecurityConfig and the backend is redeployed. Frontend shows An unexpected error occurred. -- a safe, generic failure mode. | (1) Remove the two permitAll matcher entries. (2) Redeploy backend only (frontend unaffected, can stay live). (3) Verify both endpoints return 401. | [ASSIGN: Backend Lead] |
| 5.2 | Reverse proxy / WAF block (fastest, no redeploy) | Add deny rules for the two API paths at the load balancer / CDN / WAF layer. Returns 403 immediately, no application redeploy needed -- this is the fastest available kill switch and should be the first action under an active-attack trigger (T8). | (1) Add deny-all rule for /api/v1/auth/password/forgot and /api/v1/auth/password/reset at the edge. (2) Verify 403 from outside the network. (3) Communicate to support that the feature is temporarily disabled. | [ASSIGN: DevOps / SRE] |

**Recommendation:** under T8 (active security incident), use 5.2 first (seconds to apply) while the team decides whether a full rollback (section 3) is also warranted.

---

## 6. Cache Invalidation

| # | Step | Detail | Owner |
|---|------|--------|-------|
| 6.1 | In-memory rate-limit store (default) | LoginRateLimitFilter uses an in-memory RateLimitStore by default (nexus.security.rate-limit.store-type=memory). State is lost automatically on instance restart/rollback redeploy -- no manual action needed. | [ASSIGN: DevOps / SRE] |
| 6.2 | Redis rate-limit store (only if store-type=redis is configured in this environment) | Flush the FORGOT_IP:*, FORGOT_USER:*, and RESET_IP:* key prefixes so stale rate-limit counters from the rolled-back version do not linger: redis-cli --scan --pattern FORGOT_IP:* then xargs redis-cli del (repeat for FORGOT_USER:* and RESET_IP:*). | [ASSIGN: DevOps / SRE] |
| 6.3 | No CDN content cache invalidation required for the API | The two endpoints are not cacheable (POST, no Cache-Control caching). Frontend static asset cache invalidation follows the standard frontend rollback process already in place for prior releases. | [ASSIGN: Frontend Lead] |

---

## 7. Communication

| # | Step | Detail | Owner |
|---|------|--------|-------|
| 7.1 | Internal incident channel | Post rollback start/end times, trigger condition (T1-T8), and current endpoint status (404 / 401 / 403) to the incident channel immediately on rollback start. | [ASSIGN: Release Manager] |
| 7.2 | Support / CS team | Notify support that self-service password reset is temporarily unavailable and provide the manual fallback process (admin-assisted reset, if one exists outside this feature) or an ETA for restoration. | [ASSIGN: Product Owner] |
| 7.3 | Stakeholders who received the original deploy-complete message | Send a rollback notice referencing the original communication from deployment-checklist.md step 3.5/1.11. | [ASSIGN: Product Owner] |
| 7.4 | Status page (if customer-facing status page exists) | Update with a brief, non-alarming note if the rollback is visible to end users (e.g. broken link on login page). | [ASSIGN: Product Owner] |

---

## 8. Post-Mortem

| # | Step | Detail | Owner |
|---|------|--------|-------|
| 8.1 | Post-mortem owner assigned within 1 business day of rollback | Root-cause analysis, timeline reconstruction, and corrective action items. | [ASSIGN: Release Manager] |
| 8.2 | Post-mortem must explicitly address | (a) which trigger (T1-T8) fired and whether the threshold was well-calibrated, (b) whether the rollback achieved the intended effect within the expected time, (c) whether the staging-rollback-untested gap (see header of this document) contributed to any delay or surprise during the live rollback, (d) corrective action to add a staging rollback drill before the next reset-flow-adjacent change. | [ASSIGN: Release Manager] |
| 8.3 | Security review of incident if T8 or any data-integrity concern (section 4.4) was involved | Separate security post-mortem track, coordinated with the Security Engineer who owns the original 07-security-review.md. | [ASSIGN: Security Engineer] |
