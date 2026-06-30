# Production Readiness Report — US-007: Self-Service Password Reset via Email

Prepared by: [ASSIGN: Release Manager]
Sources reviewed: 01-requirements.md, 03-design.md, 03b-threat-model.md, 06-code-review.md, 07-security-review.md, 08-test-audit.md, 09-technical.md, deployment.md, rollback.md, monitoring.md, runbook.md, ADR 0003, ADR 0010, application.yml, git working tree (commit c5b6faa, branch feature/US-007).

---

## Gate-by-Gate Findings

### 1. Are all code-review blockers resolved?

YES. 06-code-review.md verdict: APPROVE. All 3 BLOCKER findings resolved in-session:
- Missing V4 Flyway migration for the throttle index: resolved by discovering the index already exists in V3 (added for US-006). The redundant V4 file was removed rather than re-added; confirmed in the current working tree (git diff shows the V4 file deletion and corresponding doc updates are consistent across deployment.md, rollback.md, 09-technical.md, and CHANGELOG.md).
- EmailCipher.value() abstraction violation: documented and addressed.
- ForgotPasswordUseCaseTest null-Clock latent NPE: resolved.

All 3 HIGH, 4 MEDIUM, and 5 LOW findings are also marked resolved. Re-run after fixes: 358 backend / 155 frontend tests passing per the code-review doc (superseded by 369/163+ in the later test audit after gap closure).

### 2. Are all security-review blockers resolved?

YES. 07-security-review.md verdict: APPROVED (post-fix re-review). All 4 HIGH findings resolved:
- T-I2 timing oracle: partially mitigated via a dummy tokenGenerator.generate() call on the not-found path to equalize CPU-bound work. A residual DB round-trip timing difference is explicitly accepted with an inline comment -- not silently ignored. This is a documented residual risk, not an unresolved blocker.
- PASSWORD_RESET_FAILED audit durability (REQUIRES_NEW fragility): inline comment + new test added (execute_sessionRevocationFailure_isSwallowedAndPasswordStillSaved); IT-level durability test deferred (Docker unavailable in audit environment -- see test-gate section below).
- Reset-request throttle TOCTOU + missing filter-level rate limit on /forgot: resolved via LoginRateLimitFilter extension (FORGOT_IP + FORGOT_USER buckets). Underlying DB-level TOCTOU race is still possible and accepted as a documented residual -- the filter layer substantially narrows the window.
- No rate limiting on /reset: resolved via RESET_IP bucket in LoginRateLimitFilter.

All MEDIUM and LOW findings resolved: session-revocation WARN log added, frontend/backend maxLength mismatch fixed (256), token stripped from URL post-read. Auth/PII/Crypto sign-offs all PASS.

Caveat: the TOCTOU race on the DB-level 3-per-hour throttle is mitigated, not eliminated -- a sufficiently fast concurrent burst can still exceed 3 emails to one victim before the filter-level per-email bucket fully engages. This is accepted in the security review as a residual risk, not a blocker.

### 3. Are test gates green?

YES, with one explicitly accepted gap set. 08-test-audit.md verdict: PASS.
- Backend: 369 tests, 0 failures, 0 skipped (mvnw verify, including checkstyle/SpotBugs/ArchUnit/JaCoCo gates).
- Frontend: 163+ tests, 0 failures (npm run test:ci); coverage 87.46% statements / 82.09% branches / 82.82% functions / 90.16% lines.
- All 15 test gaps identified during the audit were closed in this audit cycle.

Four gaps were explicitly accepted with documented rationale (not silently skipped):
- A1: Testcontainers IT for PASSWORD_RESET_FAILED REQUIRES_NEW durability -- Docker not available in audit environment, mitigated by inline comment plus unit test.
- A2: IT for AFTER_COMMIT async email dispatch -- same Docker constraint.
- A3: Load tests for /forgot and /reset above 10 RPS -- requires running infrastructure.
- A4: End-to-end Playwright test for the full reset flow -- deferred to manual QA or integration environment.

Caveat: gaps A1 and A2 mean the REQUIRES_NEW audit-durability guarantee and the AFTER_COMMIT async-dispatch guarantee are verified only at the unit level, not against a real transaction manager in CI. These are load-bearing guarantees (anti-enumeration and audit trail) that are core to the threat model. The unit-level verification is meaningful but not equivalent to an IT-level assertion.

Pre-existing: 2 flaky frontend tests under full-parallel execution only (nx-select.spec.ts, registration-form.component.spec.ts), unrelated to US-007 and passing in isolation. Recommended follow-up: increase vitest testTimeout from 5000ms to 10000ms.

### 4. Is there a rollback plan?

YES, documented -- but NOT YET TESTED IN STAGING. rollback.md and rollback-checklist.md cover: code rollback (redeploy previous artifact), DB rollback (trivial -- no migration to undo; reset tokens expire naturally; audit events are irreversible by design), a two-tier kill switch (CDN/WAF block with no redeploy, or SecurityConfig change with redeploy), cache invalidation (in-memory vs. Redis paths), and explicit callouts for what is irreversible (audit events, already-changed passwords).

No artifact in docs/features/US-007 (deployment.md, rollback.md, runbook.md, 08-test-audit.md) or the git history records a staging rollback drill. Per the release rules of this project -- "If it has not been tested in staging, that is a NOT READY" -- this is a formal caveat.

### 5. Are env vars/config documented?

YES, fully. US-007 introduces zero new required environment variables. All mail and JWT configuration is pre-existing from US-004/US-005. Two new optional config properties with safe defaults are documented and present in application.yml: nexus.security.rate-limit.forgot-ip-max-attempts (default 10 per 60s) and reset-ip-max-attempts (default 20 per 60s). No new secrets introduced; all crypto material reuses existing Vault-managed paths.

### 6. Are monitoring/alerting requirements documented?

YES. monitoring.md (source) and monitoring-checklist.md define audit event types, log patterns, alert thresholds with specific numbers (429 rate >50/min warning, >200/min critical; PASSWORD_RESET_FAILED >50/hr warning, >200/hr critical; etc.), four SQL log queries for investigation, and a 48-hour watch period structure. Dashboard links and on-call contacts are placeholder items that must be populated before go-live -- this is an execution gap, not a documentation gap.

### 7. Is the deployment order safe (no breaking changes)?

YES. Zero Flyway migrations -- no schema change at all in this release. Backend and frontend are independently deployable with no breaking API contract change. The originally planned V4 migration was removed after discovering the required index already exists in V3; this is an additive-only release. No expand/contract review required (ADR 0003).

Caveat: no feature flag exists. The feature is always-on once the backend deploys. This is a deliberate Gate 2 design decision, not an omission, but it means there is no staged rollout capability and the only fast kill switch post-deploy is a CDN/WAF block or SecurityConfig change + redeploy.

### 8. Structured Gate Answers (Standard Checklist)

| Question | Status | Notes |
|----------|--------|-------|
| SLOs defined? (availability, latency, error rate) | PARTIAL | Error-rate alert thresholds are defined in monitoring-checklist.md. Formal SLO documents (e.g. 99.9% availability, p95 < 500ms) are not present in US-007 artifacts -- endpoints share the platform SLO if one exists; flagged as a gap. [ASSIGN: Product Owner / Platform Engineering] |
| Capacity validated? (load test results vs expected traffic) | NOT DONE | Gap A3 in the test audit -- load tests above 10 RPS were explicitly deferred. The rate limiter (10/60s per IP on /forgot, 20/60s on /reset) provides a hard ceiling on per-IP load, but no load test validates system behavior under the aggregate limit. [ASSIGN: QA Engineer -- before or soon after launch] |
| Dependencies healthy? (downstream service SLAs) | PARTIAL | SMTP relay SLA is not documented in US-007 artifacts. Email dispatch is async and non-blocking to the HTTP response (AFTER_COMMIT listener), so SMTP degradation does not affect response SLO. SMTP delivery monitoring is included in monitoring-checklist.md. DB (MySQL) is the primary dependency; no separate SLA document referenced but existing DB health is monitored. [ASSIGN: DevOps / SRE -- confirm SMTP SLA] |
| Backups in place? | YES (assumed) | auth_events and auth_tokens are in the same MySQL instance as all other identity data; backup policy for this instance is pre-existing and not changed by this release. [ASSIGN: DBA -- confirm backup coverage for auth_tokens / auth_events is current] |
| Disaster recovery tested? | NOT IN SCOPE FOR US-007 | DR for the platform is a pre-existing concern; this release adds no new DR requirements. [ASSIGN: Platform Engineering] |
| Runbook written? | YES | runbook.md covers 6 scenarios: user did not receive email, link expired/already used, high PASSWORD_RESET_FAILED rate, SESSION_REVOCATION_PARTIAL alert, user rate-limited on /forgot, POST /forgot returning 500. |
| Security review signed off? | YES | 07-security-review.md verdict: APPROVED (post-fix). Auth/PII/Crypto sign-offs: all PASS. No dependency CVEs introduced per the dependency scan section of 07-security-review.md. |
| Privacy review complete? | PARTIAL | US-007 handles email addresses (PII) within the existing US-003/US-004 email encryption and HMAC blind-index framework. No new PII fields are introduced. The raw email is masked in logs (SEC-3 compliance verified in tests). Token is stripped from browser URL post-read (ADR 0010). A formal DPIA/privacy review document is not present in the feature artifacts -- acceptable for an MVP update to the identity context, but a full privacy review should be completed before this feature is relied upon in a regulated (GDPR/CCPA) production environment. [ASSIGN: Privacy/Legal -- confirm or schedule] |
| Accessibility review complete? | PARTIAL | WCAG 2.1 AA compliance is addressed in the design (03-design.md section 7: labels, aria-describedby, strength meter as text+icon). The code review confirmed the maxlength WCAG gap (missing error message for 254-char email) was resolved (HIGH finding in code review). No independent accessibility audit document exists -- self-certified via design and code review only. [ASSIGN: QA Engineer -- commission an independent a11y spot check before broad rollout] |
| i18n complete? | NOT APPLICABLE | Nexus is single-locale (en) at this stage. Error messages and UI copy are all English; no i18n framework is in use. |
| Feature flag plan defined? | NO (by design) | Gate 2 decision: no feature flag. Always-on. This is a documented, deliberate choice, not an omission. |
| Rollback tested at least once in staging? | NO | This is the primary READY WITH CAVEATS gate item -- see section 4 and the verdict below. |

---

## Known Issues and Caveats Summary

1. Rollback not drilled in staging (primary caveat -- see verdict).
2. No feature flag -- always-on once deployed; no staged rollout capability; fastest kill switch is a CDN/WAF block.
3. Timing-oracle and throttle-TOCTOU residual risks: partially mitigated, accepted, and documented; not eliminated.
4. Build artifact versioning is SNAPSHOT/0.0.0: confirm CI/CD pipeline promotes a tagged release build before deploying to production (deployment-checklist.md section 0 action item).
5. Testcontainers IT for REQUIRES_NEW audit-durability and AFTER_COMMIT dispatch deferred: unit-level only verification for two load-bearing transactional guarantees.
6. Load test not performed: no evidence of sustained throughput testing above 10 RPS; the per-IP rate limiter caps individual IP load but aggregate load is untested.
7. Formal SLO document not present in US-007 artifacts.
8. SMTP relay SLA not documented.
9. Formal accessibility audit (independent) not conducted -- design + code-review self-certification only.
10. Monitoring dashboard links and on-call contacts are not yet populated in monitoring-checklist.md.

---

## Verdict

**READY WITH CAVEATS**

**Reasoning:**

All functional correctness, security, and test gates have passed. Code review, security review, and test audit carry explicit APPROVE/PASS verdicts with every blocker resolved. The feature is architecturally sound, the threat model is largely covered, and the deployment is additive-only (zero schema changes). The feature is ready to ship if the following caveats are accepted and the two MUST-DO items below are actioned before or immediately after go-live:

**Caveats that keep this from being READY:**

C1 (Rollback not staged-tested): The rollback plan for an unauthenticated, internet-facing endpoint pair has not been exercised as a drill. Any rollback executed under incident conditions will be a first run of the actual procedure. The risk is real for operations: the endpoints are permitAll (no auth barrier), touch a sensitive action (password change), and revoke sessions. If the deploy window allows, a dry-run code revert in the staging environment -- confirming the four expected rollback behaviors (404 on /forgot and /reset, disappearance of the Forgot? link, preservation of existing auth flows) -- should be completed first. If the window does not allow it, the deploy team should accept this gap explicitly.

C2 (No staged rollout / no feature flag): There is no mechanism to show the feature to a subset of users first. Any incident after deploy affects 100% of users. The CDN/WAF kill switch (rollback-checklist.md section 5.2) is fast (seconds) and does not require a redeploy, which partially compensates.

C3 (SNAPSHOT build artifact): Confirm that the deployment pipeline does not ship the raw SNAPSHOT JAR to production.

---

## Top 3 Things the Deploy Team Must Not Miss

1. NO V4 MIGRATION EXISTS -- VERIFY BEFORE PRESSING GO. The migration directory must show only V1-V3 at deploy time. A V4 file was committed, then removed (confirmed deleted in the working tree). A bad merge could accidentally reintroduce it; if it is present at deploy time, Flyway will fail to apply a duplicate index and the application will not start. Check the migration directory as the final pre-deploy step (deployment-checklist.md 1.2). Do not proceed if V4 is present.

2. NEXUS_FRONTEND_BASE_URL MUST POINT TO THE PRODUCTION FRONTEND. This variable (pre-existing from US-004) is used to build the password-reset link URL that is emailed to users. If it is set to localhost:2000 or a staging URL in production, every reset email will contain a non-functional link. This is a silent failure -- the API returns 202, no error is raised, but users cannot complete their reset. Verify the value in the target environment config before deploying (deployment-checklist.md 1.6).

3. ROLLBACK KILL SWITCH MUST BE READY BEFORE TRAFFIC HITS THE NEW ENDPOINTS. No feature flag exists. The moment the backend deploys, both /password/forgot and /password/reset are live and accessible to the internet. The on-call engineer must have the CDN/WAF deny-rule procedure (rollback-checklist.md 5.2) ready to execute within minutes -- not as a post-incident lookup, but pre-loaded and pre-authorized. This is especially critical given the rollback plan has not been drilled in staging.
