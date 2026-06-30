# Deployment Checklist — US-007: Self-Service Password Reset via Email

Branch: `feature/US-007` -> `main` · Commit: `c5b6faa` (`feat(identity): US-007 — Enable self-service password reset via email`)
References: [deployment.md](../deployment.md) · [09-technical.md](../09-technical.md) · [ADR 0003](../../../adr/0003-flyway-schema-migrations.md) · [ADR 0010](../../../adr/0010-password-reset-token-in-url.md)

---

## 0. Build Artifacts

| Artifact | Identifier | Owner |
|----------|-----------|-------|
| Backend commit SHA | c5b6faa8e854fb477f52de13fdbd1397899ce755 (record the actual merge-to-main SHA at deploy time -- this is the feature-branch tip) | [ASSIGN: Release Manager] |
| Backend Maven artifact version | nexus-backend-0.0.1-SNAPSHOT.jar -- CAVEAT: this is a SNAPSHOT version; confirm the deploy pipeline tags/promotes a release build (e.g. 0.7.0) before shipping to prod, not the raw SNAPSHOT jar | [ASSIGN: Release Manager] |
| Frontend build identifier | nexus-frontend package.json version 0.0.0 + commit SHA above -- CAVEAT: same SNAPSHOT/unversioned concern; confirm CI assigns a build number/tag | [ASSIGN: Release Manager] |
| Frontend bundle | Output of npm run build (production config) -- record the dist hash / CI build ID | [ASSIGN: Frontend Lead] |

Action before deploy: resolve the version-identifier caveat above -- get the actual CI build/tag number for both artifacts and replace the SNAPSHOT/0.0.0 placeholders before this checklist is signed off. [ASSIGN: Release Manager]

---

## 1. Pre-Deploy

| # | Step | Detail | Owner |
|---|------|--------|-------|
| 1.1 | Confirm Gate verdicts | Code review: APPROVE (06-code-review.md -- all 3 blockers + 3 high + 4 medium + 5 low resolved). Security review: APPROVED post-fix (07-security-review.md -- all 4 HIGH resolved, MEDIUM/LOW resolved). Test audit: PASS (08-test-audit.md -- 369 backend / 163+ frontend tests green, 15/15 gaps closed). | [ASSIGN: Release Manager] |
| 1.2 | Verify no new Flyway migration is pending | ls of the migration directory must show only V1__baseline.sql, V2__identity_schema.sql, V3__add_password_hash_to_users.sql. No V4 file. The throttle index idx_auth_tokens_user_id_type_created_at was already created in V3 for ResendVerificationUseCase (US-006) and is reused as-is by US-007's throttle query. A V4 migration was drafted during code review then removed once this was discovered -- confirm it is not reintroduced by a bad merge. | [ASSIGN: Backend Lead] |
| 1.3 | Confirm ddl-auto=validate in target environment | application-prod config must have spring.jpa.hibernate.ddl-auto=validate (ADR 0003). This release has zero schema changes -- no expand/contract review required. | [ASSIGN: Backend Lead] |
| 1.4 | Run mvnw verify (full suite incl. Testcontainers IT) on the exact commit being shipped | Must be 0 failures. Attach CI run URL to the deploy ticket. | [ASSIGN: Backend Lead] |
| 1.5 | Run npm run test:ci, npm run lint, npm run format:check on the exact commit | Must be 0 failures. Note: 2 pre-existing flaky tests under full-parallel run only (nx-select.spec.ts, registration-form.component.spec.ts) -- not introduced by US-007 and pass in isolation (08-test-audit.md); do not block on these alone. | [ASSIGN: Frontend Lead] |
| 1.6 | Verify config -- no new required env vars | US-007 adds zero new required env vars. NEXUS_FRONTEND_BASE_URL, NEXUS_MAIL_FROM_ADDRESS, NEXUS_MAIL_HOST/PORT/USERNAME/PASSWORD are pre-existing from US-004/US-005 -- confirm all are already correctly set in the target environment, especially NEXUS_FRONTEND_BASE_URL (used to build the reset-link URL in the email). | [ASSIGN: DevOps / SRE] |
| 1.7 | Verify new optional config (safe defaults; tune only if traffic profile demands it) | nexus.security.rate-limit.forgot-ip-max-attempts (default 10 per 60s), reset-ip-max-attempts (default 20 per 60s), existing user-max-attempts (default 5 per 900s, reused for the new FORGOT_USER bucket). No action required unless ops wants different limits for this environment; source: application.yml committed defaults. | [ASSIGN: DevOps / SRE] |
| 1.8 | Secrets -- confirm no rotation needed | US-007 introduces no new secrets. Reuses existing Vault-managed paths for: identity encryption password/salt, identity HMAC key (email blind index -- used by the throttle lookup), JWT private/public key PEM, mail username/password. Confirm these Vault paths are already populated and unchanged in the target environment (no values recorded here). | [ASSIGN: Security Engineer] |
| 1.9 | Feature flag check | No feature flag exists for this feature -- confirmed Gate 2 design decision (03-design.md section 10: Feature flag required: No). Endpoints are permitAll in SecurityConfig with no ConditionalOnProperty guard -- there is no config-driven OFF switch. The only kill switches are a SecurityConfig code change plus redeploy, or a CDN/WAF block (see rollback-checklist.md). Action: explicitly confirm stakeholders accept always-on, no staged rollout before this deploy window. | [ASSIGN: Product Owner] |
| 1.10 | Reverse proxy / CDN config | Add Referrer-Policy: no-referrer header for the /auth/reset-password route (ADR 0010 -- prevents reset-token leakage via the Referer header to any third-party resource). Must be live before or with the frontend deploy. | [ASSIGN: DevOps / SRE] |
| 1.11 | Communication to stakeholders sent | Notify support/CS team that Forgot password? is now live; share runbook.md link covering the two most likely support scenarios (no email received; link expired/already used). Notify on-call of the new alert patterns (see monitoring-checklist.md). | [ASSIGN: Product Owner] |
| 1.12 | Smoke test plan reviewed and ready | See smoke-test-checklist.md -- owner assigned and available during the deploy window. | [ASSIGN: QA Engineer] |
| 1.13 | Rollback plan reviewed by on-call | See rollback-checklist.md. CAVEAT: rollback has not been exercised in staging -- no artifact in this feature's documentation set records a staging rollback drill. Recommend a dry-run revert in staging ahead of the production window if the schedule allows; flagged in production-readiness-report.md. | [ASSIGN: Release Manager] |

---

## 2. During Deploy

| # | Step | Detail | Owner |
|---|------|--------|-------|
| 2.1 | Deploy backend JAR | Standard rolling deploy. Flyway runs on startup; expect zero migrations applied (V1-V3 are already at baseline in every existing environment). New endpoints POST /api/v1/auth/password/forgot and POST /api/v1/auth/password/reset become available once the new instance is in rotation. | [ASSIGN: DevOps / SRE] |
| 2.2 | Verify Flyway ran clean | Check startup logs for the Flyway banner -- expect schema up to date, no migration necessary. If a stray V4 migration appears (bad merge), halt the deploy and re-check step 1.2. | [ASSIGN: Backend Lead] |
| 2.3 | Verify ddl-auto=validate did not fail startup | A schema validation failure indicates entity/schema drift unrelated to this release -- investigate before retry; do not force ddl-auto=update as a workaround. | [ASSIGN: Backend Lead] |
| 2.4 | Health check new backend instances before adding to load balancer | GET /actuator/health returns status UP before traffic cutover. | [ASSIGN: DevOps / SRE] |
| 2.5 | Deploy frontend build | Static asset deploy / CDN invalidation per standard process. New routes /auth/forgot-password and /auth/reset-password become available; Forgot password? link appears on the login form. | [ASSIGN: Frontend Lead] |
| 2.6 | Confirm independent deployability | No breaking API contract change -- old frontend continues to work against new backend; new frontend degrades gracefully (An unexpected error occurred.) if the backend deploy lags. Backend-first is the team's existing convention but is not a hard requirement here. | [ASSIGN: Release Manager] |
| 2.7 | Confirm CDN/reverse-proxy Referrer-Policy header is live (from 1.10) | Manual header check against /auth/reset-password in production after frontend deploy. | [ASSIGN: DevOps / SRE] |

---

## 3. Post-Deploy

| # | Step | Detail | Owner |
|---|------|--------|-------|
| 3.1 | Run smoke test suite | See smoke-test-checklist.md in full. | [ASSIGN: QA Engineer] |
| 3.2 | Watch monitoring dashboards for the defined watch period | See monitoring-checklist.md -- minimum 24h active watch, 48h passive. | [ASSIGN: On-Call Engineer] |
| 3.3 | Verify rate-limit filter is active in production | Confirm via synthetic/controlled test that exceeding forgot-ip-max-attempts (10/60s) returns 429 with a Retry-After header, without impacting real users. | [ASSIGN: QA Engineer] |
| 3.4 | Confirm audit events are being written | Query auth_events for a PASSWORD_RESET_REQUESTED row generated by the smoke test within the last 10 minutes. | [ASSIGN: Backend Lead] |
| 3.5 | Send deploy-complete communication | Notify stakeholders from 1.11 that the feature is live, smoke tests passed, and monitoring is green. | [ASSIGN: Product Owner] |
| 3.6 | Close out deployment ticket with final artifact identifiers | Update the deploy ticket (and this checklist if kept as a living doc) with the actual merge-commit SHA and CI build numbers used in production, replacing the SNAPSHOT/0.0.0 placeholders from section 0. | [ASSIGN: Release Manager] |

---

## Non-Additive Change Review

N/A -- this release contains no Flyway migration at all. The original design called for a new V4__auth_tokens_reset_throttle_index.sql (additive -- CREATE INDEX only, which would have qualified as a safe additive change under ADR 0003 even if shipped). During code review it was discovered the required index already exists from V3 (added for US-006), so the V4 file was removed rather than risk a duplicate-index error. No expand/contract review is required for this release.
