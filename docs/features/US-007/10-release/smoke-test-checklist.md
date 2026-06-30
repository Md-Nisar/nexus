# Smoke Test Checklist — US-007: Self-Service Password Reset via Email

Run immediately after deploy, before declaring the deploy complete (deployment-checklist.md step 3.1). Reference: deployment.md "Smoke Test After Deploy" section, runbook.md.

---

## 1. Healthcheck

| # | Test | Method | Expected | Owner |
|---|------|--------|----------|-------|
| 1.1 | Backend health endpoint | GET /actuator/health | HTTP 200, body {"status":"UP"}, db and mail components (if exposed) also UP | [ASSIGN: QA Engineer] |
| 1.2 | Frontend loads | Navigate to the production base URL | SPA shell loads, no console errors on initial paint | [ASSIGN: QA Engineer] |

---

## 2. Happy-Path: New Feature (Password Reset)

| # | Test | Method | Expected | Owner |
|---|------|--------|----------|-------|
| 2.1 | Forgot-password request -- registered email | curl -X POST https://HOST/api/v1/auth/password/forgot with a known test account email | HTTP 202, body: "If an account with that email exists, a reset link has been sent." | [ASSIGN: QA Engineer] |
| 2.2 | Forgot-password request -- unregistered email | Same call with an email guaranteed not to exist | HTTP 202, identical body to 2.1 (anti-enumeration contract, AC-1) | [ASSIGN: QA Engineer] |
| 2.3 | Reset email delivered | Check the test mailbox (or SMTP relay log / LoggingMailSenderAdapter log in lower environments) within 30 seconds of 2.1 | Email received with a reset link of the form BASE_URL/auth/reset-password?token=<64-char-hex> | [ASSIGN: QA Engineer] |
| 2.4 | Frontend forgot-password page loads | Navigate to /auth/forgot-password | Email form renders; submit triggers 2.1 behavior; success state shows the generic confirmation message | [ASSIGN: QA Engineer] |
| 2.5 | Frontend reset-password page loads with a valid token | Click the link from 2.3 (or navigate to /auth/reset-password?token=<valid-token>) | New-password form renders with the strength meter; token is stripped from the visible URL after load (ADR 0010) | [ASSIGN: QA Engineer] |
| 2.6 | Submit a valid new password | Enter a policy-compliant password different from the current one and submit | HTTP 200 from POST /reset; body: "Password reset successfully. Please sign in."; frontend redirects to /auth/login?reset=true | [ASSIGN: QA Engineer] |
| 2.7 | Success banner shown on login | After redirect from 2.6 | Login page shows a one-time success banner/toast | [ASSIGN: QA Engineer] |
| 2.8 | Login with the new password | Submit the login form with the just-reset password | Login succeeds | [ASSIGN: QA Engineer] |
| 2.9 | Old password is rejected | Attempt login with the pre-reset password | Login fails (password was changed) | [ASSIGN: QA Engineer] |
| 2.10 | Reused/expired token rejected | Re-submit POST /reset with the same token from 2.6 (now consumed) | HTTP 410, code AUTH_RST_002 | [ASSIGN: QA Engineer] |
| 2.11 | Invalid token rejected | Navigate to /auth/reset-password?token=badtoken000...(64 chars) and submit | HTTP 410, code AUTH_RST_002; frontend shows "This reset link has expired or already been used" with a link back to /auth/forgot-password | [ASSIGN: QA Engineer] |
| 2.12 | Locked-account escape path (AC-4) | Using a test account in LOCKED status (from US-006 lockout), complete a reset | Account status becomes ACTIVE after a successful reset; user can log in immediately afterward | [ASSIGN: QA Engineer] |
| 2.13 | Session revocation (AC-3) | Log in as a test user on a second session/device before reset, then complete a reset on the first session | The second session's refresh token is revoked (subsequent refresh call fails) within a few seconds of the reset | [ASSIGN: QA Engineer] |

---

## 3. Critical Pre-Existing Flows (Regression Guard)

| # | Test | Method | Expected | Owner |
|---|------|--------|----------|-------|
| 3.1 | Login | Submit valid credentials for an unaffected test account | Login succeeds, tokens issued | [ASSIGN: QA Engineer] |
| 3.2 | Dashboard loads post-login | Navigate to the authenticated landing page after login | Dashboard renders with expected user data | [ASSIGN: QA Engineer] |
| 3.3 | Refresh token flow | Allow access token to expire (or call POST /api/v1/auth/refresh directly) | New access token issued without forcing re-login | [ASSIGN: QA Engineer] |
| 3.4 | Logout | Trigger logout from an active session | Refresh token revoked; subsequent refresh call with the same token fails | [ASSIGN: QA Engineer] |
| 3.5 | Registration | Register a new throwaway test account | Registration succeeds; verification email flow unaffected by this release | [ASSIGN: QA Engineer] |
| 3.6 | Payment flow | N/A -- Nexus identity context has no payment flow in scope for this release | N/A | N/A |

---

## 4. Rate Limiting Sanity Check

| # | Test | Method | Expected | Owner |
|---|------|--------|----------|-------|
| 4.1 | /forgot per-IP limit | From a single test IP/origin, issue 11 POST /forgot requests within 60 seconds | The 11th request returns HTTP 429 with a Retry-After header (default forgot-ip-max-attempts=10) | [ASSIGN: QA Engineer] |
| 4.2 | /reset per-IP limit | From a single test IP/origin, issue 21 POST /reset requests within 60 seconds (any payload) | The 21st request returns HTTP 429 with a Retry-After header (default reset-ip-max-attempts=20) | [ASSIGN: QA Engineer] |
| 4.3 | Application-level per-account throttle (AC-5) | Issue 4 forgot-password requests for the same test account within 1 hour (staying under the per-IP/per-email filter limits) | First 3 generate emails; the 4th still returns 202 but no email is sent, and a PASSWORD_RESET_THROTTLED audit event is recorded | [ASSIGN: QA Engineer] |

---

## 5. Error Monitoring -- No Spike

| # | Check | Method | Expected | Owner |
|---|-------|--------|----------|-------|
| 5.1 | 5xx rate on new endpoints | APM dashboard filtered to /api/v1/auth/password/forgot and /reset for the 15 minutes following deploy | 0 unexpected 5xx responses (smoke-test-induced 410/400/429 are expected and not errors) | [ASSIGN: On-Call Engineer] |
| 5.2 | 5xx rate on existing auth endpoints | Same dashboard for /login, /refresh, /logout, /register | No increase versus the pre-deploy 24h baseline | [ASSIGN: On-Call Engineer] |
| 5.3 | Application error tracker (e.g. Sentry/equivalent) | Check for new exception types tagged with this release's commit/version | No new unhandled exception types introduced | [ASSIGN: On-Call Engineer] |

---

## 6. Logs Flowing

| # | Check | Method | Expected | Owner |
|---|-------|--------|----------|-------|
| 6.1 | Application logs reaching the central log store | Search the log aggregator for any log line emitted by the new backend instances (e.g. startup banner) within 2 minutes of deploy | Logs present and timestamped correctly | [ASSIGN: On-Call Engineer] |
| 6.2 | Audit events reaching auth_events | After smoke test 2.1, query: SELECT * FROM auth_events WHERE event_type='PASSWORD_RESET_REQUESTED' ORDER BY created_at DESC LIMIT 1; | Row present, timestamp matches the smoke test execution time | [ASSIGN: Backend Lead] |
| 6.3 | No raw token or raw email in logs (SEC-3 spot check) | grep the smoke-test time window in application logs for the literal 64-char hex token used in 2.5/2.6 | Zero matches -- token must never appear in logs | [ASSIGN: Security Engineer] |

---

## 7. Metrics Flowing

| # | Check | Method | Expected | Owner |
|---|-------|--------|----------|-------|
| 7.1 | Prometheus/metrics endpoint reachable | GET /actuator/prometheus (or environment-equivalent) | HTTP 200, metrics payload returned | [ASSIGN: On-Call Engineer] |
| 7.2 | HTTP request metrics for new endpoints appear | Query the metrics backend for http_server_requests with uri matching /api/v1/auth/password/** after running section 2 | Non-zero count for both forgot and reset paths, broken out by status code | [ASSIGN: On-Call Engineer] |
| 7.3 | Async executor / mail queue metrics visible | Check existing Spring async executor metrics (task queue depth/active count) used by MailEventListener | Metrics present and queue depth near zero shortly after the smoke-test email (2.3) is dispatched | [ASSIGN: On-Call Engineer] |

---

## Sign-off

All sections 1-7 must show expected results before the deploy is declared complete (deployment-checklist.md step 3.1/3.5). Any unexpected result triggers an evaluation against rollback-checklist.md trigger conditions (T1-T8).

| Section | Pass/Fail | Verified By | Timestamp |
|---------|-----------|--------------|-----------|
| 1. Healthcheck | [ASSIGN: QA Engineer] | | |
| 2. Happy path | [ASSIGN: QA Engineer] | | |
| 3. Regression guard | [ASSIGN: QA Engineer] | | |
| 4. Rate limiting | [ASSIGN: QA Engineer] | | |
| 5. Error monitoring | [ASSIGN: On-Call Engineer] | | |
| 6. Logs flowing | [ASSIGN: On-Call Engineer] | | |
| 7. Metrics flowing | [ASSIGN: On-Call Engineer] | | |
