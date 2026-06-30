# Monitoring Checklist — US-007: Self-Service Password Reset via Email

Reference: monitoring.md (source guide), runbook.md (incident response), 03b-threat-model.md (threat IDs)

---

## 1. Dashboards to Watch

| # | Dashboard | Scope | Link | Owner |
|---|-----------|-------|------|-------|
| 1.1 | API Gateway / APM -- auth endpoints | HTTP status code breakdown for /api/v1/auth/password/forgot and /reset | [ASSIGN: DevOps -- attach APM dashboard URL] | [ASSIGN: On-Call Engineer] |
| 1.2 | Application logs -- identity context | Filtered view on com.example.nexus.identity package, this release's deploy timestamp onward | [ASSIGN: DevOps -- attach log aggregator URL] | [ASSIGN: On-Call Engineer] |
| 1.3 | Database performance -- auth_tokens / auth_events | Query latency and table size for the throttle COUNT query and audit INSERTs | [ASSIGN: DBA -- attach DB dashboard URL] | [ASSIGN: DBA] |
| 1.4 | Mail delivery / SMTP relay dashboard | Delivery success/bounce rate for the password-reset email template | [ASSIGN: DevOps -- attach mail relay dashboard URL] | [ASSIGN: On-Call Engineer] |
| 1.5 | Rate-limiter 429 dashboard | 429 response rate on /forgot and /reset, broken out by FORGOT_IP / FORGOT_USER / RESET_IP bucket if the metric is taggable | [ASSIGN: DevOps -- attach dashboard URL] | [ASSIGN: On-Call Engineer] |
| 1.6 | Security/SIEM dashboard | PASSWORD_RESET_FAILED and PASSWORD_RESET_THROTTLED volume, correlated by IP and account | [ASSIGN: Security Engineer -- attach SIEM dashboard URL] | [ASSIGN: Security Engineer] |

**Action:** all six dashboard links above must be populated with real URLs before the watch period begins -- placeholders are not acceptable for go-live. [ASSIGN: Release Manager]

---

## 2. Key Metrics: Baseline and Alert Thresholds

| Metric | Baseline (pre-launch, day 0) | Warning Threshold | Critical Threshold | Owner |
|--------|-------------------------------|--------------------|----------------------|-------|
| 5xx rate on /password/forgot | 0% (new endpoint, no traffic yet) | > 1% of requests over 5 min | > 5% of requests over 5 min | [ASSIGN: On-Call Engineer] |
| 5xx rate on /password/reset | 0% | > 1% of requests over 5 min | > 5% of requests over 5 min | [ASSIGN: On-Call Engineer] |
| 429 rate on /password/forgot | 0% | > 50 events/min | > 200 events/min | [ASSIGN: On-Call Engineer] |
| 410 rate on /password/reset | 0% | > 20 events/min | > 100 events/min | [ASSIGN: On-Call Engineer] |
| PASSWORD_RESET_FAILED events | 0/hour | > 50/hour | > 200/hour | [ASSIGN: Security Engineer] |
| PASSWORD_RESET_THROTTLED events | 0/day | > 0.1% of total reset requests/day | Any single account exceeding 3 throttle events/day | [ASSIGN: Security Engineer] |
| SESSION_REVOCATION_PARTIAL WARN logs | 0 (new code path, no historical baseline) | Any occurrence | > 5 in 1 hour | [ASSIGN: Backend Lead] |
| Mail delivery failures (SmtpMailSenderAdapter errors) | 0 | Any occurrence | > 5% bounce/error rate sustained 15 min | [ASSIGN: On-Call Engineer] |
| auth_tokens query p95 latency (throttle COUNT) | Pre-deploy baseline from existing ResendVerificationUseCase traffic on the same index | > 200ms p95 | > 500ms p95 | [ASSIGN: DBA] |
| Expired/unconsumed RESET tokens accumulating | 0 | > 5,000 rows WHERE type=RESET AND consumed_at IS NULL AND expires_at < NOW() | > 10,000 rows | [ASSIGN: Backend Lead] |
| Reset-to-login conversion (REQUESTED to CHANGED within 1h) | No historical baseline (new feature) -- establish after 7 days | < 50% conversion after 7-day baseline is set | < 30% conversion | [ASSIGN: Product Owner] |
| Async mail queue depth (MailEventListener executor) | Existing baseline from US-002/US-004 verification-email traffic | Queue depth > 100 | Queue depth > 500 or sustained growth over 10 min | [ASSIGN: Backend Lead] |

---

## 3. Log Queries for New Code Paths

| # | Purpose | Query | Owner |
|---|---------|-------|-------|
| 3.1 | Recent reset failures for a specific user (support investigation) | SELECT created_at, ip_address, metadata FROM auth_events WHERE event_type='PASSWORD_RESET_FAILED' AND created_at > NOW() - INTERVAL 24 HOUR ORDER BY created_at DESC; | [ASSIGN: On-Call Engineer] |
| 3.2 | IPs generating high PASSWORD_RESET_FAILED volume (possible token guessing, T-S1) | SELECT ip_address, COUNT(*) AS attempts FROM auth_events WHERE event_type='PASSWORD_RESET_FAILED' AND created_at > NOW() - INTERVAL 1 HOUR GROUP BY ip_address HAVING attempts > 10 ORDER BY attempts DESC; | [ASSIGN: Security Engineer] |
| 3.3 | Accounts hitting the throttle repeatedly (possible email-bomb target, T-D1/T-D4) | SELECT user_id, COUNT(*) AS throttles, MAX(created_at) AS last_throttle FROM auth_events WHERE event_type='PASSWORD_RESET_THROTTLED' AND created_at > NOW() - INTERVAL 24 HOUR GROUP BY user_id HAVING throttles > 3 ORDER BY throttles DESC; | [ASSIGN: Security Engineer] |
| 3.4 | PASSWORD_CHANGED not preceded by a RESET_REQUESTED (anomaly detection, T-R1) | SELECT pc.user_id, pc.created_at FROM auth_events pc WHERE pc.event_type='PASSWORD_CHANGED' AND pc.created_at > NOW() - INTERVAL 24 HOUR AND NOT EXISTS (SELECT 1 FROM auth_events pr WHERE pr.event_type='PASSWORD_RESET_REQUESTED' AND pr.user_id=pc.user_id AND pr.created_at BETWEEN pc.created_at - INTERVAL 2 HOUR AND pc.created_at); (some results expected for admin-initiated resets if that path exists; investigate volume) | [ASSIGN: Security Engineer] |
| 3.5 | Application log grep for session revocation partial failures | grep "SESSION_REVOCATION_PARTIAL" against the identity-context log stream, alert on any match | [ASSIGN: Backend Lead] |
| 3.6 | SEC-3 compliance spot check -- raw token must never appear in logs | grep against a known 64-char hex pattern from a test reset performed during the watch period; expect zero matches | [ASSIGN: Security Engineer] |
| 3.7 | Expired/unconsumed RESET token volume | SELECT COUNT(*) FROM auth_tokens WHERE type='RESET' AND consumed_at IS NULL AND expires_at < NOW(); run daily during the watch period | [ASSIGN: Backend Lead] |

---

## 4. On-Call Rotation Contact

| Role | Contact | Escalation Path |
|------|---------|-------------------|
| Primary on-call (deploy week) | [ASSIGN: On-Call Engineer -- name/PagerDuty rotation] | Escalates to Backend Lead after 15 min unacknowledged |
| Backend Lead | [ASSIGN: Backend Lead -- name/contact] | Escalates to Release Manager for rollback authorization |
| Security Engineer (for T8-class incidents, see rollback-checklist.md) | [ASSIGN: Security Engineer -- name/contact] | Direct page for any SIEM alert on PASSWORD_RESET_FAILED/THROTTLED spikes |
| Release Manager | [ASSIGN: Release Manager -- name/contact] | Final rollback go/no-go authority |

**Action:** populate actual names/PagerDuty schedule IDs before go-live; this checklist cannot be marked complete with placeholder contacts. [ASSIGN: Release Manager]

---

## 5. Watch Period

| Phase | Duration | Activity | Owner |
|-------|----------|----------|-------|
| Active watch | First 24 hours post-deploy | On-call engineer actively monitors all dashboards in section 1 at least hourly; immediate triage of any threshold breach from section 2 | [ASSIGN: On-Call Engineer] |
| Passive watch | Hours 24-48 post-deploy | Standard on-call monitoring (alert-driven, not active dashboard polling); daily metric review at the 48h mark | [ASSIGN: On-Call Engineer] |
| Baseline establishment | Days 3-7 post-deploy | Establish real baselines for metrics marked "no historical baseline" in section 2 (reset-to-login conversion, mail queue depth under real reset traffic); update thresholds if the MVP defaults prove miscalibrated | [ASSIGN: Backend Lead] |
| Sign-off | End of hour 48 | Release Manager confirms no unresolved alerts and closes the watch period | [ASSIGN: Release Manager] |
