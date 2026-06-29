# US-006 Monitoring Guide

## Key audit events to track

All lockout-related events are written to `auth_events` via `SecureEventService.recordEvent` (each in its own REQUIRES_NEW TX, guaranteed to commit even when the outer login TX rolls back).

| Event name | event_type | outcome | Meaning |
|------------|-----------|---------|---------|
| `ACCOUNT_LOCKED` | `ACCOUNT_LOCKED` | `FAILURE` | Account transitioned to LOCKED after 5 consecutive failures |
| `ACCOUNT_UNLOCKED` | `ACCOUNT_UNLOCKED` | `SUCCESS` | Expired lock auto-cleared on successful login |
| `ACCOUNT_LOCKED_WRITE_FAILED` | `ACCOUNT_LOCKED_WRITE_FAILED` | `FAILURE` | Inner REQUIRES_NEW TX failed (non-OL exception); lockout write silently skipped |
| `LOGIN_FAILURE` | `LOGIN_FAILURE` | `FAILURE` | Every failed login attempt (credential failure or on locked account) |

## Metrics and alert thresholds

### Alert 1 — Mass account lockout campaign (T-LCK-3)

```sql
-- accounts locked in last 15 minutes
SELECT COUNT(*) FROM auth_events
WHERE event_type = 'ACCOUNT_LOCKED'
  AND recorded_at > NOW() - INTERVAL 15 MINUTE;
```

**Alert threshold:** > 10 `ACCOUNT_LOCKED` events in 15 minutes on the same tenant.
**Severity:** HIGH — possible credential-stuffing campaign.
**Action:** Review source IPs in `metadata` JSON; consider emergency IP block at the load-balancer level.

### Alert 2 — Lockout write failures (T-LCK-12)

```sql
-- write failures in last 5 minutes
SELECT COUNT(*) FROM auth_events
WHERE event_type = 'ACCOUNT_LOCKED_WRITE_FAILED'
  AND recorded_at > NOW() - INTERVAL 5 MINUTE;
```

**Alert threshold:** > 0 in 5 minutes.
**Severity:** CRITICAL — when this fires, the lockout mechanism is silently disabled. Every `ACCOUNT_LOCKED_WRITE_FAILED` event means a failed-attempt counter write was dropped.
**Action:** Check DB connection pool (HikariCP) health; check for deadlocks (`SHOW ENGINE INNODB STATUS`); check `nexus-backend` logs for `ACCOUNT_LOCKED_WRITE_FAILED userId=` WARN entries.

### Alert 3 — Login failure spike

```sql
-- failures per minute
SELECT DATE_FORMAT(recorded_at, '%Y-%m-%d %H:%i') as minute, COUNT(*) as failures
FROM auth_events
WHERE event_type = 'LOGIN_FAILURE'
  AND recorded_at > NOW() - INTERVAL 1 HOUR
GROUP BY minute
ORDER BY minute;
```

**Alert threshold:** > 100 `LOGIN_FAILURE` events per minute.
**Severity:** MEDIUM.
**Action:** Correlate with `ACCOUNT_LOCKED` events; if many accounts locking, escalate to HIGH.

## Log queries (application logs)

All application logs use structured JSON (Logback). Key patterns:

```
# Account locked — userId is a UUID
level=WARN logger=SecureEventService msg="ACCOUNT_LOCKED" userId=<uuid>

# Optimistic-lock collision (benign, debug only)
level=DEBUG logger=SecureEventService msg="ACCOUNT_LOCK_INCREMENT_LOST" userId=<uuid>

# Write failure (non-OL exception — needs investigation)
level=WARN logger=SecureEventService msg="ACCOUNT_LOCKED_WRITE_FAILED" userId=<uuid>

# Reset failure on successful login (benign)
level=WARN logger=SecureEventService msg="ACCOUNT_RESET_WRITE_FAILED" userId=<uuid>

# Successful login
level=DEBUG logger=LoginUseCase msg="LOGIN_SUCCESS" userId=<uuid> tenantId=<uuid>
```

## Dashboard panels (Grafana / Prometheus)

If Prometheus scraping is enabled (`/actuator/prometheus`):

| Panel | Query / SQL |
|-------|-------------|
| Accounts locked per hour | `auth_events` table; group by hour |
| Login failure rate | `auth_events` WHERE event_type = 'LOGIN_FAILURE'; rate per minute |
| Active locked accounts | `SELECT COUNT(*) FROM users WHERE status = 'LOCKED'` |
| Write failure count | `auth_events` WHERE event_type = 'ACCOUNT_LOCKED_WRITE_FAILED' |
| 429 rate (rate-limit hits) | Spring MVC `http.server.requests` metric, status=429, uri=/api/v1/auth/login |
| 423 rate (lockout hits) | Spring MVC `http.server.requests` metric, status=423 |

## Baseline values (post-deployment, healthy system)

| Metric | Expected baseline |
|--------|-----------------|
| `ACCOUNT_LOCKED` events / hour | < 5 in a healthy system with real users |
| `ACCOUNT_LOCKED_WRITE_FAILED` events | 0 — any non-zero value requires investigation |
| Active `LOCKED` users | < 1% of active user base |
| 423 response rate | < 0.1% of login requests |
| `ACCOUNT_LOCK_INCREMENT_LOST` debug log | Occasional under high concurrency; not an alert |
