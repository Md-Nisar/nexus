# Monitoring Guide — US-007: Self-Service Password Reset

---

## Key Audit Events

All events are written to `auth_events` table with `event_type`, `outcome`, `user_id`, `ip_address`, `created_at`, and a `metadata` JSON column.

| Event type | Outcome | Meaning |
|-----------|---------|---------|
| `PASSWORD_RESET_REQUESTED` | SUCCESS | Token generated and email queued |
| `PASSWORD_RESET_THROTTLED` | FAILURE | Account hit 3-per-hour limit; no email sent |
| `PASSWORD_RESET_FAILED` | FAILURE | Invalid/expired/consumed token submitted to /reset |
| `PASSWORD_CHANGED` | SUCCESS | Password successfully updated via reset flow |

---

## Log Patterns

### Reset request accepted (found account)

```
DEBUG ... ForgotPasswordUseCase : (no explicit log — audit event is the record)
```

### Reset request throttled

```
DEBUG ... ForgotPasswordUseCase : PASSWORD_RESET_THROTTLED userId=<uuid>
```

### Reset failed (bad token)

```
WARN  ... ResetPasswordUseCase  : (no explicit log — audit event is the record)
```
*Note: `recordFailure()` writes to auth_events, not to application logs, to avoid log-enumeration.*

### Session revocation partial failure

```
WARN  ... ResetPasswordUseCase  : SESSION_REVOCATION_PARTIAL userId=<uuid> reason=<message>
```
Alert on this log line in production — it signals that some refresh-token families may survive a reset.

### Rate limit triggered

```
INFO (HTTP 429 response written directly by LoginRateLimitFilter — no log line)
```
Monitor via HTTP 429 rate on `/api/v1/auth/password/forgot` and `/api/v1/auth/password/reset`.

---

## Metrics and Alerts

### HTTP response codes

| Endpoint | 202 | 400 | 410 | 429 |
|----------|-----|-----|-----|-----|
| `POST /forgot` | Normal | Validation error | N/A | Rate limited |
| `POST /reset` | N/A | Policy / same-password | Bad/expired token | Rate limited |

**Alert thresholds (suggested):**

| Metric | Warning | Critical |
|--------|---------|----------|
| 429s on `/forgot` per minute | > 50 | > 200 |
| 410s on `/reset` per minute | > 20 | > 100 |
| `PASSWORD_RESET_FAILED` events per hour | > 50 | > 200 |
| `SESSION_REVOCATION_PARTIAL` WARN log | Any | — |
| Mail delivery failures (SMTP errors in `MailEventListener`) | Any | — |

### Database

| Query | Alert if |
|-------|----------|
| `auth_tokens WHERE type='RESET' AND consumed_at IS NULL AND expires_at < NOW()` | Count > 10,000 (expired tokens not being cleaned up) |

Add a periodic cleanup job to delete expired/consumed reset tokens older than 24 hours if table volume becomes a concern.

---

## Log Queries

### Find all PASSWORD_RESET_FAILED events for a user in the last 24 hours

```sql
SELECT created_at, ip_address, metadata
FROM auth_events
WHERE event_type = 'PASSWORD_RESET_FAILED'
  AND created_at > NOW() - INTERVAL 24 HOUR
ORDER BY created_at DESC;
```

### Find IPs generating high PASSWORD_RESET_FAILED volume (possible token guessing)

```sql
SELECT ip_address, COUNT(*) as attempts
FROM auth_events
WHERE event_type = 'PASSWORD_RESET_FAILED'
  AND created_at > NOW() - INTERVAL 1 HOUR
GROUP BY ip_address
HAVING attempts > 10
ORDER BY attempts DESC;
```

### Find accounts hitting the throttle repeatedly

```sql
SELECT user_id, COUNT(*) as throttles, MAX(created_at) as last_throttle
FROM auth_events
WHERE event_type = 'PASSWORD_RESET_THROTTLED'
  AND created_at > NOW() - INTERVAL 24 HOUR
GROUP BY user_id
HAVING throttles > 3
ORDER BY throttles DESC;
```

### Find PASSWORD_CHANGED events not preceded by a RESET_REQUESTED (anomaly detection)

```sql
SELECT pc.user_id, pc.created_at
FROM auth_events pc
WHERE pc.event_type = 'PASSWORD_CHANGED'
  AND pc.created_at > NOW() - INTERVAL 24 HOUR
  AND NOT EXISTS (
    SELECT 1 FROM auth_events pr
    WHERE pr.event_type = 'PASSWORD_RESET_REQUESTED'
      AND pr.user_id = pc.user_id
      AND pr.created_at BETWEEN pc.created_at - INTERVAL 2 HOUR AND pc.created_at
  );
```
*(Some results are expected for admin-initiated resets; investigate any at volume.)*

---

## Operational Baselines

These baselines apply to a typical low-traffic deployment. Adjust after observing production traffic.

| Metric | Expected baseline |
|--------|-------------------|
| `PASSWORD_RESET_REQUESTED` events per day | < 1% of active user count |
| `PASSWORD_RESET_THROTTLED` per day | < 0.1% of reset requests |
| `PASSWORD_RESET_FAILED` per day | < 5% of reset-link clicks |
| Reset-to-login conversion (REQUESTED → CHANGED) | > 70% within 1 hour |
| SMTP delivery latency (async, not in request path) | < 30 s (P95) |
