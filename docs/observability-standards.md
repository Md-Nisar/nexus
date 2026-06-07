# Observability Standards — Nexus

## Three Pillars

| Pillar | Tool | Config location |
|--------|------|-----------------|
| **Logs** | SLF4J + Logback (JSON in prod) | `logback-spring.xml` |
| **Metrics** | Spring Actuator + Micrometer | Actuator endpoints |
| **Traces** | W3C `traceparent`, correlated by `traceId` | MDC + filter |

All three must flow for a feature to be considered observable. A feature without dashboards and alerts is not production-ready.

---

## Logging

### Level discipline

| Level | When to use |
|-------|------------|
| `ERROR` | Unhandled exception, data corruption risk, external dependency down |
| `WARN` | Recoverable failure, rate-limit hit, deprecated API call, unexpected input |
| `INFO` | Significant business event: user created, order placed, payment confirmed |
| `DEBUG` | Developer-level internals — query params, cache hit/miss. Off in prod |
| `TRACE` | Execution path, loop iterations. Almost never shipped |

### Format

Structured, key=value pairs. In production, emit as JSON (configured in `logback-spring.xml` via `spring.profiles.active=prod`):

```
INFO  [traceId=abc123 userId=usr_01 tenantId=tnt_01] PasswordResetService - password reset requested email=u***@example.com tokenId=tok_01
```

### Required MDC fields

Set in a Servlet filter at request entry; cleared in `finally`:

| Field | Source |
|-------|--------|
| `traceId` | `traceparent` header if present; else `UUID.randomUUID()` |
| `userId` | JWT claim `sub`, or `anonymous` |
| `tenantId` | JWT claim `tenantId`, or `none` |
| `requestId` | Internal request counter for fan-out |

### Forbidden in logs

- Passwords (any form)
- Auth tokens (access, refresh, reset)
- Full email addresses — mask as `u***@example.com`
- Credit card numbers
- SSN / government IDs
- Full request / response bodies
- Stack traces in `INFO` or above — errors use `log.error("...", exception)`

### Masking helpers

```java
// Email masking: alice@example.com → a***@example.com
public static String maskEmail(String email) {
    int at = email.indexOf('@');
    if (at <= 1) return "***" + email.substring(at);
    return email.charAt(0) + "***" + email.substring(at);
}

// ID masking: usr_01ABCDE12345 → usr_01AB***
public static String maskId(String id) {
    return id.length() > 8 ? id.substring(0, 8) + "***" : "***";
}
```

### Log injection prevention

Before logging any user-supplied string, sanitise CRLF:

```java
private static String sanitize(String input) {
    return input == null ? null : input.replaceAll("[\r\n]", "_");
}
```

---

## Metrics

### Naming convention

```
<namespace>_<subject>_<unit>_<aggregation>
nexus_auth_login_requests_total
nexus_auth_login_errors_total
nexus_auth_login_duration_seconds   (histogram)
nexus_db_queries_duration_seconds   (histogram)
```

### Standard metrics for every feature

| Metric | Type | Labels |
|--------|------|--------|
| `nexus_<feature>_requests_total` | Counter | `method`, `status` |
| `nexus_<feature>_errors_total` | Counter | `error_code` |
| `nexus_<feature>_duration_seconds` | Histogram | `method` |

### Cardinality discipline

Label values must have bounded cardinality. **Never** use as a label:
- `userId` (unbounded)
- `email` (unbounded, PII)
- `sessionId`
- Free-form error messages

Use: `status` (success/failure), `error_code` (SCREAMING_SNAKE_CASE, from a fixed list), `method`.

### Histogram buckets

For HTTP response latency, use buckets: `[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5]` seconds. This gives good resolution for p95 and p99 targets.

### Spring Actuator

Expose Actuator at a separate port (e.g., 1001) not accessible from the public internet:
- `/actuator/health` — liveness + readiness
- `/actuator/metrics` — Micrometer
- `/actuator/prometheus` — Prometheus scrape endpoint

---

## Distributed Tracing

Use W3C `traceparent` header format:

```
traceparent: 00-<traceId>-<parentSpanId>-<flags>
```

- Extract from inbound request in a filter; set in MDC as `traceId`.
- Forward in all outbound HTTP calls.
- Return `X-Trace-Id: <traceId>` in responses so clients can correlate errors.

---

## Dashboards

Every feature that ships must have a Grafana dashboard row (or panel group) with:

| Panel | What to show |
|-------|-------------|
| Request rate | Requests per second by endpoint |
| Error rate | Errors per second by error_code |
| Latency | p50 / p95 / p99 by endpoint |
| Active sessions | (if applicable) |
| Feature-specific KPI | Business metric (e.g., password reset success rate) |

Link from `docs/features/<FEATURE-ID>/monitoring.md`.

---

## Alerts

### Alert quality bar

Every alert must answer: "What broke, who does it affect, and what do I do?"

| Property | Requirement |
|----------|-------------|
| Name | `nexus_<service>_<symptom>` |
| Severity | `page` (wake someone up) / `ticket` (creates a Jira) / `info` |
| Threshold | Specific. "Error rate > 1% for 5m" not "errors are high" |
| Runbook link | Link to `docs/features/*/runbook.md` |
| Owner | Which team / on-call rotation |

### Standard alert thresholds

| Alert | Threshold | Severity |
|-------|-----------|----------|
| Error rate spike | > 1% for 5 min | page |
| Latency p95 degradation | > 2× baseline for 10 min | ticket |
| DB connection pool exhausted | > 90% for 2 min | page |
| Disk usage | > 80% | ticket |
| Feature toggle missing | Flag not found at startup | page |

---

## Audit Log

Security-relevant events go to a separate audit log with guaranteed delivery (write-ahead log, or separate DB table never deleted by application code):

```json
{
  "timestamp": "2025-11-14T09:12:00.000Z",
  "eventType": "PASSWORD_RESET_REQUESTED",
  "actor": { "userId": null, "email": "u***@example.com" },
  "target": { "type": "User", "id": null },
  "outcome": "ACCEPTED",
  "metadata": {
    "ip": "192.168.1.1",
    "userAgent": "Mozilla/5.0 ...",
    "traceId": "abc-123"
  }
}
```

Audit log is append-only. No application code deletes from it. Retention: minimum 1 year.

---

## Per-Feature Observability Checklist

At Phase 9 (documentation), confirm each item exists:

- [ ] Metrics registered and emitting (verify in staging with `/actuator/prometheus`)
- [ ] MDC fields set correctly on new code paths
- [ ] Audit events fired for all security-relevant actions
- [ ] Dashboard panel(s) added and linked
- [ ] Alerts defined with thresholds and runbook links
- [ ] Log queries documented in `monitoring.md`
- [ ] Baseline captured before release for anomaly detection
