# Monitoring Guide — US-008: Emit Audit Events for All Authentication Actions

_T-08-21 deliverable. Specification for ops to implement against the application's existing
`/actuator/prometheus` scrape endpoint. **No Grafana/Prometheus stack is checked into this repo**
(verified: no `grafana/`, `monitoring/`, `dashboards/` directory, and `docker-compose.yml` has no
`grafana`/`prometheus` service) — this document is the panel/alert specification, not
dashboard-as-code. Follows the `US-006/monitoring.md` and `US-007/monitoring.md` precedent format._

---

## Key Audit Events

All events are written to `auth_events` with `event_type` (one of the 9 canonical
`AuthEventType.wireName()` values plus retained granular states — see `03-design.md` §2.1),
`outcome`, `user_id` (nullable), `tenant_id` (nullable), `ip_address`, `user_agent` (nullable,
≤512 chars), `metadata` (JSON — `traceId`, `ip`, `userAgent`), and `created_at`.

| Priority-lane event type (routed via `AuthEventType.isPriority()`) | Meaning |
|---|---|
| `LOCKOUT` | Account locked after repeated failed logins |
| `TOKEN_REFRESH_REUSE` | Refresh-token-family reuse detected (revocation) |
| `PASSWORD_CHANGED` | Password successfully updated via reset flow |
| `ACCOUNT_LOCKED_WRITE_FAILED` | Lockout write itself failed — a write-path failure on the highest-value signal |

| Standard-lane event type (everything else) | Meaning |
|---|---|
| `LOGIN_SUCCESS` / `LOGIN_FAILURE` | Login outcome |
| `LOGOUT` | Session terminated, refresh token revoked |
| `REGISTER` / `REGISTRATION_DUPLICATE_EMAIL` | Registration outcome |
| `VERIFY` / `VERIFICATION_FAILED` | Email verification outcome |
| `PASSWORD_RESET_REQUESTED` / `PASSWORD_RESET_THROTTLED` / `PASSWORD_RESET_FAILED` | Password-reset flow |
| `TOKEN_REFRESH_SUCCESS` / `TOKEN_REFRESH_FAILURE` | Refresh-token flow (non-reuse outcomes) |
| `RESEND_REQUESTED` / `RESEND_THROTTLED` | Verification-email resend flow |
| `LOGIN_PENDING_ACCOUNT` / `ACCOUNT_UNLOCKED` | Retained granular login states |

The priority/standard split is a **retry-buffer routing concern only** (`AuthEventRetryBuffer`,
ADR 0011) — both lanes write to the same `auth_events` table under normal (DB-healthy) operation.
The split only becomes observable when the synchronous insert is failing and events are buffered.

---

## Metric Names (Micrometer → Prometheus exposition)

The six `nexus.audit.*` metrics registered by `AuthEventRetryBuffer` (5 metrics) and
`LoggingAuditAlertAdapter` (1 metric) — exact names verified against
`identity/infrastructure/audit/AuthEventRetryBuffer.java` as actually implemented (source of
truth; the design doc's §4.5 sketch matches the implementation 1:1, no drift found):

| Source name (Java, dotted) | Prometheus scrape name (dots→underscores, `_total` on counters) | Type | Tags |
|---|---|---|---|
| `nexus.audit.buffer.depth` | `nexus_audit_buffer_depth` | Gauge | `lane=priority\|standard` |
| `nexus.audit.buffer.oldest.age.seconds` | `nexus_audit_buffer_oldest_age_seconds` | Gauge | `lane=priority\|standard` |
| `nexus.audit.retry.success` | `nexus_audit_retry_success_total` | Counter | `lane=priority\|standard` |
| `nexus.audit.retry.exhausted` | `nexus_audit_retry_exhausted_total` | Counter | `lane=priority\|standard` |
| `nexus.audit.buffer.dropped` | `nexus_audit_buffer_dropped_total` | Counter | `reason=overflow`, `lane=priority\|standard` |
| `nexus.audit.alert.raised` | `nexus_audit_alert_raised_total` | Counter | `type=BUFFER_DEPTH_WARN\|BUFFER_DEPTH_CRITICAL\|BUFFER_AGE_CRITICAL\|RETRY_EXHAUSTED` |

Scraped via the existing `/actuator/prometheus` endpoint (already exposed and auth-gated per
`observability-standards.md` — metrics require auth, only `health`/`info` are public).

---

## Dashboard — Grafana Row Specification

One Grafana row, per `03-design.md` §4.5/§10.2's sketch. **Priority-lane panels are placed first
and are visually prominent** — during an incident, the single most important signal is "does the
priority lane stay near zero while the standard lane absorbs the damage" (the T-D1 mitigation
made observable; see `03b-threat-model.md` T-D1: *"if priority-lane depth/age stays near zero
while standard-lane drops climb, the system is behaving as designed"*).

| # | Panel | Type | Query | Placement |
|---|-------|------|-------|-----------|
| 1 | **Priority-lane depth** | Gauge | `nexus_audit_buffer_depth{lane="priority"}` | Left column, top — most prominent panel on the row |
| 2 | **Priority-lane oldest age** | Gauge | `nexus_audit_buffer_oldest_age_seconds{lane="priority"}` | Left column, below #1 |
| 3 | Standard-lane depth | Gauge | `nexus_audit_buffer_depth{lane="standard"}` | Left column, below #2 |
| 4 | Standard-lane oldest age | Gauge | `nexus_audit_buffer_oldest_age_seconds{lane="standard"}` | Left column, below #3 |
| 5 | Retry-success rate (by lane) | Graph (rate) | `rate(nexus_audit_retry_success_total[5m])` — split by `lane` | Right column, top |
| 6 | Retry-exhausted + dropped rate (by lane) | Graph (rate, stacked) | `rate(nexus_audit_retry_exhausted_total[5m])` and `rate(nexus_audit_buffer_dropped_total{reason="overflow"}[5m])` — split by `lane` | Right column, below #5 |
| 7 | Alert-raised count by type | Counter / table | `increase(nexus_audit_alert_raised_total[1h])` — split by `type` | Bottom, full width |

**Reading the dashboard during an incident (per threat-model T-D1 framing):** if panel #1
(priority depth) and #2 (priority age) stay near zero while panels #3/#4 climb and panel #6 shows
a rising standard-lane drop rate, the two-lane design is working as intended — a `LOGIN_FAILURE`
flood or DB outage is degrading the low-value standard lane without touching the four
security-critical priority event types. If panel #1 or #2 moves off zero at all, treat it as
urgent regardless of panel #6 (see depth-warn threshold below — priority depth-warn is ≥1, not a
percentage).

---

## Alert Rules

Bound 1:1 to `03-design.md` §4.1 / ADR 0011 §2 / `AuditRetryProperties.LaneThresholds` — **verified
against the actual configured defaults in `application.yml` (see Threshold Verification below),
not re-derived from the design doc alone.**

| Alert | PromQL expression | For | Severity | Threshold source |
|---|---|---|---|---|
| Standard-lane depth warn | `nexus_audit_buffer_depth{lane="standard"} >= 250` | 1m | ticket | `AuditRetryProperties.LaneThresholds.standardDefaults().depthWarn()` = 250 |
| Priority-lane depth warn | `nexus_audit_buffer_depth{lane="priority"} >= 1` | 1m | ticket | `...priorityDefaults().depthWarn()` = 1 |
| Standard-lane depth critical | `nexus_audit_buffer_depth{lane="standard"} >= 720` | 1m | page | `...standardDefaults().depthCritical()` = 720 (90% of 800) |
| Priority-lane depth critical | `nexus_audit_buffer_depth{lane="priority"} >= 180` | 1m | page | `...priorityDefaults().depthCritical()` = 180 (90% of 200) |
| Age critical — either lane | `nexus_audit_buffer_oldest_age_seconds{lane=~"priority\|standard"} > 900` | (instant — evaluate every scrape interval) | page | `...ageCritical()` = 15m = 900s (both lanes) |
| Retry exhaustion occurred | `increase(nexus_audit_retry_exhausted_total[5m]) > 0` | — | ticket | ADR 0011 §2 "on attempt-5 exhaustion... `RETRY_EXHAUSTED`" |
| Buffer overflow occurred | `increase(nexus_audit_buffer_dropped_total{reason="overflow"}[5m]) > 0` | — | ticket | ADR 0011 §1/§2 drop-newest overflow policy |

**Owner:** identity/auth on-call rotation (same as US-005/US-006/US-007 auth-flow alerts).

**Runbook link:** `docs/features/US-008/runbook.md` — **this file does not exist yet.** Per
`observability-standards.md`'s Alerts section, every alert must link a runbook. Authoring
`runbook.md` is explicitly **out of scope for T-08-21** (not listed in `04-tasks.md`'s T-08-21
file list) and is called out here as a transparent, tracked gap rather than a silent dead link or
a fabricated placeholder file — **follow-up task required before these alert rules are wired into
a real ops-facing Prometheus instance.** Until that file exists, on-call should treat this
`monitoring.md` document itself as the interim reference (event taxonomy, metric names, thresholds,
and the T-D1 "is this working" dashboard-reading guidance above).

### Threshold verification (this doc's numbers vs. the shipped code)

Cross-checked directly against `nexus-backend/src/main/resources/application.yml` (the actually
configured values, which match `AuditRetryProperties.LaneThresholds`'s coded defaults exactly):

```yaml
# priority lane
depth-warn: 1            # any sustained priority-lane backlog is anomalous
depth-critical: 180      # 90% of priority-capacity
age-critical: 15m

# standard lane
depth-warn: 250          # 25% of standard-capacity
depth-critical: 720      # 90% of standard-capacity
age-critical: 15m
```

These match the alert-rule table above exactly (250/720 standard, 1/180 priority, 15m age-critical
both lanes) — **no drift between design, ADR, configured YAML, and this monitoring spec.**

---

## Log Patterns

| Situation | Log line | Notes |
|---|---|---|
| Synchronous audit insert fails | `WARN JpaAuthEventAdapter — Audit write failed [type=<wireName>] — enqueueing for retry: <message>` | Never includes `user_agent` or any raw UA-derived string (T-I1) — only the enum wire name and exception message |
| Buffer lane full on enqueue | `WARN AuthEventRetryBuffer — Audit retry buffer lane full — dropping newest event [lane=<lane>, type=<wireName>]` | |
| Buffer lane full during drain requeue | `WARN AuthEventRetryBuffer — Audit retry buffer lane filled during drain — dropping requeued event [lane=<lane>, type=<wireName>]` | |
| Retry exhausted (attempt 5) | `WARN AuthEventRetryBuffer — Audit event dropped after exhausting retries [lane=<lane>, type=<wireName>]` + `AuditAlertPort.raise(RETRY_EXHAUSTED)` | |
| Drain-loop structural exception (T-D4 guard) | `ERROR AuthEventRetryBuffer — Unexpected exception in AuthEventRetryBuffer.drain() — scheduler continues` | Scheduler thread survives; next `fixedDelay` tick still runs |

---

## Log Queries

### Find all LOCKOUT events for a user in the last 24 hours

```sql
SELECT created_at, ip_address, user_agent, metadata
FROM auth_events
WHERE event_type = 'LOCKOUT'
  AND user_id = :userId
  AND created_at > NOW() - INTERVAL 24 HOUR
ORDER BY created_at DESC;
```

### Find TOKEN_REFRESH_REUSE events (family-revocation / possible token theft) in the last hour

```sql
SELECT user_id, tenant_id, ip_address, user_agent, created_at
FROM auth_events
WHERE event_type = 'TOKEN_REFRESH_REUSE'
  AND created_at > NOW() - INTERVAL 1 HOUR
ORDER BY created_at DESC;
```

### Find events with a NULL tenant_id post-auth (should only be LOGOUT or pre-auth failures)

```sql
SELECT event_type, COUNT(*) AS cnt
FROM auth_events
WHERE tenant_id IS NULL
  AND created_at > NOW() - INTERVAL 24 HOUR
GROUP BY event_type
ORDER BY cnt DESC;
```
*(Per `03-design.md` §5: `LOGOUT` is expected here by design (accepted NULL, Open Unknown #5); any
other event type appearing here at volume is worth investigating as a WS-4 population regression.)*

---

## Operational Baselines

| Metric | Expected baseline |
|--------|-------------------|
| `nexus_audit_buffer_depth{lane="priority"}` | 0 under normal (DB-healthy) operation at all times |
| `nexus_audit_buffer_depth{lane="standard"}` | 0 under normal operation; brief non-zero spikes only during genuine transient DB blips |
| `nexus_audit_retry_exhausted_total` | 0 — any increase means events were permanently dropped after 5 attempts |
| `nexus_audit_buffer_dropped_total{reason="overflow"}` | 0 — any increase means a lane hit capacity |
| Load-test baseline (Test Scenario 5, T-08-20) | 100 RPS / 10 min sustained login against a healthy DB: zero `buffer.dropped`, zero `retry.exhausted`, `auth_events` row count == emitted event count |

---

## Cross-references

- `docs/features/US-008/03-design.md` §4.1 (SLO/threshold table), §4.5 (metric names), §10.2 (observability plan / dashboard sketch)
- `docs/features/US-008/03b-threat-model.md` — T-D1 (priority-lane visibility is the key "is this working" signal), T-I2 (see `docs/adr/0011-in-process-bounded-retry-buffer-for-audit-writes.md` §7 for the recorded cross-story obligation this monitoring doc does not itself resolve)
- `docs/adr/0011-in-process-bounded-retry-buffer-for-audit-writes.md` (two-lane design, thresholds, accepted residuals)
- `docs/observability-standards.md` (Phase-9 checklist, dashboard/alert quality bar, audit-log JSON shape)
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/AuthEventRetryBuffer.java` (implementation — metric names verified against this file directly)
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/AuditRetryProperties.java` (threshold defaults)
- `nexus-backend/src/main/resources/application.yml` (configured threshold values — verified matching)
