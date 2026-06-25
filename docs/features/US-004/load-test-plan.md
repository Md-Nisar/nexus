# US-004 Load Test Plan — POST /api/v1/auth/refresh

Date: 2026-06-24  
Target NFR: p95 < 150 ms at 200 RPS sustained for 10 min (TS-5)

---

## 1. Objectives

1. Confirm `POST /api/v1/auth/refresh` meets the p95 < 150 ms NFR at 200 RPS.
2. Verify that 0 theft-detection family-revocation events (`REFRESH_FAMILY_REVOKED`) occur under
   normal concurrent multi-client refresh traffic (no false positives from the proactive path).
3. Verify the `idx_refresh_tokens_token_hash` UNIQUE index is sufficient at this load (no V4
   `idx_refresh_tokens_expires_at` required).

---

## 2. Tool

**k6** (preferred) or Gatling.

---

## 3. Pre-conditions

1. Pre-seed **5 000 ACTIVE users** with valid refresh tokens (14-day TTL) in the target environment.
   Use a seeding script that calls `POST /auth/login` for each user and captures the `refresh_token`
   cookie. Store cookie values in a k6 `SharedArray` data file.
2. Set `nexus.security.rate-limit.max-attempts=100000` and `window-seconds=3600` in the load-test
   environment's `application.yml` override — prevents the per-IP throttle from interfering with
   the test (same approach as US-003 load test).
3. Argon2 parameters **must match production** (not dev) to measure realistic `POST /login` cost;
   for the refresh path only (no Argon2 involved) this is not load-test-sensitive, but environment
   parity is required to avoid misleading baseline numbers.
4. MySQL instance sized identically to production (same IOPS, same connection pool).

---

## 4. Load Profile

```
Ramp:    0 → 200 RPS over 60 s
Sustain: 200 RPS for 10 min
Ramp-down: 200 → 0 RPS over 30 s
```

Each virtual user:
1. Pick a cookie from the pre-seeded pool (round-robin, no recycling of already-consumed tokens).
2. `POST /api/v1/auth/refresh` with `Cookie: refresh_token=<value>`.
3. Assert HTTP 200 and a non-empty `accessToken` in the response body.
4. Discard the rotated `Set-Cookie` (single rotation per VU to avoid the token-reuse false-positive
   scenario — the test validates throughput, not rotation chains).

---

## 5. Assertions

| Metric | Target | Fail condition |
|--------|--------|----------------|
| p95 response time | < 150 ms | p95 ≥ 150 ms |
| p99 response time | < 300 ms | p99 ≥ 300 ms |
| Error rate (non-200) | 0 % | Any 4xx/5xx |
| `REFRESH_FAMILY_REVOKED` audit events during test | 0 | Any occurrence (indicates false theft detection) |
| DB connection pool exhaustion | 0 | Any `HikariPool-1 - Connection is not available` in server logs |

---

## 6. Monitoring During Test

- **Grafana / server metrics:** refresh p95/p99 latency, DB connection pool active/waiting,
  `auth_events` insert rate, GC pause time.
- **MySQL `EXPLAIN`:** verify `uq_refresh_tokens_token_hash` UNIQUE index is used for
  `findByTokenHash`; confirm no full-table scan.
- **`REFRESH_FAMILY_REVOKED` count** (query `auth_events` at end of run):
  `SELECT COUNT(*) FROM auth_events WHERE event_type = 'REFRESH_FAMILY_REVOKED'` — must be 0.

---

## 7. Acceptance Criteria

The load test passes when **all** of the following hold after the sustained 10-min window:

- [x] p95 < 150 ms
- [x] p99 < 300 ms
- [x] 0 non-200 responses
- [x] 0 `REFRESH_FAMILY_REVOKED` events
- [x] Server logs: no connection-pool exhaustion, no `OutOfMemoryError`

---

## 8. Known Limitations / Notes

- **In-memory `InMemoryRateLimitStore`:** counters are per-JVM; load test uses a single server
  instance. In multi-replica production, per-IP counts are not shared. Rate-limiting behaviour
  under distributed load is out of scope for this test.
- **Single-rotation tokens:** each VU uses its pre-seeded token exactly once; this does not model
  long-lived sessions that rotate many times. Multi-rotation chain load testing is a separate
  concern (no known NFR).
- **V4 index decision:** if p95 ≥ 150 ms and profiling shows `expires_at` range scans are the
  bottleneck, create `idx_refresh_tokens_expires_at` (V4, reserved slot) and retest. Based on
  the current design (UNIQUE hash index lookup, no range scan), this is not expected.
