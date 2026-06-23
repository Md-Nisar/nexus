# US-003 Load Test Plan — JWT Login Flow

**Feature:** US-003 — Login (JWT access + refresh tokens)
**Environment:** Staging (MySQL, 2 vCPU / 4 GB, no CDN)
**Tool:** [k6](https://k6.io/) (JavaScript DSL, open-source)

---

## Objectives

| # | Objective | Pass threshold |
|---|-----------|----------------|
| 1 | Confirm login p95 latency meets NFR under target load | p95 < 500 ms at 100 concurrent users |
| 2 | Confirm rate-limit kick-in does not degrade non-throttled users | p99 for non-throttled VUs < 1 s |
| 3 | Confirm refresh-token rotation holds correctness under concurrent load | 0 double-spend / theft-detection false positives at 50 concurrent VUs |
| 4 | Confirm Argon2 does not saturate CPU and starve other endpoints | CPU headroom ≥ 20 % at steady state |
| 5 | Confirm audit events are written without blocking the login path | p95 login latency not affected by `jpa_auth_events` write volume |

---

## Scenarios

### Scenario 1 — Steady-state login ramp

```js
export const options = {
  stages: [
    { duration: '1m', target: 25 },   // ramp up
    { duration: '3m', target: 100 },  // steady state
    { duration: '1m', target: 0 },    // ramp down
  ],
  thresholds: {
    'http_req_duration{name:login}': ['p(95)<500'],
    'http_req_failed{name:login}': ['rate<0.01'],
  },
};

export default function () {
  const payload = JSON.stringify({
    email: `user-${__VU}@loadtest.example.com`,
    password: 'LoadTest99!',
  });
  const res = http.post(`${BASE_URL}/api/v1/auth/login`, payload, {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: 'login' },
  });
  check(res, { 'login 200': (r) => r.status === 200 });
  sleep(1);
}
```

**Pre-condition:** 100 active users pre-seeded in the staging DB (one per VU). Each VU authenticates
with its own email to avoid username-key rate-limit interference between VUs.

**Expected:** p95 < 500 ms, < 1 % HTTP errors, CPU < 80 %.

---

### Scenario 2 — Rate-limit isolation

```js
// 5 VUs hammer a single IP with wrong passwords, 95 VUs log in legitimately.
// Throttled VUs should see 429; legitimate VUs should be unaffected.
export const options = {
  scenarios: {
    throttled: {
      executor: 'constant-vus', vus: 5, duration: '2m',
      exec: 'hammering',
    },
    legitimate: {
      executor: 'constant-vus', vus: 95, duration: '2m',
      exec: 'normal',
      thresholds: { 'http_req_duration{name:login}': ['p(99)<1000'] },
    },
  },
};
export function hammering() {
  http.post(`${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ email: 'victim@loadtest.example.com', password: 'Wrong!' }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'hammer' } });
  sleep(0.1);
}
export function normal() {
  // same as Scenario 1 normal login
  sleep(1);
}
```

**Expected:** Throttled VUs receive 429 after `max-attempts` exceeded; legitimate VU p99 < 1 s.

---

### Scenario 3 — Concurrent refresh-token rotation

```js
// 50 VUs each hold a valid session. Every iteration: login → extract cookie →
// refresh → verify new access token → repeat.
export const options = {
  scenarios: {
    rotation: {
      executor: 'constant-vus', vus: 50, duration: '2m',
    },
  },
  thresholds: {
    'http_req_duration{name:refresh}': ['p(95)<300'],
    'checks': ['rate>0.999'],   // 0 double-spend / unexpected theft events
  },
};
export default function () {
  // Login
  const loginRes = http.post(/* ... */);
  const cookie = extractCookie(loginRes.headers['Set-Cookie']);
  // Refresh
  const refreshRes = http.post(`${BASE_URL}/api/v1/auth/refresh`, null, {
    headers: { Cookie: `refresh_token=${cookie}` },
    tags: { name: 'refresh' },
  });
  check(refreshRes, {
    'refresh 200': (r) => r.status === 200,
    'no theft detection': (r) => r.status !== 401,
  });
  sleep(0.5);
}
```

**Expected:** 0 theft-detection false positives (401 with `AUTH_007`), p95 refresh < 300 ms.

---

## Metrics to capture

| Metric | Tool | Alert threshold |
|--------|------|-----------------|
| `http_req_duration` p50/p95/p99 per endpoint | k6 built-in | p95 > 500 ms → investigate |
| `http_req_failed` | k6 built-in | > 1 % → fail run |
| JVM heap / GC pause | Actuator `/actuator/metrics/jvm.gc.pause` | GC pause > 200 ms → flag |
| CPU utilisation | OS metrics (staging host) | > 80 % at steady state → flag |
| `jpa_auth_events` row count | DB query during/after run | Mismatches login count → audit pipeline broken |
| Argon2 thread pool queue depth | Micrometer (if instrumented) | Queue depth > 10 → Argon2 params too high for hardware |

---

## Pre-run checklist

- [ ] Staging DB seeded with 100 active users (use `scripts/seed-load-test-users.sh`)
- [ ] `feature.nexus-us003-auth-login.enabled=true` in staging config
- [ ] `nexus.security.rate-limit.max-attempts` set to staging value (5 in default; do not override for Scenario 2)
- [ ] k6 `BASE_URL` points to staging, not production
- [ ] No other load test running concurrently on the same host

## Post-run checklist

- [ ] Export k6 summary JSON to `docs/features/US-003/load-test-results-<date>.json`
- [ ] Verify `jpa_auth_events` count matches expected login + refresh event count
- [ ] Review `target/actuator` GC metrics for stop-the-world pauses > 200 ms
- [ ] If any threshold fails: open a bug, link to this plan, block release
