/*
 * US-014 Phase 8 test-coverage audit — targeted regression check for threat-model finding T-D6
 * (docs/features/US-014/03b-threat-model.md), NOT a ">10 RPS" endpoint-sizing scenario.
 *
 * Why this script exists despite POST/DELETE /api/v1/users/{userId}/roles NOT being a >10 RPS
 * endpoint (docs/TESTING.md's stated trigger): the endpoints are `user:write`-gated and today
 * reachable only by an active TENANT_ADMIN (design §0 decision 5a) — realistic steady-state RPS
 * is low. The risk T-D6 documents is not sustained throughput; it is CONCURRENCY BURST. US-014's
 * denial path added a second, nested `REQUIRES_NEW` transaction that suspends-but-does-not-release
 * TX1's own pooled connection (Hibernate resource-local release mode), so every in-flight denial
 * holds TWO of the default HikariCP pool's 10 connections for the duration of the audit INSERT.
 * The threat model's own arithmetic: ~5 CONCURRENT denials saturate the pool; the 6th blocks in
 * getConnection() for up to the unconfigured 30s connectionTimeout default — a self-reinforcing,
 * platform-wide (every tenant, every endpoint sharing the pool) stall.
 *
 * This script drives exactly that shape — a short, sharp concurrency burst, not sustained RPS —
 * against the CHEAPEST denial path (T2, CROSS_TENANT_TARGET via a foreign-tenant roleId: no valid
 * foreign user UUID needed, no mutation, no lock; threat-model T-D7's "cheap path" finding).
 *
 * Run manually against a staging-like environment with production-like HikariCP sizing (NOT
 * against a laptop/CI Testcontainers instance, which has different pool characteristics) — this is
 * NOT part of `./mvnw verify` and is not a CI gate. Requires k6 (https://k6.io/).
 *
 * Usage:
 *   k6 run -e BASE_URL=https://staging.example.com \
 *          -e ADMIN_TOKEN=<TENANT_ADMIN JWT with user:write> \
 *          -e TARGET_USER_ID=<any user id in the admin's OWN tenant> \
 *          -e FOREIGN_ROLE_ID=<a role id belonging to a DIFFERENT tenant> \
 *          nexus-backend/src/test/load/role-assignment-denial-pool-pressure.k6.js
 *
 * What to watch (the T-D6 watch-list, design §11 / §9.3 — pull from the app's Actuator/
 * Prometheus endpoint during and after the run, not from this script's own output):
 *   - hikaricp_connections_pending      -- must return to the pre-run baseline (0) promptly
 *   - hikaricp_connections_acquire_seconds -- must not show a sustained tail above baseline
 *   - nexus.rbac.audit_write_failed{operation="deny"} -- must stay at 0
 *   - nexus.rbac.permission_denied{reason="CROSS_TENANT_TARGET"} -- expected to rise with load;
 *     confirms the requests actually reached the denial path this script targets
 *
 * Pass/fail here is informational, not a build gate: a 403 on every request is the CORRECT
 * application-level outcome (this script intentionally trips CROSS_TENANT_TARGET on every call).
 * The thing worth failing on is elevated p95 latency or non-403 errors under the burst, which
 * would indicate pool exhaustion (T-D6 live) rather than the accepted, priced cost.
 */

import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const ADMIN_TOKEN = __ENV.ADMIN_TOKEN;
const TARGET_USER_ID = __ENV.TARGET_USER_ID;
const FOREIGN_ROLE_ID = __ENV.FOREIGN_ROLE_ID;

export const options = {
  scenarios: {
    // A short, sharp burst -- not a sustained-RPS soak -- deliberately shaped to land 8-10
    // concurrent in-flight requests at once, mirroring the threat model's "~5 concurrent
    // denials saturate the (default 10-connection) pool" arithmetic with headroom to observe
    // the effect clearly.
    concurrent_denial_burst: {
      executor: 'per-vu-iterations',
      vus: 10,
      iterations: 3,
      maxDuration: '30s',
    },
  },
  thresholds: {
    // Informational gate: a non-403 response under this burst means the pool is exhausted
    // and requests are failing outright (T-D6 live), not merely "denied as designed".
    http_req_failed: ['rate<0.01'],
    // p95 above ~1s under a 10-VU burst on a healthy pool would indicate queueing for a
    // second connection (T-D6 §8.3's estimate: one extra INSERT round-trip in the healthy
    // case, low-single-digit ms; anything materially higher is the signal to watch).
    http_req_duration: ['p(95)<1000'],
  },
};

export default function () {
  if (!ADMIN_TOKEN || !TARGET_USER_ID || !FOREIGN_ROLE_ID) {
    throw new Error(
      'Set BASE_URL, ADMIN_TOKEN, TARGET_USER_ID, FOREIGN_ROLE_ID env vars before running.'
    );
  }

  // T2 (CROSS_TENANT_TARGET): a role id from another tenant against a target already in the
  // caller's own tenant. Cheapest denial to generate at volume (threat-model T-D7) -- no
  // reconnaissance of a foreign user id required.
  const res = http.post(
    `${BASE_URL}/api/v1/users/${TARGET_USER_ID}/roles`,
    JSON.stringify({ roleId: FOREIGN_ROLE_ID }),
    {
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        'Content-Type': 'application/json',
      },
    }
  );

  check(res, {
    // 403 RBAC_001/CROSS_TENANT_TARGET is the CORRECT outcome for every call this script
    // makes -- it is what proves the request reached the denial path, not a failure.
    'denied as expected (403) or pool exhausted (5xx/timeout) -- inspect body on 5xx': (r) =>
      r.status === 403 || r.status >= 500,
  });
}
