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
 * against the cheapest REQUIRES_NEW denial path left after US-018 B1 (GRANT_EXCEEDS_CALLER: a
 * role in the caller's own tenant that carries a permission the caller lacks; no mutation, no
 * lock; threat-model T-D7). The former cross-tenant scenario is gone: since US-018 B1 a
 * cross-tenant target is a 404 that writes no audit row and opens no second connection.
 *
 * Run manually against a staging-like environment with production-like HikariCP sizing (NOT
 * against a laptop/CI Testcontainers instance, which has different pool characteristics) — this is
 * NOT part of `./mvnw verify` and is not a CI gate. Requires k6 (https://k6.io/).
 *
 * Usage:
 *   k6 run -e BASE_URL=https://staging.example.com \
 *          -e ACTOR_TOKENS=<comma-separated JWTs, at least 10, each for a DIFFERENT user holding
 *             only user:role:assign, so no actor reaches the denial throttle (US-018 B8)> \
 *          -e TARGET_USER_ID=<any user id in the actors' OWN tenant> \
 *          -e EXCEEDING_ROLE_ID=<a role id in that tenant carrying a permission the actors lack> \
 *          nexus-backend/src/test/load/role-assignment-denial-pool-pressure.k6.js
 *
 * What to watch (the T-D6 watch-list, design §11 / §9.3 — pull from the app's Actuator/
 * Prometheus endpoint during and after the run, not from this script's own output):
 *   - hikaricp_connections_pending      -- must return to the pre-run baseline (0) promptly
 *   - hikaricp_connections_acquire_seconds -- must not show a sustained tail above baseline
 *   - nexus.rbac.audit_write_failed{operation="deny"} -- must stay at 0
 *   - nexus.rbac.permission_denied{reason="GRANT_EXCEEDS_CALLER"} -- expected to rise with load;
 *     confirms the requests actually reached the denial path this script targets
 *
 * Pass/fail here is informational, not a build gate: a 403 on every request is the CORRECT
 * application-level outcome (this script intentionally trips GRANT_EXCEEDS_CALLER on every call).
 * Each VU uses its own actor and makes 3 iterations, below the default denial threshold of 5, so
 * every call writes a REQUIRES_NEW denial row: that is the pool-pressure shape. A throttled actor
 * writes no row (US-018 B8), which would hide the pressure.
 *
 * Status: written for the US-018 M8 exit gate (T-024); NOT run in the authoring environment
 * (no Docker, no staging topology). Run once per deployment shape before production.
 * The thing worth failing on is elevated p95 latency or non-403 errors under the burst, which
 * would indicate pool exhaustion (T-D6 live) rather than the accepted, priced cost.
 */

import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const ACTOR_TOKENS = (__ENV.ACTOR_TOKENS || '').split(',').filter((t) => t.length > 0);
const TARGET_USER_ID = __ENV.TARGET_USER_ID;
const EXCEEDING_ROLE_ID = __ENV.EXCEEDING_ROLE_ID;

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
  if (ACTOR_TOKENS.length < 10 || !TARGET_USER_ID || !EXCEEDING_ROLE_ID) {
    throw new Error(
      'Set BASE_URL, ACTOR_TOKENS (at least 10), TARGET_USER_ID, EXCEEDING_ROLE_ID env vars before running.'
    );
  }

  // GRANT_EXCEEDS_CALLER: a role in the caller's own tenant whose permissions the caller does not
  // all hold. One actor per VU keeps every actor under the denial throttle.
  const token = ACTOR_TOKENS[(__VU - 1) % ACTOR_TOKENS.length];
  const res = http.post(
    `${BASE_URL}/api/v1/users/${TARGET_USER_ID}/roles`,
    JSON.stringify({ roleId: EXCEEDING_ROLE_ID }),
    {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    }
  );

  check(res, {
    // 403 RBAC_001/GRANT_EXCEEDS_CALLER is the CORRECT outcome for every call this script
    // makes -- it is what proves the request reached the denial path, not a failure.
    'denied as expected (403) or pool exhausted (5xx/timeout) -- inspect body on 5xx': (r) =>
      r.status === 403 || r.status >= 500,
  });
}
