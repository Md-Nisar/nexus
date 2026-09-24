/*
 * US-016 Phase 8 test-coverage audit — targeted regression check for D14 / RC-10
 * (docs/features/US-016/03-design.md §4.8, §6.1 "check 3.5"), NOT a routine ">10 RPS"
 * endpoint-sizing scenario. Mirrors role-assignment-denial-pool-pressure.k6.js's own framing
 * (US-014/T-D6): POST/DELETE /api/v1/users/{userId}/roles are `user:write`-gated and today
 * reachable only by holders of an already-privileged role, so realistic STEADY-STATE RPS is
 * low. The risk this script exists to exercise is not sustained legitimate throughput; it is
 * a single actor (or a small number of compromised/misbehaving `user:write` credentials) firing
 * the privileged-gate denial path at volume — exactly the T-D10/T-D11 cost-amplification finding
 * D14 was added to bound (03b-threat-model.md RC-10).
 *
 * US-017 D7 update (Phase 8 test-coverage audit): both scenarios below grant the literally-named
 * `TENANT_ADMIN` role, i.e. the NAME-MATCH branch of `assign()`'s privileged path -- which, as of
 * US-017 D7 (RES-10/RES-19), now acquires the SAME tenant-wide M11 `SELECT ... FOR UPDATE` lock
 * BEFORE the caller gate on `assign()` too, not only on `revoke()` as this script originally
 * assumed when it was written under US-016 (there is no separate revoke scenario in this file --
 * the DELETE verb was never in scope here; only the POST/assign side is exercised). Every denied
 * request in the pre-throttle phase therefore now pays for M11 + M5b + the audit write, on BOTH
 * actors, which is exactly the RES-19 residual (a pre-authorization tenant-wide X lock, bounded
 * only by D14) this script is now the load-side proof for.
 *
 * What D14 changes under this load, and what this script is watching for:
 *   - Before the actor crosses `nexus.rbac.denial-throttle.max-denials` denials in the current
 *     `…window-seconds` window, EVERY denied request is "expensive": M11 (the tenant-wide lock,
 *     new on this path per D7) + M8 + M5b (a locking read), a nested REQUIRES_NEW audit INSERT, a
 *     WARN log line and three counter/timer increments (`nexus.rbac.privileged_role_change_blocked`,
 *     `nexus.rbac.privileged_revoke_lock_hold{operation="assign",outcome="denied"}` -- the D7
 *     first-class series, despite the metric's pre-US-017 name -- and the denial-throttle counter
 *     below).
 *   - Once throttled, `requireNotThrottled` (03-design.md §6.1 check 3.5) short-circuits to a 403
 *     BEFORE M11/M8/M5b, the audit write and the metrics -- a single in-memory map lookup. The
 *     HTTP status code is identical (403 RBAC_001) in both phases, so this script cannot and does
 *     not assert on status-code shape alone; it watches for the LATENCY/THROUGHPUT signature of
 *     the transition (§9.2's own account of what "bounds cost" means operationally), pulled from
 *     Actuator/Prometheus during and after the run, not from k6's own output.
 *   - A second, independent-actor scenario proves D14's per-(tenantId, actorUserId) keying: a
 *     distinct actor hammering the same endpoint concurrently must NOT be cross-throttled by the
 *     first actor's denials (RES-11's blast radius is deliberately scoped to one actor).
 *
 * Run manually against a staging-like environment with production-like HikariCP sizing (NOT
 * against a laptop/CI Testcontainers instance). Requires k6 (https://k6.io/). This is NOT part of
 * `./mvnw verify` and is not a CI gate.
 *
 * Usage:
 *   k6 run -e BASE_URL=https://staging.example.com \
 *          -e NON_ADMIN_TOKEN=<user:write JWT, NOT an active TENANT_ADMIN, actor A> \
 *          -e NON_ADMIN_TOKEN_2=<user:write JWT, NOT an active TENANT_ADMIN, actor B -- different \
 *                                 tenant OR different actorUserId within the same tenant> \
 *          -e TARGET_USER_ID=<any user id in actor A's own tenant> \
 *          -e TARGET_USER_ID_2=<any user id in actor B's own tenant/scope> \
 *          -e TENANT_ADMIN_ROLE_ID=<the literal TENANT_ADMIN role id in the relevant tenant(s)> \
 *          nexus-backend/src/test/load/role-change-privileged-denial-throttle.k6.js
 *
 * What to watch (pull from Actuator/Prometheus during and after the run, not from this script):
 *   - nexus.rbac.privileged_role_change_blocked{operation="assign",matchedOn="ROLE_NAME"} --
 *     must stop climbing once `max-denials` is reached for actor A (the gate itself is no longer
 *     reached past the throttle) while actor B's own series keeps climbing independently.
 *   - nexus.rbac.privileged_revoke_lock_hold{operation="assign",outcome="denied"} (D7, US-017) --
 *     its count must track the blocked-counter above 1:1 up to the throttle point, then flatten
 *     identically; its p95/p99 duration is the direct RES-19 cost-per-denial signal for the
 *     pre-gate M11 lock on `assign()`, which did not exist before US-017.
 *   - nexus.rbac.denial_throttled{operation="assign"} -- must start climbing exactly where the
 *     blocked-counter's climb for actor A flattens.
 *   - hikaricp_connections_pending / *_acquire_seconds -- must NOT show a sustained rise (the
 *     whole point of check 3.5's placement ahead of M11/M8/M5b and the audit write).
 *   - nexus.rbac.audit_write_failed{operation="deny"} -- must stay at 0.
 *
 * Pass/fail here is informational, not a build gate: 403 on every request is the CORRECT outcome
 * for both actors throughout (neither ever holds an active TENANT_ADMIN assignment). The thing
 * worth failing on is a non-403 response (pool exhaustion, T-D11 live) or p95 latency that keeps
 * climbing after the throttle should have engaged for actor A.
 */

import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const NON_ADMIN_TOKEN = __ENV.NON_ADMIN_TOKEN;
const NON_ADMIN_TOKEN_2 = __ENV.NON_ADMIN_TOKEN_2;
const TARGET_USER_ID = __ENV.TARGET_USER_ID;
const TARGET_USER_ID_2 = __ENV.TARGET_USER_ID_2;
const TENANT_ADMIN_ROLE_ID = __ENV.TENANT_ADMIN_ROLE_ID;

export const options = {
  scenarios: {
    // Actor A: sustained volume, well past `max-denials` (default 5) within one
    // `window-seconds` (default 60) window -- the scenario D14 exists to bound.
    single_actor_denial_sustain: {
      executor: 'constant-arrival-rate',
      rate: 15,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 20,
      maxVUs: 40,
      exec: 'actorAHammersTheGate',
    },
    // Actor B: concurrent, independent actor at the same nominal rate -- proves the throttle's
    // per-(tenantId, actorUserId) key does not cross-throttle a second, unrelated caller.
    independent_actor_control: {
      executor: 'constant-arrival-rate',
      rate: 15,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 20,
      maxVUs: 40,
      exec: 'actorBHammersTheGateIndependently',
    },
  },
  thresholds: {
    // Informational: a non-403 means the pool is exhausted or the app errored outright, not
    // merely "denied as designed".
    http_req_failed: ['rate<0.01'],
    // p95 above ~1s under this sustained rate on a healthy pool would indicate the throttle is
    // NOT bounding cost as designed (still doing M8+M5+audit-write per request past max-denials).
    http_req_duration: ['p(95)<1000'],
  },
};

function requireEnv() {
  if (
    !NON_ADMIN_TOKEN ||
    !NON_ADMIN_TOKEN_2 ||
    !TARGET_USER_ID ||
    !TARGET_USER_ID_2 ||
    !TENANT_ADMIN_ROLE_ID
  ) {
    throw new Error(
      'Set BASE_URL, NON_ADMIN_TOKEN, NON_ADMIN_TOKEN_2, TARGET_USER_ID, TARGET_USER_ID_2, ' +
        'TENANT_ADMIN_ROLE_ID env vars before running.'
    );
  }
}

// Both actors attempt to GRANT TENANT_ADMIN to a target they are not entitled to promote --
// the name-match half of the unified gate (03-design.md §6.1), cheapest privileged path to
// trigger at volume (no dangerous-custom-role fixture needed).
function attemptPrivilegedGrant(token, targetUserId) {
  return http.post(
    `${BASE_URL}/api/v1/users/${targetUserId}/roles`,
    JSON.stringify({ roleId: TENANT_ADMIN_ROLE_ID }),
    { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
  );
}

export function actorAHammersTheGate() {
  requireEnv();
  const res = attemptPrivilegedGrant(NON_ADMIN_TOKEN, TARGET_USER_ID);
  check(res, {
    'actor A: denied as expected (403) or pool exhausted (5xx/timeout) -- inspect body on 5xx': (
      r
    ) => r.status === 403 || r.status >= 500,
  });
}

export function actorBHammersTheGateIndependently() {
  requireEnv();
  const res = attemptPrivilegedGrant(NON_ADMIN_TOKEN_2, TARGET_USER_ID_2);
  check(res, {
    'actor B: denied as expected (403) or pool exhausted (5xx/timeout) -- inspect body on 5xx': (
      r
    ) => r.status === 403 || r.status >= 500,
  });
}
