import { fail } from 'k6';
import { Gauge } from 'k6/metrics';
import { baseOptions } from '../../config/base-options.js';
import { config } from '../../config/environment.js';
import { listRoles } from '../../scenarios/rbac-read.js';
import { errorThresholds } from '../../thresholds/default-thresholds.js';
import { bearer, obtainAccessToken } from '../../utils/auth.js';
import { get } from '../../utils/http.js';
import { constantArrivalRate } from '../../workloads/constant-arrival-rate.js';

/**
 * US-018 T-009 hot-path budget (design §9.5, merge-blocking): 200 requests/s on a guarded endpoint
 * (GET /api/v1/roles), one permission-epoch check per request.
 *
 * Gate mode (default) enforces:
 * - server-side `nexus.rbac.epoch.check.latency` p95 <= 2 ms, read from /actuator/prometheus in
 *   teardown(). Micrometer computes it over a sliding window of about 2 minutes, so the run must
 *   hold the rate for at least 3 minutes (default 5m) and the value describes the run's end.
 * - zero `nexus.rbac.epoch.check{outcome="skipped_error"}`: a failing Redis read is fast, so a run
 *   that measured failures instead of reads is invalid.
 * - endpoint p95 regression < 5 ms against BASELINE_P95_MS (EPIC-002 RBAC overhead), the p95 of
 *   the same test run in baseline mode on the build without the epoch check.
 * - every arrival served (`dropped_iterations` = 0), so the rate really was 200/s.
 *
 * Baseline mode (EPOCH_CHECK_MODE=baseline) runs the same traffic and only records the endpoint
 * p95; the epoch metrics do not exist on that build. One login in setup(), so the run must end
 * within the 900 s access-token TTL.
 */

const SCENARIO = 'epoch_check';
const EPOCH_P95_BUDGET_MS = 2;
const RBAC_OVERHEAD_BUDGET_MS = 5;
const gate = config.epochCheck.mode === 'gate';

if (gate && config.epochCheck.baselineP95Ms === undefined) {
  throw new Error('Gate mode needs BASELINE_P95_MS (run once with EPOCH_CHECK_MODE=baseline)');
}

const epochCheckP95Ms = new Gauge('epoch_check_p95_ms');
const epochCheckSkippedError = new Gauge('epoch_check_skipped_error');

export const options = {
  ...baseOptions,
  scenarios: {
    [SCENARIO]: { ...constantArrivalRate({ rate: 200, duration: '5m' }), exec: 'listRoles' },
  },
  thresholds: {
    ...errorThresholds,
    dropped_iterations: ['count==0'],
    ...(gate
      ? {
          [`http_req_duration{scenario:${SCENARIO}}`]: [
            `p(95)<${config.epochCheck.baselineP95Ms + RBAC_OVERHEAD_BUDGET_MS}`,
          ],
          epoch_check_p95_ms: [`value<=${EPOCH_P95_BUDGET_MS}`],
          epoch_check_skipped_error: ['value==0'],
        }
      : {}),
  },
};

export function setup() {
  return { accessToken: obtainAccessToken() };
}

export function teardown(data) {
  if (!gate) {
    return;
  }
  const res = get('/actuator/prometheus', {
    headers: { ...bearer(data.accessToken).headers, Accept: 'text/plain;version=0.0.4' },
  });
  if (res.status !== 200) {
    fail(`GET /actuator/prometheus returned HTTP ${res.status}`);
  }
  const p95Seconds = sample(res.body, 'nexus_rbac_epoch_check_latency_seconds', 'quantile="0.95"');
  const skippedError = sample(res.body, 'nexus_rbac_epoch_check_total', 'outcome="skipped_error"');
  if (p95Seconds === undefined || skippedError === undefined) {
    fail('nexus.rbac.epoch.check metrics not found; is this the T-009 build?');
  }
  epochCheckP95Ms.add(p95Seconds * 1000);
  epochCheckSkippedError.add(skippedError);
}

/** The value of the first Prometheus sample of `name` whose labels contain `label`. */
function sample(body, name, label) {
  for (const line of body.split('\n')) {
    if (line.startsWith(`${name}{`) && line.includes(label)) {
      return Number(
        line
          .slice(line.lastIndexOf('}') + 1)
          .trim()
          .split(' ')[0],
      );
    }
  }
  return undefined;
}

export { listRoles };
