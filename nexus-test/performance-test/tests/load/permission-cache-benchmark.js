import { baseOptions } from '../../config/base-options.js';
import { config } from '../../config/environment.js';
import {
  cleanupRefreshAccounts,
  refreshFailed,
  refreshOne,
  seedRefreshAccounts,
} from '../../scenarios/token-refresh.js';
import { errorThresholds } from '../../thresholds/default-thresholds.js';
import { obtainAccessToken } from '../../utils/auth.js';

/**
 * US-018 T-023 benchmark (B6, design §10.6, ADR-0022 addendum): one arm of the permission-cache
 * comparison. Refresh at CACHE_BENCH_RATE per second (default 50) by accounts that hold 1 to 5
 * roles, against a backend started with the permission cache ON (default) or OFF
 * (`nexus.rbac.permission-cache.bypass=true`). CACHE_ARM only labels the run; it must match how
 * the backend was started.
 *
 * Run each arm at least three times on the STAGING topology (a shared CI runner's numbers are
 * meaningless), then feed the summary files to `node utils/cache-benchmark-verdict-cli.mjs`, which
 * applies the stated rule: keep the cache only if refresh p95 drops by at least 5 ms or the
 * mint-attributable MySQL QPS drops by at least 30%; otherwise, and when inconclusive, remove it.
 * Read "Permission cache benchmark" in the README first. This test is a measurement, not a pass/fail
 * gate on speed, so its thresholds only check that the run was valid.
 */

const { rate, duration, vus } = config.cacheBenchmark;

export const options = {
  ...baseOptions,
  setupTimeout: '15m',
  teardownTimeout: '5m',
  scenarios: {
    refresh_at_rate: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: vus,
      maxVUs: vus,
      exec: 'refreshOne',
    },
  },
  thresholds: {
    ...errorThresholds,
    // A run that dropped arrivals or failed refreshes did not hold the stated rate: invalid.
    dropped_iterations: ['count==0'],
    cache_bench_refresh_failed: ['count==0'],
    // Declared so k6 records and exports this sub-metric; the verdict CLI reads its p95.
    'http_req_duration{name:/api/v1/auth/refresh}': ['p(95)>0'],
  },
};

export function setup() {
  return seedRefreshAccounts(obtainAccessToken());
}

export function teardown(data) {
  cleanupRefreshAccounts(data);
}

export { refreshFailed, refreshOne };
