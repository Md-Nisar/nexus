import { config } from '../config/environment.js';

/**
 * Nexus has no agreed performance SLAs yet, so nothing here is one.
 *
 * - errorThresholds are framework correctness gates: the system answered, and answered correctly.
 * - EXAMPLE_LATENCY_MS are deliberately loose placeholder values that show the mechanism works.
 *   Replace them per scenario once real targets exist (story acceptance criteria are the source).
 *
 * A breached threshold makes `k6 run` exit non-zero (99), which fails the npm script and CI step.
 */

export const errorThresholds = {
  http_req_failed: ['rate<0.01'],
  checks: ['rate>0.99'],
};

export const EXAMPLE_LATENCY_MS = { p95Ms: 1000, p99Ms: 2000 };

/**
 * p95/p99 gates on http_req_duration, scoped to one k6 scenario so that setup() traffic (e.g.
 * login) and other scenarios in the same test do not skew it. THRESHOLD_P95_MS / THRESHOLD_P99_MS
 * override the values passed in, because acceptable latency depends on the hardware under test.
 */
export function latencyThresholds(scenarioName, { p95Ms, p99Ms } = {}) {
  const p95 = config.thresholds.p95Ms ?? p95Ms;
  const p99 = config.thresholds.p99Ms ?? p99Ms;
  const rules = [];
  if (p95 !== undefined) {
    rules.push(`p(95)<${p95}`);
  }
  if (p99 !== undefined) {
    rules.push(`p(99)<${p99}`);
  }
  return rules.length ? { [`http_req_duration{scenario:${scenarioName}}`]: rules } : {};
}
