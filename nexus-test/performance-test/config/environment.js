/**
 * The single place where environment-specific values enter the tests.
 *
 * Everything comes from environment variables (k6 exposes both OS variables and `-e NAME=value`
 * flags through __ENV), so the same test runs unchanged against a local app, a CI runner, staging
 * or a dedicated performance environment. Nothing here has an environment-specific default.
 */

function requireBaseUrl() {
  const raw = __ENV.BASE_URL;
  if (!raw) {
    throw new Error('BASE_URL is required, e.g. BASE_URL=http://localhost:1000 k6 run <test>');
  }
  if (!/^https?:\/\//.test(raw)) {
    throw new Error(`BASE_URL must start with http:// or https://, got "${raw}"`);
  }
  return raw.replace(/\/+$/, '');
}

function optionalPositiveInt(name) {
  const raw = __ENV[name];
  if (raw === undefined || raw === '') {
    return undefined;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer, got "${raw}"`);
  }
  return value;
}

export const config = Object.freeze({
  baseUrl: requireBaseUrl(),

  // Free-text label (local, ci, staging, perf...) attached to every metric so results from
  // different environments are never mixed up when compared.
  testEnv: __ENV.TEST_ENV || 'local',

  // Scale knobs for workloads/*.js. Unset means "use the workload's own conservative default".
  workload: Object.freeze({
    vus: optionalPositiveInt('VUS'),
    duration: __ENV.DURATION || undefined,
  }),

  // Environment-level latency overrides for thresholds/default-thresholds.js.
  thresholds: Object.freeze({
    p95Ms: optionalPositiveInt('THRESHOLD_P95_MS'),
    p99Ms: optionalPositiveInt('THRESHOLD_P99_MS'),
  }),

  // Credentials are only ever read from the environment — never commit them.
  auth: Object.freeze({
    accessToken: __ENV.ACCESS_TOKEN || undefined,
    email: __ENV.PERF_USER_EMAIL || undefined,
    password: __ENV.PERF_USER_PASSWORD || undefined,
  }),
});
