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

function epochCheckMode() {
  const raw = __ENV.EPOCH_CHECK_MODE || 'gate';
  if (raw !== 'gate' && raw !== 'baseline') {
    throw new Error(`EPOCH_CHECK_MODE must be "gate" or "baseline", got "${raw}"`);
  }
  return raw;
}

function optionalPositiveNumber(name) {
  const raw = __ENV[name];
  if (raw === undefined || raw === '') {
    return undefined;
  }
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive number, got "${raw}"`);
  }
  return value;
}

function optionalInt(name, fallback) {
  return optionalPositiveInt(name) ?? fallback;
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
    // Iterations per second for arrival-rate workloads (workloads/constant-arrival-rate.js).
    rate: optionalPositiveInt('RATE'),
  }),

  // Environment-level latency overrides for thresholds/default-thresholds.js.
  thresholds: Object.freeze({
    p95Ms: optionalPositiveInt('THRESHOLD_P95_MS'),
    p99Ms: optionalPositiveInt('THRESHOLD_P99_MS'),
  }),

  // Operator token for /actuator/prometheus (the backend's NEXUS_MANAGEMENT_SCRAPE_TOKEN). No
  // tenant credential can read the platform metrics (US-018 pre-PR security re-review RR-M2).
  scrapeToken: __ENV.SCRAPE_TOKEN || undefined,

  // US-018 epoch-check hot-path test (tests/load/epoch-check-latency.js). "baseline" measures the
  // endpoint on a build without the epoch check; "gate" (default) enforces the server-side epoch
  // p95 and the regression against baselineP95Ms, which gate mode requires.
  epochCheck: Object.freeze({
    mode: epochCheckMode(),
    baselineP95Ms: optionalPositiveNumber('BASELINE_P95_MS'),
  }),

  // US-018 T-013 detach-refresh storm (tests/load/detach-refresh-storm.js). This is a write-path
  // test: it seeds users and a role, so the defaults mirror the merge gate (200 holders, one
  // attacker at 100 invalid refreshes per minute) and only MAILHOG_URL has no default.
  refreshStorm: Object.freeze({
    // Where the backend's outgoing mail is readable (MailHog API), needed to verify the seeded
    // accounts. Read in setup(), not at init, so `k6 inspect` needs no value.
    mailhogUrl: (__ENV.MAILHOG_URL || '').replace(/\/+$/, '') || undefined,
    holders: optionalInt('STORM_HOLDERS', 200),
    // Seconds over which the holders' refreshes arrive after the detach (a real tenant's users do
    // not all click in the same second). Any 60 s window then holds at most holders * 60 / spread
    // holder refreshes next to the attacker's, so keep it above 60 or the REFRESH_IP total of 300
    // is exceeded by arithmetic alone.
    holderSpreadSeconds: optionalInt('STORM_HOLDER_SPREAD_SECONDS', 90),
    attackerPerMinute: optionalInt('STORM_ATTACKER_PER_MINUTE', 100),
    replays: optionalInt('STORM_REPLAYS', 5),
    leadInSeconds: optionalInt('STORM_LEAD_IN_SECONDS', 30),
  }),

  // US-018 security review M7 part 2 M-1 (tests/load/refresh-junk-flood.js): cookie-less junk
  // refreshes from one IP above the per-IP refresh total (300 per 60 s), next to valid users.
  refreshJunkFlood: Object.freeze({
    mailhogUrl: (__ENV.MAILHOG_URL || '').replace(/\/+$/, '') || undefined,
    floodPerMinute: optionalInt('JUNK_FLOOD_PER_MINUTE', 400),
    validUsers: optionalInt('JUNK_VALID_USERS', 10),
    floodSeconds: optionalInt('JUNK_FLOOD_SECONDS', 120),
  }),

  // Credentials are only ever read from the environment — never commit them.
  auth: Object.freeze({
    accessToken: __ENV.ACCESS_TOKEN || undefined,
    email: __ENV.PERF_USER_EMAIL || undefined,
    password: __ENV.PERF_USER_PASSWORD || undefined,
  }),
});
