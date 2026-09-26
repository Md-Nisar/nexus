# Nexus performance tests (k6)

HTTP performance tests for `nexus-backend`, written for [k6](https://grafana.com/docs/k6/latest/).
Plain k6 JavaScript: no custom framework, no build step.

## Structure

```text
performance-test/
├── tests/                  # Entry points: one file = one runnable test = scenario(s) + workload + thresholds
│   ├── smoke/              #   platform-health.js, user-profile.js
│   ├── load/               #   platform-health.js
│   ├── stress/             #   platform-health.js
│   ├── spike/              #   platform-health.js
│   └── soak/               #   platform-health.js
├── scenarios/              # WHAT a user/client does (application flows), knows nothing about traffic volume
│   ├── platform-health.js  #   GET /actuator/health/readiness
│   └── user-profile.js     #   GET /api/v1/users/me (authenticated)
├── workloads/              # HOW MUCH traffic: k6 executor + stages, knows nothing about the application
│   └── smoke.js · load.js · stress.js · spike.js · soak.js
├── thresholds/
│   └── default-thresholds.js  # error-rate/checks gates + per-scenario p95/p99 builder
├── config/
│   ├── environment.js      # the ONLY place environment variables are read
│   └── base-options.js     # k6 options every test shares (summary stats, env tag)
├── utils/                  # small shared helpers: http.js, checks.js, auth.js
├── scripts/                # wait-for-ready.sh, inspect-tests.sh
├── results/                # run output (git-ignored, except .gitkeep)
└── package.json            # npm scripts + Prettier (k6 itself is NOT an npm package)
```

### Why scenarios and workloads are separate

A **scenario** is an application flow ("an authenticated user loads their profile"). A
**workload** is a traffic shape ("ramp to 10 users, hold 5 minutes"). They change for different
reasons: flows change when the API changes, traffic shapes change when the question changes
("normal day?" → load, "breaking point?" → stress). Keeping them apart means one scenario is
reused under every workload, and one workload drives any scenario. A test file only wires them
together:

```js
export const options = {
  ...baseOptions,
  scenarios: { platform_health: { ...load(), exec: 'platformHealth' } },
  thresholds: { ...errorThresholds, ...latencyThresholds('platform_health', EXAMPLE_LATENCY_MS) },
};
export { platformHealth }; // k6 calls exported functions by the name given in `exec`
```

## Prerequisites

- **k6** (v1.x; CI pins v1.3.0), installed separately. It is a standalone binary, not an npm
  package: `brew install k6` · `winget install k6 --source winget` · Linux/Docker:
  <https://grafana.com/docs/k6/latest/set-up/install-k6/>. Check with `k6 version`.
- **Node.js + npm**, only for the npm scripts and Prettier: `npm ci` in this directory.
- **A running nexus-backend** (see the root [README](../../README.md#quickstart)):

  ```bash
  docker compose up -d                          # repo root: MySQL + Redis
  cd nexus-backend && ./mvnw spring-boot:run    # dev profile, port 1000
  ```

## Configuration

All configuration is environment variables, read only in [`config/environment.js`](config/environment.js).
Set them as OS variables or pass `-e NAME=value` to k6 (`npm run test:smoke -- -e BASE_URL=...`).

| Variable | Required | Purpose |
|----------|----------|---------|
| `BASE_URL` | **yes** | Backend root URL, e.g. `http://localhost:1000`. No default, so a test can never silently hit the wrong environment. |
| `TEST_ENV` | no (`local`) | Label tagged on every metric (`local`, `ci`, `staging`, `perf`). |
| `VUS` | no | Scales the workload: steady-state users (load, soak) or peak users (stress, spike). |
| `DURATION` | no | Hold time of the workload's main phase, e.g. `30s`, `10m`, `2h`. |
| `THRESHOLD_P95_MS`, `THRESHOLD_P99_MS` | no | Override the latency thresholds for this environment. |
| `ACCESS_TOKEN` | auth tests | A bearer token to use as-is. |
| `PERF_USER_EMAIL`, `PERF_USER_PASSWORD` | auth tests | Credentials to log in with once in `setup()` when `ACCESS_TOKEN` is unset. |

**Credentials are never committed.** Locally, the `dev` profile seeds a pre-verified test user
(see `DevDataInitializer` in nexus-backend); pass its credentials through the variables above.
In CI they come from repository secrets.

## Running

Wait until the app is ready (optional locally, required in automation):

```bash
BASE_URL=http://localhost:1000 npm run wait-for-ready        # optional arg: timeout seconds (default 120)
```

| Category | Command | Default shape (override with `VUS` / `DURATION`) | ≈ Run time |
|----------|---------|------------------------------|------------|
| smoke | `BASE_URL=http://localhost:1000 npm run test:smoke` | 1 VU, 30s | 30s |
| smoke (auth) | `BASE_URL=... PERF_USER_EMAIL=... PERF_USER_PASSWORD=... npm run test:smoke:user-profile` | 1 VU, 30s | 30s |
| load | `BASE_URL=http://localhost:1000 npm run test:load` | ramp 1m → 10 VUs for 5m → ramp down 30s | 6.5m |
| stress | `BASE_URL=http://localhost:1000 npm run test:stress` | steps ⅓ → ⅔ → peak 30 VUs, 2m at peak | 10m |
| spike | `BASE_URL=http://localhost:1000 npm run test:spike` | baseline 5 → jump to 50 VUs for 1m → recover | 4.5m |
| soak | `BASE_URL=http://localhost:1000 npm run test:soak` | 10 VUs for 1h | 1h 4m |

On Windows PowerShell set variables first (`$env:BASE_URL="http://localhost:1000"`), or use
`npm run test:smoke -- -e BASE_URL=http://localhost:1000`. `wait-for-ready` and `inspect` need bash
(Git Bash/WSL).

Without npm: `k6 run -e BASE_URL=http://localhost:1000 tests/smoke/platform-health.js`.

### Test categories: purpose and when to use them

| Category | Question it answers | When to run |
|----------|---------------------|-------------|
| **smoke** | Do the script, config and environment work at all? Minimal traffic, not a measurement. | Every change to these tests; before any bigger run; in CI. |
| **load** | Does the system meet its thresholds under normal expected traffic? | Before releases; after performance-sensitive changes. |
| **stress** | Where does it start to degrade above normal traffic, and does it recover? | Capacity planning; after infrastructure changes. |
| **spike** | Does a sudden burst break it, and does it recover afterwards? | Before events with bursty traffic; after changes to pools, limits, autoscaling. |
| **soak** | Does anything degrade over hours (leaks, pool exhaustion, unbounded caches)? | Periodically on a dedicated environment; before major releases. |

Only smoke is meant for a laptop or PR pipeline. The other categories *run* locally (useful to try
a change), but their numbers only mean something on hardware sized like production.

### Validate without traffic

```bash
npm run inspect        # k6 inspect on every test: syntax, imports, options, thresholds
npm run format:check   # Prettier (npm run format to fix)
```

## Thresholds

Defined in [`thresholds/default-thresholds.js`](thresholds/default-thresholds.js). **Nexus has no
agreed performance SLAs yet, and nothing in this suite is one.**

- `errorThresholds` are correctness gates: `http_req_failed` rate < 1%, `checks` rate > 99%.
- `latencyThresholds(scenario, { p95Ms, p99Ms })` gates `http_req_duration` p95/p99 **per k6
  scenario**, so `setup()` traffic (the login, which is deliberately slow Argon2 hashing) and other
  scenarios in the same test don't skew it.
- `EXAMPLE_LATENCY_MS` (p95 < 1000ms, p99 < 2000ms) is a **loose placeholder** that shows the
  mechanism works. When a scenario gets a real target (story acceptance criteria are the source),
  pass it in that test: `latencyThresholds('user_profile', { p95Ms: 300 })`.
- `THRESHOLD_P95_MS` / `THRESHOLD_P99_MS` override latency per environment, because a laptop and
  a performance environment legitimately differ.
- Endpoint-level gates use the `name` tag every request gets from `utils/http.js`:
  `'http_req_duration{name:/api/v1/users/me}': ['p(95)<300']`.

**Exit codes:** `0` passed · `99` a threshold was breached · `107` script error (e.g. missing
`BASE_URL`, failed login in `setup()`). A non-zero exit fails the npm script and the CI step.

## Results and reporting

- The end-of-test summary (checks, thresholds ✓/✗, p90/p95/p99, request rate) prints to stdout,
  so it appears in CI logs.
- Each npm script also writes a machine-readable summary to `results/<category>-<test>.json` for
  archiving and comparing runs. Every metric is tagged with `test_env`.
- Optional HTML report built into k6: set `K6_WEB_DASHBOARD=true` and
  `K6_WEB_DASHBOARD_EXPORT=results/report.html` (CI does this).
- Later, k6's `--out` flag streams metrics to Prometheus, InfluxDB and similar backends without
  touching the tests. Deliberately not set up yet.

## Extending

**New scenario:** add `scenarios/<flow-name>.js` exporting one function named after the flow
(`createRole`). Use `get`/`postJson` from `utils/http.js`, assert with `checkResponse`, add
`sleep()` think time. Only call endpoints that exist in nexus-backend. Then add a test per
category you need, e.g. `tests/load/create-role.js`, copying an existing test and changing the
imports. Name the k6 scenario in snake_case (`create_role`) and pass the same name to
`latencyThresholds`. If it needs auth, add `setup()` returning `{ accessToken: obtainAccessToken() }`
as in `tests/smoke/user-profile.js`.

**New workload:** add `workloads/<shape>.js` exporting a function that returns a k6 scenario
object (executor + stages/rate, **no** `exec`). Read scale from `config.workload` with a
conservative default. For arrival-rate (requests/s) models, use k6's `constant-arrival-rate` or
`ramping-arrival-rate` executors.

**New utility:** add it only when a second scenario needs the same code. Keep one concern per file
(`utils/<concern>.js`), no catch-all "helpers" file. Business-specific metrics (e.g. a `Trend` for
an end-to-end flow) belong in the scenario that owns them; move them to `utils/metrics.js` only once
shared.

**Test data:** not needed yet, since both scenarios use only configuration, so there is no `data/`
directory. When one is needed: static non-sensitive data goes in `data/<name>.json`, loaded once
with `SharedArray` from `k6/data`; environment-specific data is selected by `TEST_ENV`
(`data/<TEST_ENV>/<name>.json`); generated data (unique emails etc.) goes in a small
`utils/test-data.js` using `exec.vu.idInTest`/`exec.scenario.iterationInTest` for uniqueness. Never
commit secrets or production data.

## CI

[`.github/workflows/performance-smoke.yml`](../../.github/workflows/performance-smoke.yml) runs on
PRs that touch this directory, and on demand (`workflow_dispatch`):

```text
checkout → install k6 (pinned + sha256-verified) → format:check + inspect → build jar
  → docker compose up mysql redis → start app (dev profile) → wait-for-ready
  → test:smoke (+ test:smoke:user-profile if secrets set) → upload results/ + app log → clean up
```

The workflow only supplies `BASE_URL`, `TEST_ENV=ci` and, optionally, credentials: the
`PERF_USER_EMAIL` / `PERF_USER_PASSWORD` repository secrets. Without them the authenticated smoke
step is skipped. Results are uploaded as the `performance-smoke-<sha>` artifact (30 days). Pointing
the same tests at another environment means changing `BASE_URL`, nothing else.

## Out of scope (for now)

- A dedicated or cloud performance environment, and any infrastructure (Kubernetes, Terraform, cloud).
- Scheduled load/stress/spike/soak runs in CI (numbers from a shared CI runner are not meaningful).
- Dashboards and metric storage (Prometheus, Grafana, k6 Cloud).
- Production SLAs, which need to be agreed first. Thresholds here are gates and examples.
- Write-path scenarios (registration, role management). They need test-data isolation and cleanup,
  and some trigger email or rate limits.

## Assumptions

- The target is `nexus-backend` (port 1000 locally). The frontend is static assets and is not
  performance-tested here.
- `GET /actuator/health/readiness` is the readiness signal. The aggregate `/actuator/health`
  reports `DOWN` on a fresh dev database (by design, via security-observability indicators and a
  missing MailHog) while the app serves normally, so it is unsuitable as a gate.
- The only authenticated read available today is `GET /api/v1/users/me`, which needs the
  `nexus-us003-auth-login` feature flag (on in the `dev` profile). It reads only JWT claims, so it
  measures the authentication path, not database performance.
- Login is rate limited per IP (10/min by default), so authenticated tests log in **once** in
  `setup()`. Tokens expire after 15 minutes, so `user-profile` is not used in the soak test.
- Workload defaults are sized so a developer machine or CI runner can run them. They are not
  capacity targets.
