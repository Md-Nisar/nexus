# Performance test conventions

How to add performance tests for a module. The RBAC suite is the reference implementation:
copy its shape, not its endpoints.

| Reference                                                                                     | Shows                                                      |
| --------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| [`scenarios/rbac-read.js`](scenarios/rbac-read.js)                                            | A read scenario: list, drill into an id taken from a reply |
| [`scenarios/rbac-role-lifecycle.js`](scenarios/rbac-role-lifecycle.js)                        | A write scenario: create, change, undo, with isolated data |
| [`tests/smoke/rbac-role-lifecycle.js`](tests/smoke/rbac-role-lifecycle.js) and `tests/load/…` | How a test wires scenario, workload and thresholds         |

The layout and the scenario/workload split are explained in the [README](README.md); this page
covers the rules for what to write.

## What a performance test covers

A performance test answers "how does this behave under traffic?" It covers **latency and error
rate for a realistic mix of calls**. It does **not** re-assert business rules, validation or
authorization: the backend integration tests own those, and repeating them here adds maintenance
and no signal. Check status codes and the shape of the reply, enough to know the call did its job
(for example that the assigned role appears in the user's role list), and stop there.

So a module gets **no** 401/403/400 scenarios. If an authorization path itself is a performance
concern (a permission check that is slow), write a scenario for that specific concern.

## Adding a module

1. **Read scenario** `scenarios/<module>-read.js`: every `GET` the module exposes, in a realistic
   order. Take ids from earlier responses, never hard-code them.
2. **Write scenario** `scenarios/<module>-<flow>-lifecycle.js`: one scenario per coherent flow
   that leaves the data as it found it (create, change, undo). One file per flow, not per endpoint.
3. **Tests**, one file each under `tests/<category>/<scenario-name>.js`:
   - reads: smoke and load (add stress, spike and soak once a dedicated environment exists);
   - writes: smoke and load only. Heavy write workloads wait for a dedicated environment.
4. **npm scripts** `test:smoke:<name>` and `test:load:<name>` in `package.json`.
5. **CI**: add a smoke step for each new smoke test to `performance-smoke.yml`.
6. **README**: add the rows to the running table.
7. Run the smoke tests against a real backend and show they pass before opening the PR.

## Naming

| Thing            | Convention                         | Example                             |
| ---------------- | ---------------------------------- | ----------------------------------- |
| scenario file    | `kebab-case`, `<module>-<flow>.js` | `rbac-role-lifecycle.js`            |
| exported flow    | `camelCase` of the file            | `rbacRoleLifecycle`                 |
| k6 scenario name | `snake_case` of the file           | `rbac_role_lifecycle`               |
| test file        | same name as the scenario          | `tests/load/rbac-role-lifecycle.js` |
| npm script       | `test:<category>:<name>`           | `test:load:rbac-role-lifecycle`     |
| created data     | `perf-<runId>-…` (see below)       | `perf-mg1x2k-vu3`                   |

The k6 scenario name must be the one passed to `latencyThresholds`, which is how latency is gated
per scenario.

## Scenario rules

- Only call endpoints that exist in the backend. Check the controller, not the docs.
- Export one function named after the flow. Anything it needs from `setup()` arrives as `data`.
- Log in **once**, in `setup()` (`obtainAccessToken()`); login is rate limited per IP, and a login
  per iteration would measure the rate limiter. Tokens live 900 seconds, so an authenticated
  scenario is not suitable for a soak test until a refresh step exists. Say so in its doc comment.
- Assert with `checkResponse(res, status, { 'name': (body) => … })`. Name every check.
- Give every request with an id in its path a stable `tags: { name: '/api/v1/things/{id}' }`, or
  the metrics fragment per id.
- Finish with `sleep()` as think time, so the workload models users, not a tight loop.
- Needing the caller's own id? `currentUserId(accessToken)` in `setup()`.

## Thresholds

`errorThresholds` plus `latencyThresholds('<scenario_name>', INTERIM_LATENCY_MS)`. The latency
numbers are interim until real targets exist; do not invent tighter ones per module. A breached
threshold must fail the run.

## Test data and isolation

Write scenarios leave data behind, and some of it cannot be removed through the API. Design for that
up front:

1. **Undo what you can.** A lifecycle ends by reverting its own change (detach, revoke), so a
   successful iteration leaves nothing active.
2. **Name what you create** `perf-<runId>-<detail>`, where `runId` is generated once in `setup()`
   (`Date.now().toString(36)`). Names stay unique across runs and are easy to find.
3. **Bound what you cannot delete.** If an entity cannot be deleted and the system caps how many
   exist (RBAC: 500 roles per tenant), create it once per VU and reuse it, never once per iteration.
   Keep the VU's entity in a module-level variable, which k6 keeps per VU.
4. **Never depend on cleanup.** CI starts from an empty database, and other environments are not
   reset between runs. Only touch data your own run created, plus the seeded test user.
5. **Reset locally when needed**: `npm run reset-local-db -- --yes` drops and re-migrates the local
   docker-compose database (stop the backend first, start it again afterwards).

Append-only tables (for example `user_roles`) grow on every iteration of a write scenario. Keep
write workloads short and modest until a dedicated environment exists.

## Test user

Authenticated scenarios use the dev-profile seed user, which holds `TENANT_ADMIN` (all
permissions). Another environment needs its own account with the permissions the scenario needs.
Never commit credentials; they come from `PERF_USER_EMAIL` and `PERF_USER_PASSWORD`.
