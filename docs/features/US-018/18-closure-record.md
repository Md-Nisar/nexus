# US-018 closure record

**Date:** 2026-10-18 · **Branch:** `ccr-047fcb60-fqvz6w` (on top of `main` at `9f6ce30`, PR #91) · **Scope source:** `04-tasks.md`.

## What "closed" means here

All US-018 code and documentation milestones are implemented and pass the local build gate. Nothing has run against a real MySQL, Redis, Kubernetes cluster or browser stack, because no environment exists (decision 2026-10-05) and Docker is unavailable in the build container. The work that needs those is **deferred and documented below**, not done. US-018 is closed as a branch deliverable. It is **not** production-verified, and it must not take production traffic until the deferred list is worked.

## Milestones

| Milestone | Tasks | Where | Local gate (`verify -DskipITs`, JDK 25) |
|---|---|---|---|
| M2, M1, M6, M4, M7, M7b, M5 | T-001..T-015, T-007, T-008 | merged to `main` (#81, #82, #84, `25ceeed`, #88, #90, #91) | recorded in `STATUS.md` |
| M3 | T-016..T-019 | this branch | 2005 run, 0 failures, 1 skipped |
| M8 | T-020..T-024 | this branch | 2042 run, 0 failures, 2 skipped; frontend 244 passed |
| M9 | T-025..T-030 | this branch | 2226 run, 0 failures, 2 skipped; frontend 253 passed |
| M9-contract | T-031 | this branch | 2226 run, 0 failures, 2 skipped |
| M11 | D1, D2, D4 | this branch | docs only |

The M3, M8, M9 and M9-contract gate numbers were re-run independently on the committed tree, not taken from the implementing agents' reports. The frontend numbers are the implementing agent's report and were not re-run.

## Decisions made on this branch

- **P-1 (RES-46), write-refusal residual: ACCEPTED.** While Redis refuses writes but serves reads, a revoke or detach is enforced at once only on the issuing instance, and already-issued tokens stay valid elsewhere for up to 900 s. Compensating controls already in place: a failed bump evicts the affected users' cached permission sets (`FailedBumpCacheEvictionTest`), `bump_failed{reason=redis}` pages immediately, and the replay queue retries. The alternative, a per-instance write canary, would turn a Redis out-of-memory condition into a platform-wide 503 after 15 minutes; that cost is larger than the residual. Owner: the author of the M7 PR. SRE gives Redis capacity input at the first deployment; the decision is revisited if `maxmemory` under `noeviction` is the deployed policy.
- **P-2 (RR-M3), client IP behind the proxy: RESOLVED.** `server.forward-headers-strategy: native`, with `server.tomcat.remoteip.internal-proxies` set from `NEXUS_TRUSTED_PROXIES`. The default trusts loopback only, so an unconfigured deployment cannot be spoofed (it keys on the proxy address, as `none` did). `docker-compose.yml` trusts only the frontend nginx container at a fixed address on a dedicated `edge` network and binds the backend port to `127.0.0.1`. Production must set `NEXUS_TRUSTED_PROXIES` to the exact ingress address. nginx appends the real peer to `X-Forwarded-For`; Tomcat takes the right-most untrusted hop. **Runtime-unverified:** the valve behaviour was not exercised.
- **M7 part 2 H-1:** already satisfied on `main` (`require-auth: true` in `application-prod.yml`, test enabled).
- **Automated security-review findings on M3:** three, all dispositioned in `15-threat-model-repass-M3.md` (RES-26, design §5.6 non-locking reads, RES-28).

## Deliberately skipped (by decision of the story owner, 2026-10-16/18)

1. **Integration tests were never run** (no Docker). They compile. Nothing has exercised migrations V7 to V10, the column-scoped `UPDATE (name, description, deleted_at) ON roles` grant, or the Redis Lua scripts (permission epoch, role-change throttle).
2. **k6 gates and the permission-cache benchmark were never run:** NAT refresh gate, `refresh-junk-flood.js`, `detach-refresh-storm.js`, the pool-pressure gate, the denial-throttle scenario and `permission-cache-benchmark.js`. The B6 keep/remove decision is **not made**: the cache stays on until measured (ADR-0022 addendum, "not yet measured").
3. **Held at the owner's request:** the `@Disabled` RC-54(b) test (the shared-store startup assertion for the throttle) stays disabled, and `application-prod.yml` is not changed. The lines a human adds at deployment are `nexus.rbac.throttle.require-shared-store: true` and `nexus.security.rate-limit.store-type: redis`; after that the RC-54(b) test is re-enabled. Until then the role-change denial throttle can run per JVM in production (RES-11).
4. **Sign-offs and acceptances for people:** Ops (Kubernetes audit logging RC-37.3, page-capture drill RC-37.4, reconciliation alert, retention RES-6 for the new audit events), Platform Security Owner (RES-26 at the M3 re-pass, RES-45), and ADRs 0021 to 0025 still **Proposed** (ADR-0023 B4 acceptance included).

## Required at the first deployment (before any production traffic)

- Create a staging environment and run: all `*IT` classes; the three k6 gates plus the benchmark; the M3 soak (at least one sprint with no `RbacAdministrators` anomalies) and the zero-admin sweep.
- V8 pre-flight (`SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.tenant_id <> r.tenant_id` = 0 in every environment); maintenance windows for V8 and V9; the per-environment column grant; **V10 only after the V9 release is live on every instance**.
- Set `NEXUS_TRUSTED_PROXIES`; add the two `application-prod.yml` lines above; confirm the prod profile is active (A-3).
- Create the alerts defined in `monitoring.md` (cross-tenant rate, `deletedRoleActiveAssignments`, break-glass reconciliation, attach signals, epoch signals).
- M2 items: permset cache flush after V6, A1 detection query, custom-admin exposure check, flag overrides checked.
- SRE and PM confirm the A9 availability consequence (RES-30); the `audit:read` detection query runs before the access-review flag flips.

## Code that has never executed against its real dependency

V7, V8, V9 and V10 DDL; the generated `active_name` column and its unique key; the column-scoped grant behaviour; the epoch and throttle Lua scripts; `RedisRoleChangeThrottleAdapter`; the Tomcat remote-IP valve configuration; the PATCH CORS change in a browser.

## Known residuals (accepted, recorded elsewhere)

RES-26 (second-account pre-positioning; review date 2026-11-27 and the Epic-3 hard expiry unchanged), RES-28 (concurrent detach race), RES-11 until the prod lines are added, RES-46 (P-1 above), the T-E32 wording "self path closed; transformed into RES-26" in EPIC-002.

## Housekeeping left

- Two M1 findings (pre-existing, outside the US-018 diff) still need tickets: the `%6Cogin` rate-limit path bypass (Medium) and the actuator metrics endpoints readable by any authenticated user (Low). `STATUS.md` lists them.
- Opening the PR for this branch: `/pre-pr-check` has not been run and no PR exists. It needs a human decision on how to split or squash the milestone commits.
