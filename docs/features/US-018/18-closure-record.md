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

## Found by the first integration run (2026-10-18)

The first full `verify` with Docker (MySQL 8.4 and Redis in Testcontainers) failed 23 of 580 ITs; all are fixed. One was a real finding, the rest were fixtures written before V8, V9 and the new authorization rules.

- **V8 drops the old index (real finding).** Adding the composite foreign key `fk_user_roles_role_tenant (role_id, tenant_id)` makes MySQL silently replace the implicit single-column index `fk_user_roles_role`. The M11 lock query still ran, because MySQL tolerates `FORCE INDEX` on the old name and used the composite index, but it named an index that no longer exists. `JpaUserRoleRepository.lockActiveAssignmentHoldersByRoles` now forces `fk_user_roles_role_tenant`, and the plan-pinning tests assert it (`key = fk_user_roles_role_tenant`, `type = ref`). The composite index leads with `role_id`, so the lock still drives off `role_id` and keeps the ascending role-id acquisition order that the deadlock argument (ADR-0017 D7) relies on; it is also narrower, locking by `(role_id, tenant_id)`. V8's header comment says `fk_user_roles_role` is kept; that applies to the constraint, not the index. The migration is append-only, so the comment stays. Reconfirmed on a bare MySQL 8.4 container.
- **Fixtures.** Roles were seeded in a random tenant and assigned in `TENANT_ID` (V8 rejects that); `HeldPermissionPartitionIT` forged a cross-tenant row that V8 now makes impossible, so the foreign role is assigned under its own tenant; `TokenFreshnessIT`'s admin lacked `role:read`, which the role-subset rule requires to detach it; `RoleManagementAdminGateIT` used role names over 64 characters; `RolePermissionsPrivilegeIT` matched `DELETE` inside the column name `deleted_at`; `LastAdminLockoutIT` read `performance_schema` as `nexus_app`, which has no access, so it now observes lock waits as the container's root user.
- **Revoke error paths.** Three unit tests were added for a failing port read during `revoke()` (classification, tenant role set, and the set-locked decision read with the error timer), which the M3 test rewrite had not carried over.

## Deliberately skipped (by decision of the story owner, 2026-10-16/18)

1. **Integration tests: run once on 2026-10-18** (see the section above). Docker was installed in the build container afterwards, and the ITs exercised migrations V7 to V10, the column-scoped grant and the Redis scripts through Testcontainers. The results are recorded below. Still not run: anything needing a deployed environment.
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

The Tomcat remote-IP valve configuration and the PATCH CORS change in a browser. (V7 to V10, the generated `active_name` key, the column grant and the Redis scripts have now run in the ITs.)

## Known residuals (accepted, recorded elsewhere)

RES-26 (second-account pre-positioning; review date 2026-11-27 and the Epic-3 hard expiry unchanged), RES-28 (concurrent detach race), RES-11 until the prod lines are added, RES-46 (P-1 above), the T-E32 wording "self path closed; transformed into RES-26" in EPIC-002.

## Housekeeping left

- The two pre-existing M1 findings are closed: the `%6Cogin` rate-limit bypass is fixed in `LoginRateLimitFilter` (path matched after decoding), and the actuator metrics exposure was already closed by M7 (scrape token). See `STATUS.md`.
- Opening the PR for this branch: `/pre-pr-check` has not been run and no PR exists. It needs a human decision on how to split or squash the milestone commits.
