# Coverage audit for Task US-016

**Phase:** 8 (Test-Validate)
**Scope:** `feature/US-016` working-tree changes only (branch has zero commits; HEAD == origin/main). Verified against `git status --short` plus `git diff HEAD` for tracked-file changes and direct reads of the untracked new files listed in the invocation context.

## Existing tests

- `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java` (82 test methods): the full D4/D14/D15/D17/D18 unit matrix for `assign()`/`revoke()` — name-match and dangerous-permission privilege paths, MC-2 (no `findActiveAssignmentViews` on the privilege path), MC-3(a)+(b) (both `hasActiveAdminAssignment` argument axes pinned against T-E22), M8-empty fail-closed without calling M5, propagation-on-throw for M7/M8/M5, exactly-one-denial/one-audit/one-metric when both gate halves hold, the four D18 lock-hold outcome tags, and the full throttle matrix (throttled short-circuits with zero downstream port/audit interaction, MC-7(i)/(ii) defense-in-depth, exactly-once `RBAC_DENIAL_THROTTLE_ENGAGED`).
- `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleManagementServiceTest.java` (46 test methods): AC7/AC11/AC4 gate ordering, D13's holder-count signal at boundaries 0/1/5/50 (all four bucket values `"0"`/`"1"`/`"2-10"`/`">10"`), WARN fired only when `holderCount > 0`, and confirmation the non-dangerous and AC11-denied paths never call `findActiveUserIdsForRole`.
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/RateLimitRoleChangeThrottleAdapterTest.java` (10 pre-existing methods): transition detection, self-clearing after the window, evict-on-read, fail-safe on a throwing store/clock, exact key format, and the "isThrottled never calls tryConsume" A-2 pin — all via a mocked `RateLimitStore` with a pre-programmed sequential answer.
- `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapterTest.java`: M7/M8 delegation (arguments/return values pass through unchanged, empty handled), constructor byte-identical (D16).
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapterTest.java`: D17's `operation` field and D13's `holderCount` field, both present-and-omitted-when-null, positioned correctly in metadata, `audit_write_failed{operation="deny"}` tag unchanged.
- `nexus-backend/src/test/java/com/example/nexus/rbac/LastAdminLockoutIT.java` (9 IT methods): MC-5 (EXPLAIN pinning M1/M5 to `fk_user_roles_role`), MC-6 (REPEATABLE-READ asserted inline), MC-1 (no `for share`/`for update` in M7/M8/M9's captured SQL), and Harnesses A/B/C — real 8-thread `CyclicBarrier`+`Future` races proving D2's lock order is deadlock-free, AC5 fires deterministically in its now-only-reachable self-revocation population, and a mixed cross-verb workload (RC-9.3) terminates with only expected outcomes.
- `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentAuditIT.java`: D17's `operation="assign"`/`"revoke"` metadata chain end-to-end against real MySQL, including under an 8-way concurrent cross-tenant denial race.
- `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentEscalationIT.java`: T-016's inversion — the former T-E16 exposure PoC now proves closure (403/`NOT_TENANT_ADMIN`, denial audit row, canary non-increment), Javadoc explicitly disclaiming T-E21.
- `nexus-backend/src/test/java/com/example/nexus/rbac/DangerousPermissionHolderSignalIT.java`: T-E21 residual made visible (not closed) — the two-legitimate-steps sequence, `holderCount==1`, the `holders="1"` bucket, and the WARN, with an explicit "must never be rewritten to assert a denial" Javadoc guard.
- `nexus-backend/src/test/java/com/example/nexus/rbac/RoleRevocationSymmetryIT.java`: the first-ever revoke-side denial/allow pair against real MySQL, plus the D7/D15 bypass canary proven against a real successful privileged self-assignment (not an empty registry).
- `nexus-backend/src/test/java/com/example/nexus/rbac/security/RoleAssignmentSecurityIT.java`: the permission×endpoint authorization matrix for `assign`/`revoke`/`list` (present/absent `user:write`/`user:read`, cross-tenant, malformed principal/UUIDs), plus stale-JWT-after-out-of-band-revocation for both the name-match and dangerous-custom-role paths.
- `nexus-backend/src/test/load/role-assignment-denial-pool-pressure.k6.js` (pre-existing, US-014): a concurrency-burst check against the `CROSS_TENANT_TARGET` denial path (T2) — this path is resolved in `verifySameTenant`/`resolveRoleInTenant`, entirely **before** D14's `requireNotThrottled` call, so it does not exercise the new throttle at all. Confirmed inadequate for D14 coverage (see Gaps).

## Gaps identified

- **[HIGH]** M7's comma-join JPQL (`JpaRoleRepository.findPermissionNamesByRole`, D16/A-6) had never been executed against real MySQL — only via a mocked adapter (unit) and via SQL-capture assertions that check for the *absence* of locking clauses, never the *correctness* of the returned rows. A cross-join or predicate bug (e.g. dropping the `rp.id.roleId = :roleId` filter, or a `BINARY(16)` bind mismatch under `UuidV7Converter`) would have passed every existing test. — added in `nexus-backend/src/test/java/com/example/nexus/rbac/RbacRepositoryRoundTripIT.java`.
- **[HIGH]** D14's transition-detection (`RateLimitRoleChangeThrottleAdapter.recordDenial`'s "exactly once" guarantee, A-3) was proven only against a Mockito mock returning a pre-programmed, strictly sequential answer sequence — structurally incapable of exposing a race. The service layer's `RBAC_DENIAL_THROTTLE_ENGAGED` WARN relies on this boolean being correct under real concurrent denials from the same actor. — added in `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/RateLimitRoleChangeThrottleAdapterTest.java`, using the real `InMemoryRateLimitStore` (not mocked) raced by 20 real threads.
- **[MED]** D18's composed lock-hold timer (RC-9.5) was proven correct in shape (four bounded outcome tags, no tenant dimension) only via a single-threaded unit test with a mocked `Timer.Sample`. Nothing verified the timer actually participates the expected number of times under the genuine lock contention the concurrency harnesses (A/B) already exercise. — added delta-based sample-count assertions (no duration thresholds, to avoid timing-dependent flakiness) to `LastAdminLockoutIT`'s Harness A (`revoked` outcome) and Harness B (`lockout` outcome).
- **[MED]** No load scenario exercised D14's denial-throttle path at all. The one existing k6 script (`role-assignment-denial-pool-pressure.k6.js`) targets a denial that resolves before `requireNotThrottled` is ever called, so it cannot demonstrate the throttle bounding cost under volume (T-D10/T-D11) or its per-`(tenantId, actorUserId)` keying (no cross-actor bleed). — added `nexus-backend/src/test/load/role-change-privileged-denial-throttle.k6.js`.
- **[LOW]** No test exercised M7 with an empty permission set against a *real* comma-join (only via a mocked port in `RoleAssignmentServiceTest`). — closed by the same `RbacRepositoryRoundTripIT` addition (a companion empty-result test).

Gaps considered and **not** added (already adequately covered, avoiding duplication):
- Authorization matrix (role × `assign`/`revoke`) — already exhaustive in `RoleAssignmentServiceTest` (unit) and `RoleAssignmentSecurityIT`/`RoleRevocationSymmetryIT` (integration).
- Boundary values for D13's holder-count buckets — already covers all four bucket boundaries (0/1/5/50) in `RoleManagementServiceTest`.
- D2's lock-order proof and the AC5/gate interaction under concurrency — already mechanically proven (MC-5/MC-6, Harnesses A/B/C) before this audit; no gap found.
- D17's `operation` metadata end-to-end — already asserted for both verbs in `RoleAssignmentAuditIT`.

## Tests added

- `RbacRepositoryRoundTripIT.should_returnDistinctPermissionNames_when_roleHasMultiplePermissionsAttached`
- `RbacRepositoryRoundTripIT.should_returnEmptyList_when_roleHasNoPermissionsAttached`
- `RateLimitRoleChangeThrottleAdapterTest.should_returnTrueExactlyOnce_when_manyThreadsRaceTheSameActorsDenialPastMaxDenials`
- `LastAdminLockoutIT.should_completeWithoutDeadlock_when_eightConcurrentRevokesRaceWithAnActiveAdminCaller` — extended with a D18 "revoked" timer sample-count delta assertion (same test, not a new method)
- `LastAdminLockoutIT.should_blockEveryThread_when_eightConcurrentSelfRevokesRaceForTheLastAdmin` — extended with a D18 "lockout" timer sample-count delta assertion (same test, not a new method)
- `nexus-backend/src/test/load/role-change-privileged-denial-throttle.k6.js` — new load scenario (see below)

## Run results

Backend, consolidated final run (`./mvnw verify`, Docker up, real Testcontainers MySQL, every edit in this audit compiled together in one pass — no `-DskipITs`):
- Unit (Surefire): **1034/1034 passing**, 1 skipped, 0 failures, 0 errors.
- Integration (Failsafe): **299/299 passing**, 0 failures, 0 errors, 0 skipped — includes `LastAdminLockoutIT` (9/9, with the new D18 lock-hold timer delta assertions in Harnesses A and B), `RbacRepositoryRoundTripIT` (8/8, with the two new M7 JPQL round-trip tests), and every other IT in the `rbac`/`identity` packages.
- SpotBugs: 0 bug instances, 0 errors.
- `BUILD SUCCESS`, exit code 0, total wall time 20:20 min.
- (An earlier full run and a standalone `LastAdminLockoutIT`-only re-run, both taken mid-audit before every edit had landed, also passed in full — 1034/1034 unit + 299/299 IT, and 9/9 for `LastAdminLockoutIT` alone respectively — consistent with the final consolidated numbers above.)

No frontend changes on this branch (confirmed against `git status --short`); `npm test` not applicable and not run, per the invocation's own scoping note.

## Load scenarios

- `nexus-backend/src/test/load/role-assignment-denial-pool-pressure.k6.js` (pre-existing, US-014): concurrency-burst check on the `CROSS_TENANT_TARGET` denial path. Confirmed **not** to exercise D14 (resolves before the throttle check).
- `nexus-backend/src/test/load/role-change-privileged-denial-throttle.k6.js` (new): sustained-rate (15 req/s, 30 s) burst against the `assign(TENANT_ADMIN)` name-match denial path from a single non-admin actor (exercising D14's cost bound, T-D10/T-D11) run concurrently with an independent second actor at the same rate (proving the throttle's per-`(tenantId, actorUserId)` key does not cross-throttle). Framed, like its US-014 sibling, as a targeted threat-model regression check rather than a routine ">10 RPS" endpoint-sizing script — `assign`/`revoke` are `user:write`-gated admin actions with low realistic steady-state RPS; the adversarial/misbehaving-client volume scenario is the one D14 exists to bound. Not part of `./mvnw verify`; run manually against staging with production-like HikariCP sizing.

## Flaky tests

- `RateLimitRoleChangeThrottleAdapterTest.should_returnFalseAndNotThrow_when_clockThrowsOnIsThrottled` (pre-existing test, not modified by this audit): observed taking 4.9 s in one run versus 0.005–0.05 s for every sibling test in the same class. This is consistent with a one-time JVM cost (Mockito's inline-mock-maker self-attaching, logged as a warning during this same run: "Mockito is currently self-attaching to enable the inline-mock-maker...") rather than non-deterministic test logic — the assertions themselves are state-based, not timing-based, and passed consistently across every run in this audit. Flagged as a **latency outlier to watch**, not a correctness flake; no action taken (would be scope creep to "fix" a pre-existing, passing test's incidental first-run cost).
- `LastAdminLockoutIT` Harnesses A/B/C (pre-existing, extended by this audit with delta-based timer assertions only): use `CyclicBarrier.await(5, TimeUnit.SECONDS)` and `ExecutorService.awaitTermination(15, TimeUnit.SECONDS)`. These are timing-bounded by design (a real 8-thread race against Testcontainers MySQL) and could theoretically time out under severe CI host contention, but this is the pre-existing, already-accepted concurrency-harness pattern used platform-wide (mirrors `ActiveAssignmentIT`, `RefreshTokenRotationIT`) and was not introduced or altered in kind by this audit — only outcome-count assertions were added on top of the existing barrier/executor shape. No new timing dependency was introduced.
- No other timing-, ordering-, or external-state-dependent tests were identified in the changed-file set. The `LastAdminLockoutIT` class's own `@AfterEach` cleanup (force-revoking bootstrap-tenant fixtures via raw JDBC) is what keeps its bootstrap-tenant scenarios order-independent; this predates the current story and was not touched.
