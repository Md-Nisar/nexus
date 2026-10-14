# Coverage audit for Task T-009 (US-018, M7 - per-user permission epoch, A9)

Branch `ccr-4e9e7cbe-4vl9v6`, audited diff `origin/main...HEAD` (source in `19bec79` and `13a8e1f`; the rest is docs and the k6 harness). No production code was edited.

## Existing tests
- `rbac/application/PermissionFreshnessServiceTest` (21): verdict boundaries (equal, +1, -1, key absent, v2 epoch 0 vs stored), single-request fail-open then stale on next request, outcome counters (registered at 0, one per verdict), latency timer incl. skipped_error, p50/p95/p99, `epochForMint` (success, absent, fails twice, fail-then-succeed, single read, not counted as a check), `invalidateUser` (target only, never propagates, logs `RBAC_EPOCH_BUMP_FAILED` with operation for a non-DataAccessException).
- `rbac/infrastructure/cache/RedisPermissionEpochAdapterNotReadyTest` (3): read returns empty and bump throws immediately while no connection exists (never connects on the caller thread).
- `rbac/infrastructure/cache/RedisPermissionEpochAdapterIT` (9 pre-audit): absent key reads 0, bump = Redis TIME, +1 when ahead of TIME, monotonic across key deletion, TTL, tenant-scoped key, multi-user bump, 50 ms bound against a paused container, 50 concurrent readers against a paused-from-start Redis then recovery (warm-up).
- `rbac/infrastructure/cache/EpochRedisConfigTest` (13 pre-audit): key-TTL startup assertion boundaries, both factories from the same connection details, timeouts and REJECT_COMMANDS, Sentinel, cluster rejected, SSL via bundle and `rediss://`.
- `identity/infrastructure/web/JwtAuthenticationFilterTest` (+10): stale -> 401 AUTH_003 and chain skipped, skipped_error proceeds, one check with token tenant/user/epoch, non-UUID subject -> 401 never throws, no check when verification fails, public request never rejected or epoch-checked (stale, expired, bad signature), public verified bearer gets empty permissions and no authorities, matcher not consulted without a bearer.
- `identity/infrastructure/security/JwtRs256ServiceTest` (+6): epoch read before permissions (InOrder), v3 minted with epoch, epoch 0, v2 verifies as epoch 0, v3 epoch value returned (Long and Integer-sized).
- `config/SecurityConfigWebTest`, `EndpointClassificationWebTest`, `PublicEndpointRequestMatcherTest`, `AuthenticationDetailsContractTest`: stale/fresh on a protected endpoint, refresh with an invalid bearer, public path with a non-public method, matcher fail-closed counter.
- `rbac/application/RoleAssignmentServiceTest` (+5): invalidate only inside afterCommit, never on rollback, never on denied revoke, target not actor, never on assign.
- `rbac/TokenFreshnessIT` (8 pre-audit): TS-8 revoke -> 401 -> refresh -> 403 within 1 s, key absent is fresh, v2 token for a recently revoked user, stale bearer on refresh/logout (200/204), logout revokes family with and without cookie.

## Gaps identified
- [MED] `perm_epoch` upper boundary: `Long.MAX_VALUE` accepted and carried through, and a value above the long range (BigInteger) rejected with reason `perm_epoch` - added in `JwtRs256ServiceTest`.
- [MED] A v2 token that carries a `perm_epoch` claim must still verify as epoch 0 (a forged or leftover claim must not raise it) - added in `JwtRs256ServiceTest`.
- [HIGH] Concurrent bumps: nothing proved the Lua script is atomic. 8 threads x 5 bumps on one user, starting ahead of Redis time, must end at exactly start + 40 (a lost update shows as a short total) - added in `RedisPermissionEpochAdapterIT`.
- [MED] Unparseable stored value: the `NumberFormatException` branch of `current()` (fail-open, empty) had no test - added in the adapter IT.
- [MED] Bump over an unparseable stored value: the script's `tonumber(...) or 0` recovery had no test - added in the adapter IT.
- [MED] A second bump must refresh the key TTL (only the first bump's TTL was asserted) - added in the adapter IT.
- [MED] Bump failure when Redis stops answering after connect: only reads were tested against a paused server; the bump (500 ms template) is shown to throw `DataAccessException` and not hang - added in the adapter IT.
- [LOW] Stored `Long.MAX_VALUE` reads back unchanged - added in the adapter IT.
- [LOW] Bump with no users is a no-op and creates no key - added in the adapter IT.
- [MED] Per-user scope: revoking one user must not stale another user's token - added in `TokenFreshnessIT`.
- [LOW] Master/replica topology rejected like cluster (ADR-0016 D1; only cluster was tested) - added in `EpochRedisConfigTest`.

## Tests added
- `JwtRs256ServiceTest`: `should_returnPermEpoch_when_v3TokenEpochIsLongMaxValue`, `should_rejectWithPermEpochReason_when_v3PermEpochExceedsLongRange`, `should_ignorePermEpochClaim_when_v2TokenCarriesOne`
- `RedisPermissionEpochAdapterIT`: `should_returnEmpty_when_storedValueUnparseable`, `should_returnStoredValue_when_epochIsLongMaxValue`, `should_recoverToRedisTime_when_unparseableValueBumped`, `should_refreshTtl_when_bumpedAgain`, `should_createNoKey_when_bumpGivenNoUsers`, `should_loseNoIncrement_when_bumpedConcurrently`, `should_throwDataAccessExceptionWithoutHanging_when_bumpAgainstPausedRedis`
- `TokenFreshnessIT`: `should_keepOtherUsersTokenFresh_when_anotherUserRevoked`
- `EpochRedisConfigTest`: `should_failStartup_when_connectionDetailsDeclareMasterReplica`

## Run results
`JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64 /opt/maven/bin/mvn -o verify` in `nexus-backend` with Docker (dockerd started locally), full suite run twice:
- Run 1: Surefire 1525 run, 0 failures, 0 errors, 1 skipped; Failsafe 384 run, 0 failures, 0 errors, 0 skipped; BUILD SUCCESS.
- Run 2: identical counts; BUILD SUCCESS.
- The one skip is the pre-existing `JpaAuthEventAdapterFailurePathBenchmarkTest` (conditional, not in this diff).
- Before the full runs, the new/changed ITs passed once in isolation (`RedisPermissionEpochAdapterIT` 16/16, `TokenFreshnessIT` 9/9). The first run of the new isolation test failed (login 400) because the e-mail local part exceeded 64 characters; the test tag was shortened, not the assertion.
- Frontend `npm run test:ci`: not run, `nexus-frontend/node_modules` is absent and the diff has no frontend change.

## Load scenarios
No Gatling or `src/test/load` added, as instructed. `nexus-test/performance-test/tests/load/epoch-check-latency.js` was read and is consistent with design §9.5: 200 req/s constant arrival on `GET /api/v1/roles` for 5 m (above the 3 m the 2-minute Micrometer window needs), server-side epoch p95 <= 2 ms, zero new `skipped_error` (difference of setup and teardown), endpoint p95 < baseline + 5 ms, `dropped_iterations` = 0, baseline mode, `npm run test:load:epoch-check`, `RATE`/`DURATION` overrides wired in `environment.js` and `constant-arrival-rate.js`. The k6 run itself was not executed here (needs a staging topology). Note `docs/TESTING.md` still names `nexus-backend/src/test/load/` as the location.

## Flaky tests
None failed in 2 full runs plus 2 isolated runs. Timing-dependent tests that can flake on a loaded CI runner (existing, not changed, not weakened):
- `RedisPermissionEpochAdapterNotReadyTest`: both tests assert < 20 ms wall time (first call may pay class loading / JIT).
- `RedisPermissionEpochAdapterIT.should_returnEmptyWithinReadBound_when_containerPaused`: asserts < 150 ms against a 50 ms bound.
- `RedisPermissionEpochAdapterIT.should_neverBlockRequestThreads_when_startedAgainstPausedRedisThenRecover`: 50 threads, max latency < 100 ms; it is the most scheduler-sensitive.
- `TokenFreshnessIT.should_reject401ThenRefreshWithoutPermission_withinOneSecond_when_roleRevoked`: < 1000 ms including a refresh round trip.
- `RedisPermissionEpochAdapterIT.awaitReady` polls with `Thread.sleep(25)` (bounded by a 15 s deadline); `docs/TESTING.md` prefers Awaitility. Not deterministic-time dependent, but a style violation.
- The new paused-container test only uses a 5 s ceiling to catch a hang; it does not assert on elapsed time. The new concurrency test asserts an exact total, not timing.

## Not covered, reported only
- Only `revoke` bumps the epoch. Other permission-reducing paths (role-permission removal, role deletion, user deactivation) do not call `invalidateUser`; whether that is intended is a design question, no test was added.
- Revoke committing while Redis is down end to end (degraded-closed behaviour) is T-011's, as the `TokenFreshnessIT` header states. `invalidateUser` swallowing the failure is covered at unit level only.
- The Low findings in `07-security-review-M7.md` were not touched.
