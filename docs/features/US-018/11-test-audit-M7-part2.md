# Coverage audit for Tasks T-010 to T-014 (US-018, M7 part 2 - epoch-keyed cache and holder fan-out, outage state machine, lost-bump replay, refresh limits, Redis auth)

Branch `ccr-4e9e7cbe-4vl9v6`, audited diff `f2cb1ea^..f5dc670` (T-010, T-011, T-012, T-013, T-014, the holder-read fix, the code-review and security-review fixes, and the SPA 429 retry in `auth.interceptor.ts`). Format and depth follow `08-test-audit-M7.md`. **No production code was edited** (checked with `git status` after every mutation experiment). `application-prod.yml` and the `@Disabled` on `RedisAuthStartupAssertionTest` were not touched.

## Changed source -> tests (matrix)

Counts are test methods after this audit; `+n` is what this audit added.

| Source (changed in scope) | Tests |
|---|---|
| `rbac.application.PermissionFreshnessService` (state machine, last-seen pools, replay, role replay, unparseable) | `PermissionFreshnessServiceTest` (194, +14), `EpochSchedulingIndependenceTest` (3), `TokenFreshnessIT` (19), `RoleManagementServiceTest` (holder paths) |
| `rbac.application.EpochReplayQueue` | `EpochReplayQueueTest` (23, +2) |
| `rbac.application.RoleReplayQueue` | `RoleReplayQueueTest` (15, +2) |
| `DegradedState`, `FreshnessVerdict`, `port.out.EpochUnparseableException`, `PermissionEpochPort`, `PermissionCachePort` | through the service, adapter and filter tests above and below |
| `rbac.application.RoleManagementService` (post-commit holder read, retry, detach bump, attach evict) | `RoleManagementServiceTest` (80), `TokenFreshnessIT`, `LastAdminLockoutIT` (14), `RoleAssignmentCacheIT` (7) |
| `rbac.application.RoleResolutionService` (epoch key, `resolveUncached`) | `RoleResolutionServiceTest` (13), `RoleResolutionServiceIT` (8), `JwtRs256ServiceTest` |
| `rbac.infrastructure.cache.RedisPermissionEpochAdapter` (script, range, bump result, probe, not-ready) | `RedisPermissionEpochAdapterIT` (39, +4), `...BumpResultTest` (3), `...ProbeTest` (2), `...NotReadyTest` (4, timing assertions fixed), `...NeverConnectsTest` (4, new), `AuthenticatedRedisIT` (7) |
| `rbac.infrastructure.cache.RedisPermissionCacheAdapter` (epoch keys, evict) | `RedisPermissionCacheAdapterTest` (17), `RedisPermissionCacheAdapterIT` (14, +1) |
| `rbac.infrastructure.cache.EpochRedisConfig` | `EpochRedisConfigTest` (16, +2), `AuthenticatedRedisIT`, `RedisPermissionEpochAdapterNotReadyTest` |
| `rbac.infrastructure.cache.RedisAuthStartupAssertion` | `RedisAuthStartupAssertionTest` (20, one `@Disabled`), `AuthenticatedRedisIT` |
| `rbac.infrastructure.cache.EpochSchedulingConfig` | `EpochSchedulingIndependenceTest` |
| `rbac.infrastructure.cache.RbacRedisKeys` | `RbacRedisKeysTest` (4, new), the Redis ITs |
| `identity.application.service.RefreshTokenUseCase` | `RefreshTokenUseCaseTest` (37, +5), `RefreshFailureThrottleIT` (4), `RefreshTokenPermissionResolutionIT` (4) |
| `SecureEventService`, `RefreshTokenPort`, `JpaRefreshTokenAdapter`, `JpaRefreshTokenRepository` (`revokeFamily` count) | `SecureEventServiceTest` (19), `RefreshTokenIT` (9) |
| `common.domain.RefreshThrottledException`, `common.web.GlobalExceptionHandler` | `GlobalExceptionHandlerTest` (25), `LoginControllerTest` (9, +2), `RefreshTokenUseCaseTest` |
| `identity.infrastructure.web.JwtAuthenticationFilter` (503 `AUTH_005`, public exemption) | `JwtAuthenticationFilterTest` (19), `TokenFreshnessIT`, `SecurityConfigWebTest` (14), `RequiresPermissionWebTest` (10) |
| `identity.infrastructure.web.LoginRateLimitFilter` (300/60 s total, no failure bucket) | `LoginRateLimitFilterTest` (18) |
| `identity.infrastructure.security.JwtRs256Service` (mint order, `verified`, `perm_epoch`) | `JwtRs256ServiceTest` (50), `JwtRs256ServiceSecurityTest` (13), `JwtClaimsContractTest`, `JwtSizeBenchmarkTest` |
| `application.yml` / `application-test.yml` keys | `RedisAuthStartupAssertionTest` profile cases, `EpochRedisConfigTest` TTL assertion, every IT that boots the context |
| `nexus-frontend/.../auth.interceptor.ts` | `auth.interceptor.spec.ts` (47, +16) |
| k6 (`tests/load/*`, `scenarios/*`) | not runnable here, see Load scenarios |

## Existing tests (what already covered the diff)

- `PermissionFreshnessServiceTest`: every transition of the outage machine on a fixed clock (3-in-10 s entry with exact-window edges, `t0` at the first failure, F F S pattern into closed, Recovering keeping `t0`, relapse open vs closed, 60 s sustain, drain failure not restarting the sustain, flap counter, gauges), RC-53 (bump and drain failures never move the machine), last-seen pools (read capacity, per-tenant cap, own-bump ceiling, global bump bound, move to the bump pool, tick purge, counters equal to the map under a race), fail-closed tenant markers (store down, DegradedOpen, store answers, expiry, lost-set full), H-2 store-written epochs, L-5 lower bound, replay queue (batches of 500, remainder with original `failedAt`, drop by newest failure, coalesce, overflow counts each id), role replay (queue, tick, hang bounded by 1 s, busy thread, overflow, degraded exit only when both queues are empty), unparseable (STALE, not counted, WARN once per tenant per minute with `suppressed`), `MintEpoch.verified`.
- `RedisPermissionEpochAdapterIT`: the whole 1..16 digit / `2^53 - 2` range (`nan`, `inf`, hex, exponent, sign, space, `2^53 - 1`, `Long.MAX_VALUE`, 17 digits with leading zeros) at read and at bump, ceiling stays, mixed valid and corrupt batches, 8 x 5 concurrent bumps without a lost update, paused-container bounds, 500-user batch, TTL refresh, A10 delete under the old epoch and under epoch 0.
- `TokenFreshnessIT`: TS-8, TS-9, the §9.4 race, key-expiry race, RC-24.3 (four bearer cases), RC-44.4 (401 healthy, 503 closed), replay within 2 s, replay after a paused Redis, holder-read failure replayed by the tick, reads failing after a seen bump.
- `RefreshTokenUseCaseTest` and `RefreshFailureThrottleIT`: family bucket after lookup only, failure bucket before the audit write and only on failure outcomes, 30 invalid then a valid refresh, 31st is 429 with no row, one WARN per window with `rejectedCount` and no IP or family id, reuse first (RC-51) with an exhausted bucket, second replay throttled, concurrent invalid refreshes write at most 30 rows (real Redis consume).
- `JwtAuthenticationFilterTest`: `UNAVAILABLE` -> 503 `AUTH_005` with `Retry-After: 30` and escaped body, DegradedOpen proceeds, public requests never rejected.
- `auth.interceptor.spec.ts` (`refresh 429`): Retry-After honoured, three attempts, proactive 429 keeps the session, 401 still clears, concurrent share one refresh, header clamp cases.

## Gaps identified

Gaps were found by reading each changed class against the design §9.11 test list, the threat-model RC list and JaCoCo (baseline run on `f5dc670`: 1809 unit, 457 IT, all green). Every new test exercises existing behaviour, so each passed on its first run; to prove they are not vacuous, a mutation of the production line was applied for most and reverted (noted per row, `git status` clean of production files afterwards).

- [HIGH] Tenant isolation of the locally-seen epochs and the replay queue was never asserted with the **same user id in two tenants**. A bump in tenant A must not make tenant B's token stale (store down, DegradedOpen, mint), and queued bumps of two tenants replay as two script calls with their own tenant id - added in `PermissionFreshnessServiceTest` (4 tests). Mutation: `UserKey` equality on the user id only -> 3 of them fail.
- [HIGH] Drain vs offer: nothing proved that the scheduler's poll/requeue and request threads' offers lose no queued user. Added at queue level (4 producers x 500 users against a drainer that requeues half its batches; replayed users equal the offered ones, size 0) in `EpochReplayQueueTest`, and at service level (4 workers failing 3 bumps in 4 while 300 ticks drain; after the store answers one tick leaves nobody unbumped and the queue empty) in `PermissionFreshnessServiceTest`. Mutations: no `requeue` in the drain -> service test and 4 existing tests fail; no `size++` in `requeue` -> queue test fails.
- [HIGH] Third-party origin safety of the SPA interceptor (the documented `@security` guarantee) had no test and was the only uncovered branch of `auth.interceptor.ts`: a token is never attached to another origin, a third-party 401 triggers no refresh and no logout, no proactive refresh for it - added in `auth.interceptor.spec.ts` (3 tests). Mutation: remove the origin guard -> all 3 fail.
- [HIGH] The refresh 429 contract end to end through the controller: `RefreshThrottledException` -> 429 `RATE_001` with `Retry-After` and **no `Set-Cookie`** (the SPA keeps the session, so the server must not clear the cookie), and the reuse response 401 `AUTH_004` without a cookie - added in `LoginControllerTest` (2 tests).
- [MED] Interceptor 429 state machine edges: success on the third attempt, a 401 on the retry after a 429 (clears, stops), a fresh refresh for the next 401 after exhaustion (`refreshInFlight` reset), proactive 429 then success forwards with the new token, 503 `AUTH_005` and a plain 429 on a normal request are surfaced without refresh or logout, `Retry-After` boundaries (1, 60, 61, padded, fractional, HTTP date, empty) - added in `auth.interceptor.spec.ts` (13 tests). Mutation: clamp 61 and a looser number regex -> 10 fail.
- [MED] Boundaries of A-20: a replay that revokes nothing spends only the failure bucket, never the family's; a user that vanished after a valid token consumes no failure bucket and writes no row; a token that expires exactly now still rotates (strict `isBefore`) and one nanosecond later does not; the WARN stays suppressed one second before the window ends - added in `RefreshTokenUseCaseTest` (5 tests). Mutation on the first two -> both fail.
- [MED] TTL edge: the last-seen entry still counts 1 ms before the key TTL (only the expiry side was pinned); the all-tenants fail-closed marker ends after one key TTL; the tick purges expired lost-tenant markers so a full set does not outlive its markers (otherwise one overflow marks every tenant) - added in `PermissionFreshnessServiceTest` (3 tests). Mutation: drop the purge, make the all-tenants marker permanent -> both fail.
- [MED] Role replay read failure modes with no test: the replay thread stopped (counts a failed read, keeps the role, never touches the port) and an interrupted tick (stops waiting, keeps the role, keeps its interrupt flag) - added in `PermissionFreshnessServiceTest` (2 tests). Covers JaCoCo lines 1161-1163 and 1170-1173.
- [MED] TLS parity of the dedicated factories (RC-45.2): `startTls` and the verify mode were copied but never tested (the only uncovered branch of `EpochRedisConfig`) - added in `EpochRedisConfigTest` (2 tests).
- [MED] Lua key formatting at 16 digits: the script formats the old epoch with `%.0f`; the DEL must hit the key Java built with `Long.toString`. Added with the old epoch at `MAX_EPOCH - 1`; also a zero-padded 16-digit value (valid for `parse` and for the script, read then raised by one) and a stored `0` (valid, read as 0, bump writes Redis TIME) - added in `RedisPermissionEpochAdapterIT` (3 tests).
- [MED] Tenant isolation at the Redis layer: bumping a user id in tenant A leaves tenant B's epoch key and cache entries alone; evicting one tenant's holder leaves the other tenant's entry - added in `RedisPermissionEpochAdapterIT` and `RedisPermissionCacheAdapterIT`.
- [MED] Operator log signals with no assertion: `RBAC_LAST_SEEN_BUMP_DROPPED` (ERROR, once per marking, tenant id only), `RBAC_HOLDER_READ_REPLAY_DROPPED` (ERROR, role and tenant ids, no user ids), `RBAC_EPOCH_DEGRADED_RECOVERING` (INFO) - added in `PermissionFreshnessServiceTest` (3 tests).
- [MED] The "never connect on a request thread" rule (H-1) was only checked with wall-clock bounds. Added the deterministic form: while a template is not ready the adapter never calls `read()` or `bump()` on it - `RedisPermissionEpochAdapterNeverConnectsTest` (4 tests).
- [LOW] Pure unit pin of the Redis key shapes the Java adapters and the Lua scripts share (tenant scope, epoch suffix, 16-digit rendering, roleset vs permset) - `RbacRedisKeysTest` (4 tests).
- [LOW] Queue edges: offering nobody for a new tenant leaves no phantom tenant; a role queue offered concurrently never exceeds capacity and keeps the oldest and newest times; a poll of only expired roles empties the queue; a mint whose retry read finds the corrupt key is an unverified 0 - added in the queue and service tests.
- [LOW, no test] Unreachable or defensive lines left uncovered, no hook to reach them: `PermissionFreshnessService:1153` (a read abandoned in the instant it starts), `:1178` (a checked cause of the read), `RefreshTokenUseCase:298-299` (`NoSuchAlgorithmException` for SHA-256), `EpochRedisConfig:263` (interrupt while the warm-up thread sleeps; the thread name is shared across tests, so asserting its end would be order-dependent), and the double-checked-locking re-checks (`:590`, `:639`) that need a race.
- [LOW, pre-existing, outside the diff] `LoginRateLimitFilter` 413 paths (login and forgot body size) are uncovered (6 lines).

## Requirement traceability (claims in the design, threat model and decisions A-18 to A-22)

Every item below names a running test unless marked.

| Claim | Test |
|---|---|
| TS-8, TS-9 incl. after refresh, §9.4 race, absent key, v2 as epoch 0 | `TokenFreshnessIT` |
| RC-24.3 four bearer cases, RC-44.4 (401 healthy, 503 closed, logout without cookie) | `TokenFreshnessIT`, `JwtAuthenticationFilterTest` |
| RC-29.2 TTL startup assertion, RC-29.3 key-expiry race | `EpochRedisConfigTest`, `TokenFreshnessIT` |
| RC-30 / RC-42 replay (every state, within 2 s, coalesce, overflow drop-newest, partial drain) | `PermissionFreshnessServiceTest`, `EpochReplayQueueTest`, `TokenFreshnessIT` |
| RC-31 / RC-41 / RC-53 machine (3-in-10 s, F F S, relapse, sustain, only reads and probes count) | `PermissionFreshnessServiceTest` |
| RC-52 scheduling independence | `EpochSchedulingIndependenceTest` (3, real `@Scheduled`) |
| RC-34.1 / RC-45.2 `require-auth` over main and both dedicated factories, ACL user, `rediss://` | `RedisAuthStartupAssertionTest`, `AuthenticatedRedisIT`, `EpochRedisConfigTest` |
| **RC-45.1 the `prod` profile resolves `require-auth=true`** | **test exists but is `@Disabled`: no running test** (open, human, see Open items) |
| RC-32 / RC-43 buckets, WARN per window, no row on throttle | `RefreshTokenUseCaseTest`, `RefreshFailureThrottleIT` (real Redis), `LoginRateLimitFilterTest`, `LoginControllerTest` |
| RC-51 reuse first, `revokeFamily` count, exactly one reuse row | `RefreshTokenUseCaseTest`, `RefreshFailureThrottleIT`, `RefreshTokenIT`, `SecureEventServiceTest` |
| MC-7a mint order, MC-7b bumps only in `afterCommit` | `JwtRs256ServiceTest` (`InOrder`), `RoleManagementServiceTest`, `RoleAssignmentServiceTest` |
| M-2 holder read retried once, role replayed by the tick | `RoleManagementServiceTest`, `PermissionFreshnessServiceTest`, `TokenFreshnessIT` |
| L-1 one valid range for script and parser | `RedisPermissionEpochAdapterIT`, `...BumpResultTest` |
| L-3 unverified mint skips the cache | `JwtRs256ServiceTest`, `RoleResolutionServiceTest` |
| A-18 last-seen pools, fail-closed markers, A-21 H-1 no scan on a request thread | `PermissionFreshnessServiceTest` |
| RES-40 SPA keeps the session on a refresh 429 | `auth.interceptor.spec.ts`; the k6 gate `refresh-junk-flood.js` was **not run** |
| RC-32.3 / RC-43.3 / RC-51 storm gate, §9.5 latency budget | k6 only, **not run** (no dev stack) |
| RES-31 (queue lost on restart), RC-31.4 (restart resets the window), RES-30 (platform-wide 503), RC-31.5 alerts, §9.9 alert rules | accepted or operational; no automated test, and none is possible for the alert rules here |
| A-22 (6) tenant predicate on `findActiveUserIdsByRole` | follow-up, not implemented, so nothing to test |

## Tests added

Backend (35 unit, 5 IT) and frontend (16).

- `PermissionFreshnessServiceTest` (14): `should_notReturnStale_when_sameUserIdWasBumpedInAnotherTenant`, `should_notReturnStale_when_sameUserIdWasBumpedInAnotherTenantAndInstanceIsDegradedOpen`, `should_mintZero_when_sameUserIdWasBumpedInAnotherTenantAndStoreIsDown`, `should_replayEachTenantSeparately_when_sameUserIdQueuedForTwoTenants`, `should_stillReturnStale_when_oneMillisecondBeforeKeyTtl`, `should_mintUnverifiedZero_when_firstReadEmptyAndRetryUnparseable`, `should_loseNoBump_when_requestThreadsFailWhileTickDrainsAndRequeues`, `should_stopFailingClosedForEveryTenant_when_lostAllMarkerOlderThanKeyTtl`, `should_markOnlyTheLosingTenant_when_expiredLostTenantMarkersWerePurged`, `should_keepRoleQueuedAndCountFailure_when_replayThreadWasStopped`, `should_keepRoleQueuedAndRestoreInterruptFlag_when_tickInterruptedDuringHolderRead`, `should_logBumpDroppedOncePerMarkingWithTenantOnly_when_ownBumpsRefused`, `should_logRoleReplayDroppedWithIdsOfRoleOnly_when_roleQueueFull`, `should_logRecoveringInfoWithInstanceAndCause_when_probeSucceedsInDegradedOpen`
- `EpochReplayQueueTest` (2): `should_stayEmpty_when_offeredNoUsersForNewTenant`, `should_loseNoUser_when_offeredWhileDrainerPollsAndRequeues`
- `RoleReplayQueueTest` (2): `should_neverExceedCapacityAndKeepOldest_when_offeredConcurrently`, `should_returnEmptyAndEmptyTheQueue_when_everyRoleExpired`
- `RefreshTokenUseCaseTest` (5): `should_consumeOnlyFailureBucket_when_replayRevokesNothing`, `should_consumeNoFailureBucketAndWriteNoRow_when_userVanishedAfterValidToken`, `should_stillSuppressWarn_when_oneSecondBeforeWindowEnds`, `should_rotate_when_tokenExpiresExactlyNow`, `should_rejectWithoutRotating_when_tokenExpiredOneNanoAgo`
- `LoginControllerTest` (2): `should_return429Rate001WithRetryAfterAndNoSetCookie_when_refreshThrottled`, `should_return401Auth004WithNoSetCookie_when_refreshTokenReused`
- `EpochRedisConfigTest` (2): `should_copyStartTlsAndPeerVerification_when_mainFactoryUsesThem`, `should_notEnableStartTls_when_mainFactoryUsesPlainSsl`
- `RbacRedisKeysTest` (4, new class): `should_buildTenantScopedEpochKey`, `should_appendEpochToStem_when_buildingCacheKeys`, `should_separateRolesetFromPermsetAndTenantFromTenant`, `should_renderSixteenDigitEpochAsPlainDigits`
- `RedisPermissionEpochAdapterNeverConnectsTest` (4, new class): `should_notTouchReadTemplate_when_currentCalledBeforeReadConnectionReady`, `should_notTouchReadTemplate_when_probeCalledBeforeReadConnectionReady`, `should_notTouchBumpTemplate_when_bumpCalledBeforeBumpConnectionReady`, `should_notUseReadTemplate_when_onlyBumpConnectionIsReady`
- `RedisPermissionEpochAdapterIT` (4): `should_readAndRaiseByOne_when_storedValueIsZeroPaddedTo16Digits`, `should_readZeroAndBumpToRedisTime_when_storedValueIsZero`, `should_deleteCacheEntryUnderSixteenDigitEpoch_when_bumped`, `should_leaveOtherTenantsEpochAndCacheEntry_when_sameUserIdBumped`
- `RedisPermissionCacheAdapterIT` (1): `should_leaveOtherTenantsEntry_when_evictingSameUserIdInOneTenant`
- `auth.interceptor.spec.ts` (16): never attaches the bearer to a third-party origin; no refresh or logout on a third-party 401; no proactive refresh for a third-party origin; succeeds on the third attempt after two 429s; a 401 on the retry after a 429 clears and stops; a fresh refresh after exhaustion; proactive 429 then success; 503 `AUTH_005` surfaced without refresh or logout; 429 `RATE_001` on a normal request surfaced; `it.each` over 7 `Retry-After` shapes (1, 60, 61, padded, fractional, HTTP date, empty).
- Changed, not added: `RedisPermissionEpochAdapterNotReadyTest` (see Flaky tests). No assertion was loosened.

## Run results

`cd nexus-backend && sh ./mvnw -o verify` with Docker running (dockerd was already up), `JAVA_HOME` = JDK 25.

| Run | Surefire (unit, slice) | Failsafe (IT) | Gates |
|---|---|---|---|
| Baseline on `f5dc670`, before any change | 1809 run, 0 failures, 0 errors, 2 skipped | 457 run, 0 failures, 0 errors, 0 skipped | BUILD SUCCESS, 6 m 42 s |
| After the first batch of tests | 1834, 0, 0, 2 | 462, 0, 0, 0 | BUILD SUCCESS |
| **Final, after the last test edit** | **1844 run, 0 failures, 0 errors, 2 skipped** | **462 run, 0 failures, 0 errors, 0 skipped** | **BUILD SUCCESS, 6 m 11 s; Checkstyle 0 violations; SpotBugs 0; JaCoCo "All coverage checks have been met"** |

- Skipped (2, unchanged): `RedisAuthStartupAssertionTest.should_resolveRequireAuthTrue_when_prodProfileActive` (`@Disabled` by design until `application-prod.yml` gets `require-auth: true`) and the pre-existing conditional `JpaAuthEventAdapterFailurePathBenchmarkTest`.
- Between the runs, targeted mutation runs and isolated loops (see Flaky tests) were made; production files were restored each time and verified with `git status`.

Frontend (`cd nexus-frontend`, Node 22.22.3 from `/tmp/claude-0/n` put first on `PATH`, `ng` refuses 22.22.0):

- `npm run test:ci`: **236 of 236 passing**, 29 of 29 files (220 before this audit, +16). Overall 88.34% statements, 80.57% branches. `auth.interceptor.ts` 100% of statements, branches, functions and lines after the audit (it was 98.03% statements, 96.77% branches, 97.87% lines).
- `npm run lint`: all files pass. `npm run format:check`: all files pass.

JaCoCo, touched classes (line, branch), baseline -> final:

| Class | Line | Branch |
|---|---|---|
| `PermissionFreshnessService` | 98.3% -> 99.6% (527/529) | 224/240 -> 224/240 |
| `EpochReplayQueue` | 98.0% -> 100% | 27/28 -> 28/28 |
| `RoleReplayQueue` | 100% | 12/12 |
| `RedisPermissionEpochAdapter` | 100% | 33/36 (3 partial: `probe` null, two script-result guards) |
| `RedisPermissionCacheAdapter` | 100% | 14/14 |
| `RedisAuthStartupAssertion` | 100% | 12/12 |
| `EpochRedisConfig` | 98.0% -> 100% | 11/12 -> 12/12 |
| `RbacRedisKeys` | 100% | n/a |
| `RefreshTokenUseCase` | 98.0% (97/99; SHA-256 catch) | 16/16 |
| `JwtAuthenticationFilter` | 100% | 19/19 |
| `LoginRateLimitFilter` | 93.5% (pre-existing 413 paths) | 41/46 |
| `RoleManagementService` | 100% | 63/64 |
| `RoleResolutionService` | 100% | 4/4 |
| `JwtRs256Service` | 99.1% | 45/50 |
| `GlobalExceptionHandler` | 98.1% | 5/6 |

Every layer rule of `docs/TESTING.md` passed (the build enforces them).

## Load scenarios

No scenario was added: the three needed for this diff already exist and no k6 run is possible here (no dev stack). Checked statically: `node --check` and Prettier pass for every file under `tests/load` and `scenarios`; `k6 inspect` (k6 v1.3.0) parses `detach-refresh-storm.js` and `refresh-junk-flood.js` and resolves their options and thresholds, and `epoch-check-latency.js` in `EPOCH_CHECK_MODE=baseline` (200 req/s constant arrival for 5 m, 50 to 200 VUs).

| Endpoint, expectation | File | State |
|---|---|---|
| Guarded request, epoch check, 200 req/s | `nexus-test/performance-test/tests/load/epoch-check-latency.js` | exists, matches design §9.5 (epoch p95 <= 2 ms, zero new `skipped_error`, endpoint p95 baseline + 5 ms). Not run |
| `POST /auth/refresh` after a detach, 200 holders behind one IP plus an attacker at 100/min and replays | `tests/load/detach-refresh-storm.js` + `scenarios/detach-refresh-storm.js` | exists; thresholds: zero forced logouts, zero failed recoveries, every replay answered 401 `AUTH_004`, successor never 200, `storm_refresh_failure_throttled > 0`. Not run (merge gate, per deployment shape) |
| `POST /auth/refresh`, 400 junk/min from one IP next to valid users | `tests/load/refresh-junk-flood.js` | exists; valid users see 200 or 429 with a valid `Retry-After`, never 401, and recover. Not run |

Missing, to be written when a staging topology exists:
1. **Detach fan-out latency at scale** (1,000 and 10,000 holders): the 204 waits for every sequential batch of 500 on the request thread with the JDBC connection held (design §9.4, T-D23). The design's "20 calls of about 1 ms" and the 500 ms bump timeout are only checked for one batch (`should_bump500UsersWithinBumpTimeout_when_fullBatch`).
2. **Redis impaired under load** (A-18 part (c), open): the 50 ms read bound under overload, time to `DegradedOpen`, the platform-wide 503 after the window, and recovery. Needs fault injection in the staging Redis.
3. **Steady refresh throughput** (above 10 RPS): not representable from one source IP because the per-IP total is 300/60 s; it needs several source IPs or the proxy topology (DF-1).
4. `docs/TESTING.md` still names `nexus-backend/src/test/load/` as the load-test location; the epoch and refresh scenarios live in `nexus-test/performance-test` (docs drift, as noted in the previous audit).

## Flaky tests

Measured by running isolated surefire JVMs (`surefire:test -Dtest=...`, cold JVM, which is how an IDE or `-Dtest` run behaves), idle and with 4 busy loops on the 4 cores.

| Test | Finding | Measurement |
|---|---|---|
| `RedisPermissionEpochAdapterNotReadyTest` (3 timing tests, 20 ms bound) | **Order-dependent and cold-JVM-dependent: red in isolation.** `elapsed` was computed after `assertThat(...)`, so the first AssertJ use in the JVM (class loading) was inside the timed region. It passed in the full suite only because other tests had already loaded AssertJ. | Before: `should_returnEmptyImmediately_when_readConnectionNotReady` failed **12 of 12** isolated runs (56 ms). After moving the clock read right behind the call: 2 of 36 isolated runs still failed (22 ms, first call in a cold JVM). After also running each not-ready path once in `@BeforeEach`: **0 of 20 idle, 0 of 15 under 4-core saturation**. Bounds are unchanged (20 ms). Intent preserved and strengthened: `RedisPermissionEpochAdapterNeverConnectsTest` pins "never touches the template while not ready" without a clock. |
| `PermissionFreshnessServiceTest` real-time tests (`should_requeueWithOriginalTimeAndKeepTickRunning_when_holderReadHangs`, `should_readAgainOnNextTick_when_earlierReadWasCancelledBeforeItRan`, both 1 s by design: the production read timeout is wall clock), my interrupt test, the 4 concurrency tests | Timing-bound by the design's 1 s role read timeout, otherwise deterministic (final assertions do not depend on interleaving). `awaitRoleReadIdle` polls with `Thread.sleep(20)` under a 10 s deadline (style: Awaitility is the project convention). | 8 idle and 6 loaded isolated runs of this class together with the queue, scheduling, refresh-use-case and filter classes: all green. |
| `EpochSchedulingIndependenceTest` | Waits on the real 1 s `@Scheduled` tick with a 10 s ceiling, polling with `Thread.sleep(50)`. Each test takes about 1 s (justified: it proves the real scheduler runs). | included in the loops above: green |
| `RedisPermissionEpochAdapterIT` paused-container tests (150 ms and 2 x read-bound max latency) and `TokenFreshnessIT` (< 1000 ms revoke to refreshed token) | Timing-bound against a real container; the most scheduler-sensitive tests of the diff. | 4 isolated runs of 92 tests (`RedisPermissionEpochAdapterIT`, `TokenFreshnessIT`, `AuthenticatedRedisIT`, `RefreshFailureThrottleIT`), 2 idle and 2 with 4 busy loops: all green; plus 3 full verify runs |
| `TokenFreshnessIT`, `AuthenticatedRedisIT`, `RedisPermissionEpochAdapterIT.awaitReady` | `Thread.sleep(25..100)` polling loops under deadlines (15 s, 30 s, 10 s, 3 s). Not a source of flakiness, but against `docs/TESTING.md` ("No Thread.sleep", use Awaitility). | n/a |
| `RateLimitIT.rate_limit_resets_after_window` (outside the diff) | Waits out a real rate-limit window, 11 s. | n/a |
| `EpochReplayQueueTest.should_loseNoUser_when_offeredWhileDrainerPollsAndRequeues` (new) | Spins a drainer thread while producers run; ends on a final-state assertion. If a regression leaves the size counter unbalanced it fails by the 60 s `get` timeout instead of hanging (seen once during a mutation run, then bounded). | 0.1 s when green |

Slow tests (> 1 s) in scope, all justified above: `TokenFreshnessIT` 3 to 7 s each (real Redis pause, state machine, real windows), `AuthenticatedRedisIT.should_neverBecomeReady_when_passwordRemovedAndRequireAuthFalse` 3 s (observes that readiness never arrives), `RefreshTokenUseCaseTest.should_throw429WithRetryAfterAndWriteNoAuditRow_when_thirtyFirstInvalidRefresh` 1.2 s, two `PermissionFreshnessServiceTest` cases at 1 s (read timeout), `EpochSchedulingIndependenceTest` 1 s each.

## Defects found

No production defect was proven by a failing test. Items for the owners:

1. **[Test defect, fixed]** The NotReady timing assertions measured AssertJ's first-use initialisation (table above). Test-only change in `RedisPermissionEpochAdapterNotReadyTest`.
2. **[Design vs code, decision needed]** The SPA clears the session on **any** refresh failure except 429: a refresh answered 500/503 or a network error (status 0) logs the user out. Design §9.7 says it "clears it only on 401". A 503 from a briefly unavailable database during a refresh, or an offline tab, ends the session. Not changed and not pinned by a test (a test would cement the mismatch). Either narrow the condition in `auth.interceptor.ts` (clear on 401 only) or amend §9.7.
3. **[Open, human action]** `application-prod.yml` still has no `nexus.rbac.redis.require-auth: true` and the only test that would catch it is `@Disabled` (security review H-1). Until then production can start against an unauthenticated Redis (RES-32). Untouched on purpose.
4. **[Nit]** `isApiRequest` uses `pathname.startsWith(base.pathname)`, so same-origin `/apiary/...` also receives the bearer. Same origin only, so no third-party leak; match on `/api/` to be exact.

## Open items

- Human: `application-prod.yml` `require-auth: true`, then remove `@Disabled` from `RedisAuthStartupAssertionTest.should_resolveRequireAuthTrue_when_prodProfileActive` (merge-checklist item already recorded in `04-tasks.md`).
- Merge gates not run here: `epoch-check-latency.js` (baseline then gate), `detach-refresh-storm.js` and `refresh-junk-flood.js` in the production ingress topology, once per deployment shape (direct client IP, behind the proxy).
- Decide item 2 above (refresh 5xx/offline logs the user out versus the design text).
- Write the three missing load scenarios above (fan-out at scale, Redis impaired under load, multi-IP refresh).
- Follow-ups already recorded: tenant predicate on `findActiveUserIdsByRole` (A-22 (6)), extraction of `OutageStateMachine` and `LastSeenEpochs` (A-21 (10)).
- Replace the `Thread.sleep` polling loops in the ITs and `awaitRoleReadIdle` with Awaitility (style, `docs/TESTING.md`).
