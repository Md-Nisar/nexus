# Code review: US-018 M7 / T-009 (A9 per-user permission epoch, core)

**Verdict: CHANGES REQUESTED.** Reviewed by the `code-reviewer` agent (fresh context). Scope: `git diff origin/main...HEAD`, commits `19bec79` (the change) and `6294e24` (docs only), 38 files, +2434/-160. Nothing was modified by the review.

## Resolution (2026-10-07)

All findings are fixed in the branch `ccr-4e9e7cbe-4vl9v6`. Gates after the fixes: `mvn verify -DskipITs` 1521 tests, 0 failures, 0 errors (1 skipped), 0 Checkstyle violations, 0 SpotBugs bugs; full `mvn verify` the same plus 376 ITs, 0 failures; k6 `npm run inspect` and `format:check` pass. Not re-run: the k6 hot-path load run itself (needs the full stack).

| Finding | Fix |
|---|---|
| H-1 | `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java:214,231` (`WarmedFactory` connects each factory on its own daemon thread, retry with 100 ms to 2 s backoff); `:197-202` `readReady()` / `bumpReady()`; `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java:64` (read returns empty at once) and `:80` (bump throws `RedisConnectionFailureException` at once). Tests: `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapterIT.java:220` (paused Redis from startup, 50 concurrent `current()`, max latency under 2x the 50 ms bound, then unpause and recovery) and `RedisPermissionEpochAdapterNotReadyTest` (no Docker) |
| M-1 | `EpochRedisConfig.java:114-146` now takes the auto-configured main `LettuceConnectionFactory` and copies its TLS flag, verify mode, STARTTLS, `SslOptions` (bundle managers, ciphers, protocols) and client name; Javadoc rewritten (`:25-45`); design §9.5 wording updated (`03-design.md:810`). Tests in `EpochRedisConfigTest`: `should_useSslWithBundleOptionsAndClientName_when_mainFactoryUsesSslBundle` (`:193`), `should_useSsl_when_mainFactoryAutoConfiguredFromRedissUrl` (`:226`, Boot's real auto-configuration) |
| M-2 | Docs only: `04-tasks.md:532` (M7 merge checklist, first item) and `STATUS.md` (M7 paragraph and table row): M7 merges as one PR with T-009..T-014; T-009 must not merge or release alone |
| L-1 | `nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java:120` catches `RuntimeException`, same `RBAC_EPOCH_BUMP_FAILED` ERROR log; comment on the 500 ms connection hold at `:116-117`. Test `PermissionFreshnessServiceTest.should_logBumpFailedWithOperation_when_bumpFailsWithNonDataAccessException` |
| L-2 | `PermissionFreshnessService.java:69-77` `epochForMint` retries the read once before falling back to 0 (chosen over the 500 ms template so the port stays unchanged). Tests `should_returnCurrentEpoch_when_epochForMintReadFailsThenSucceeds`, `should_returnZero_when_epochForMintReadFailsTwice`, `should_readOnce_when_epochForMintFirstReadSucceeds` |
| L-3 | `EpochRedisConfig.java:74-75` adds the clock skew. `rbac` may not import `identity` (ArchUnit `rbac_must_not_depend_on_identity`), so the constant now lives in `nexus-backend/src/main/java/com/example/nexus/common/security/TokenClockSkew.java` and `AuthConstants.AUTH_CLOCK_SKEW_SECONDS` (`identity/domain/AuthConstants.java:14`) is that value. Boundary tests `should_start_when_keyTtlEqualsTokenTtlPlusSkewPlusMargin`, `should_failStartup_when_keyTtlOneBelowTokenTtlPlusSkewPlusMargin`. The skew is 0 today, so these only distinguish the formula if the skew changes |
| L-4 | `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapterIT.java:152` `isGreaterThan(first)`; residual risk recorded in `docs/adr/0022-permission-token-freshness.md:128` (ADR-0022 is still Proposed) |
| L-5 | `nexus-test/performance-test/tests/load/epoch-check-latency.js:62-85` reads `skipped_error` in `setup()` and gates on the difference in `teardown()`; `README.md` (epoch gate paragraph) updated |
| L-6 | `03-design.md:291` (matcher row and the 405 to 401 change), `04-tasks.md` T-009 (e) (same note), `STATUS.md` table row and M7 paragraph |
| N-1 | Not cached. A request-attribute cache would survive a forward or error dispatch to another path, and the matcher must fail closed. Comment justifying the second call at `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java:87-88` |
| N-2 | `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java:99-108` catches `IllegalArgumentException` and calls `reject(...)`. Test `should_return401AndNeverThrow_when_verifiedClaimsHaveNonUuidSubject` |
| N-3 | `PermissionFreshnessService.invalidateUser(tenantId, userId, operation)` (`:115`); `RoleAssignmentService.java:633` passes `OPERATION_REVOKE`; tests adjusted |
| N-4 | Dated amendment note at the end of `docs/adr/0016-redis-infrastructure-dependency.md` (ADR-0016 is Accepted, so its decisions are not rewritten, ADR 0001): Redis 5 or later, 7.x tested |

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 1 (H-1) |
| Medium | 2 (M-1, M-2) |
| Low | 6 (L-1 .. L-6) |
| Nit | 4 (N-1 .. N-4) |

Fix H-1 and M-1, and settle M-2, before merge. L-1 and L-3 are one-line fixes worth doing in this PR.

## Gates run by the reviewer

- Targeted unit tests (offline, jacoco and spotbugs skipped): all green. JwtAuthenticationFilterTest 14, PermissionFreshnessServiceTest 17, EpochRedisConfigTest 9, JwtRs256ServiceTest 44, JwtClaimsContractTest 1, RoleAssignmentServiceTest 155, AuthenticationDetailsContractTest 2, PublicEndpointRequestMatcherTest 28, JwtClaimsTest 4.
- ITs not run by the reviewer (no Docker): `TokenFreshnessIT`, `RedisPermissionEpochAdapterIT`, `RefreshTokenPermissionResolutionIT`. They ran on the branch in the implementation session (375 IT, 0 failures).
- Library behaviour checked by disassembling Boot 4.1.1 `PropertiesDataRedisConnectionDetails` / `LettuceConnectionConfiguration` and SDR 4.1.1 `LettuceConnectionFactory$SharedConnection` (evidence for H-1 and M-1).

## Matches the design

- **MC-7a:** `JwtRs256Service.java:118` reads `epochForMint` before `resolve`; `should_readEpochBeforeResolvingPermissions_when_issuing` pins the order with `InOrder`.
- **MC-7b:** the bump runs in `registerPostCommitSideEffects`, after the lock-hold timer stops (`RoleAssignmentService.java:633`); the test fails if `invalidateUser` runs outside `afterCommit`.
- **Fail-open limited to one request:** `SKIPPED_ERROR` lets that request through and is counted; no state is kept (`should_returnStaleOnNextRequest_after_singleSkippedError`).
- **Public endpoints (RC-24 / RC-44.2):** matcher runs before `verify`; a failed bearer is ignored; a verified bearer gets `authorities=[]` and `PERMISSIONS=[]` with no epoch check. Unit tests for each; `TokenFreshnessIT` covers refresh and logout.
- **`permitAll` from the matcher (method + pattern):** closes the path-only F-5 hole. Side effect: a wrong method on a public path now gets 401 instead of 405 (see L-6).
- **Lua bump:** atomic, `max(old+1, TIME ms)`, `SET ... EX ttl`, missing key handled; IT covers first bump, stored value ahead of TIME, deletion, TTL, key shape.
- **Token:** `CURRENT_VERSION` 3, accepted {2, 3}; v2 is epoch 0; a v3 token without a valid `perm_epoch` is rejected.
- **Config:** 50 ms read, 500 ms bump, `key-ttl-seconds` 960; startup fails below max(token TTL, cache TTL) + 60 s (boundary tests 959/960); Cluster and static master/replica fail startup.

Good decisions: `switch (verdict)` without `default` (T-011 verdicts won't compile until handled); bounded metric tags; private dedicated factories so Boot's Redis auto-configuration does not back off; literal-pattern rule for `@PublicEndpoint`; paused-container IT; generic `AUTH_003` body.

## Findings

### [HIGH] H-1: First epoch-read connection is opened on request threads under a lock
`EpochRedisConfig.java:96-99, 150-162`.
- SDR 4.1.1 `SharedConnection.getConnection()` runs `if (connection == null) connection = getNativeConnection()` inside `doInLock(...)`. Until the shared connection exists, every `current()` call takes the lock in turn and makes its own connect attempt, each bounded by the 50 ms RedisURI timeout.
- If Redis refuses connections each attempt fails fast. If the network drops packets (security group, partition, frozen host), throughput is about 20 epoch reads per second per instance. At 200 RPS the queue grows by about 180 requests per second and Tomcat threads run out within seconds. `epochForMint` uses the same template, so login and refresh hang too.
- Design §9.5's runbook action for a Redis outage is "raise the window through config and a rolling restart"; every restarted instance would start in exactly this state and hang instead of failing open. The paused-container IT avoids this path on purpose.
- **Fix:** never connect on the request thread. Warm both factories off-thread at startup (`factory.start()` then `CompletableFuture.runAsync(factory::getConnection)` with retry); in the adapter return `OptionalLong.empty()` immediately while a `volatile boolean ready` is false, or use `tryLock` semantics. Add an IT: start against a paused container, fire 50 concurrent `current()` calls, assert max latency is about 2x the bound.

### [MEDIUM] M-1: Dedicated factories don't match the main factory's TLS
`EpochRedisConfig.java:104-119`.
- `details.getSslBundle()` returns null unless `spring.data.redis.ssl.enabled=true`. Boot's main factory also calls `useSsl()` for a `rediss://` URL. With `SPRING_DATA_REDIS_URL=rediss://...` the main factory uses TLS while both epoch factories connect in plaintext, sending `HELLO/AUTH` in cleartext before the server drops the connection. Every check then returns `SKIPPED_ERROR` (fail open on every request) and every bump fails, with only ERROR logs as a signal.
- Boot also applies `SslBundle.getOptions()` ciphers and protocols and the client name; these factories do not. The Javadoc and RC-45.2 promise more than the code does. `EpochRedisConfigTest` has no SSL test. Latent today because the YAML uses host and port.
- **Fix:** derive both factories from the auto-configured `LettuceConnectionFactory` (copy `getClientConfiguration()` and the standalone/sentinel configuration). At minimum add `if (url != null && url.startsWith("rediss:")) client.useSsl()` and copy the bundle's ciphers and protocols. Add tests: bundle gives `isUseSsl()` true with SslOptions; `rediss://` URL gives TLS.

### [MEDIUM] M-2: On `main`, T-009 alone fails open on every request while Redis is down
`PermissionFreshnessService.java:83-97`; `STATUS.md`.
- Until T-011 adds the degraded-state machine and the 503 time limit, a Redis outage skips the epoch check on every authenticated request and nothing pages. The spring-boot-standards skill says authorization fails closed unless the design records an exception; ADR-0022 records only a time-boxed one. The constraint lives only in a STATUS sentence.
- **Fix:** merge M7 as one PR containing T-009..T-014, or not before T-011. Say so in the PR description and in the `04-tasks.md` M7 exit criteria.

### [LOW] L-1: `invalidateUser` catches only `DataAccessException`
`PermissionFreshnessService.java:111`. Other runtime exceptions (for example `IllegalStateException` from a stopped factory during shutdown, or an NPE from a script result) propagate out of `afterCommit`, so a committed revoke returns 500 and nothing logs `RBAC_EPOCH_BUMP_FAILED`. The bump also holds the JDBC connection up to 500 ms (comment worthy). **Fix:** `catch (RuntimeException e)` with the same ERROR log, as `RoleAssignmentService.recordDenial` does.

### [LOW] L-2: Mint-time epoch read uses the 50 ms template
`JwtRs256Service.java:118` -> `PermissionFreshnessService.java:70`. Intermittent read failures mint `perm_epoch=0` for a recently revoked user, giving a 401 -> refresh -> 401 loop (bounded by the refresh rate limit). **Fix:** read on the bump template (500 ms) or retry once before falling back to 0; add a "mint read fails then succeeds" test.

### [LOW] L-3: Key-TTL assertion ignores clock skew
`EpochRedisConfig.java:63-71`. `verify()` accepts tokens up to `AUTH_CLOCK_SKEW_SECONDS` after `exp` (`JwtRs256Service.java:168`). **Fix:** `Math.max(accessTokenTtlSeconds + AuthConstants.AUTH_CLOCK_SKEW_SECONDS, permissionCacheTtlSeconds) + MIN_KEY_TTL_MARGIN_SECONDS`.

### [LOW] L-4: Monotonicity IT assertion is weaker than the property
`RedisPermissionEpochAdapterIT.java:125`. `isGreaterThanOrEqualTo(first)` passes if the post-deletion bump equals the earlier epoch; a token minted at `first` must become STALE, so it needs `>`. **Fix:** `isGreaterThan(first)`. Record in ADR-0022 the residual risk that key loss plus a Sentinel failover to a replica with a lagging clock can produce a smaller value.

### [LOW] L-5: k6 `skipped_error` gate uses the counter total since JVM start
`nexus-test/performance-test/tests/load/epoch-check-latency.js:77-83`. A JVM that already counted a blip fails a clean run. **Fix:** read the counter in `setup()` and gate on the difference in `teardown()`, or document "fresh JVM per gate run".

### [LOW] L-6: Docs drift
- `03-design.md:291`: the `@PublicEndpoint` row still says "listed in `SecurityConfig` `permitAll`"; it is now granted via `PublicEndpointRequestMatcher`.
- The 405 -> 401 behaviour change for a wrong method on a public path is not recorded in the design or API notes (a client relying on 405 now sees `AUTH_003`).
- `STATUS.md` table row "M5, M7, ..." still says "Not started" while the paragraph below says T-009 is implemented.

### Nits
- **N-1:** `PublicEndpointRequestMatcher.matches` runs twice per bearer request (`JwtAuthenticationFilter.java:89` and `SecurityConfig.java:87`); microseconds, optional request-attribute cache.
- **N-2:** `JwtAuthenticationFilter.java:100-101` `UUID.fromString(...)` relies on `verify()`'s canonical-UUID guarantee; another `JwtPort` would 500. Comment citing RC-40.1 or catch `IllegalArgumentException` -> `reject(...)`.
- **N-3:** `invalidateUser` hard-codes `operation="revoke"` (`PermissionFreshnessService.java:114`); T-010's detach needs a parameter.
- **N-4:** The bump script calls `TIME` then writes, which needs Redis 5+ (effects replication). Compose and ITs use 7.4, but ADR-0016's prerequisites state no minimum.
