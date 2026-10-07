# Code review: US-018 M7 / T-009 (A9 per-user permission epoch, core)

**Verdict: CHANGES REQUESTED.** Reviewed by the `code-reviewer` agent (fresh context). Scope: `git diff origin/main...HEAD`, commits `19bec79` (the change) and `6294e24` (docs only), 38 files, +2434/-160. Nothing was modified by the review.

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
