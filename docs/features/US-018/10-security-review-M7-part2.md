# Security Review: US-018 M7 part 2 (T-014, T-010, holder-read fix, T-011, T-012, T-013 and review fixes)

**Verdict: BLOCKED.** There is 1 High, 2 Medium and 3 Low findings, and no Blocker. Only the High blocks the merge. It is a configuration gap, not a code defect: T-014's Redis-authentication guard is off in production because `application-prod.yml` does not set `nexus.rbac.redis.require-auth: true`. The merge checklist already tracks this as the open H-3, and a human has to make the edit because a repo hook blocks agents. The verdict becomes **APPROVED** once both of these are done:
1. `application-prod.yml` sets `nexus.rbac.redis.require-auth: true`.
2. `@Disabled` is removed from `RedisAuthStartupAssertionTest.should_resolveRequireAuthTrue_when_prodProfileActive`, and the test is green.

The two Mediums must be fixed or explicitly accepted, with the named owner, before the M7 PR merges. The Lows can be ticketed.

**Scope:** `git diff f2cb1ea^..HEAD` on `ccr-4e9e7cbe-4vl9v6` at HEAD `c1057d8`. That is 12 commits and 68 files, +7165/-310:
- T-014: `f2cb1ea`, `6124d2a`
- T-010: `94859ca`
- holder-read fix: `224ea88`
- T-011: `02d67fc`
- T-012: `23cf696`
- T-013: `98c79f6`
- code review: `8eb529a`
- review fixes: `1aed47a`, `52cfe0d`, `7007287`, `c7dd28e`, `c1057d8`

Items resolved in `07-security-review-M7.md` are not raised again. This review did not modify, stage or commit any application code, test or config file.

**Auth, authorization, crypto, credentials and PII were reviewed explicitly.** This diff changes authentication and authorization code (`JwtAuthenticationFilter`, `JwtRs256Service`, `PermissionFreshnessService`, `RefreshTokenUseCase`, `LoginRateLimitFilter`). It also changes credential handling (`RedisAuthStartupAssertion`, `EpochRedisConfig`) and touches logging of identifiers and IPs. The concerns checked were:
- **Freshness verdicts:** the verdict for every state of the degraded state machine, and every path on which a revoked token can still be accepted.
- **Last-seen map:** what fills it, how big it can get, and when entries expire.
- **Replay queue:** how bumps for the same user are coalesced, when entries expire, and whether a bump can be lost.
- **Epoch values:** the H-2 store-returned epochs, the Lua guard, the Java parser, and minting with an unverified epoch.
- **503 `AUTH_005`:** the response itself and the exemption for public endpoints.
- **Refresh tokens:** the family, `REFRESH_IP` and `REFRESH_IP_FAIL` buckets, reuse detection, family revocation, and whether 429 or 401 comes first.
- **Redis authentication:** the `require-auth` check against the effective connection configuration, with no credentials in messages.
- **Isolation and injection:** tenant isolation of every new key and query, and injection into cache keys and scripts.
- **Logs and metrics:** user ids, IPs and family ids in log lines and metric tags, and whether log volume is bounded.
- **Fan-out:** resource use of the detach fan-out.
- **Crypto:** SHA-256 for the family bucket key (not used as a MAC). No algorithm, key or randomness changes.

---

## Verification run

| Check | Result |
|---|---|
| Unit tests (`./mvnw -o verify` with jacoco, spotbugs and checkstyle skipped): `PermissionFreshnessServiceTest`, `EpochReplayQueueTest`, `RefreshTokenUseCaseTest`, `JwtAuthenticationFilterTest`, `RedisAuthStartupAssertionTest`, `RoleManagementServiceTest`, `RoleResolutionServiceTest`, `EpochSchedulingIndependenceTest`, `LoginRateLimitFilterTest`, `GlobalExceptionHandlerTest`, `JwtRs256ServiceTest`, `RedisPermissionCacheAdapterTest`, `TenantIsolationArchitectureTest` | **423 run, 0 failures, 0 errors, 1 skipped.** The skip is the `@Disabled` prod-profile test (High below). |
| ITs (Docker available): `TokenFreshnessIT` (18), `RedisPermissionEpochAdapterIT` (29), `RefreshFailureThrottleIT` (4), `AuthenticatedRedisIT` (6), `RedisPermissionCacheAdapterIT` (11) | **68 run, 0 failures, BUILD SUCCESS** |
| Bump Lua script run against a local `redis-server` 7.0.15 with corrupt stored values (evidence for Low L-1) | `nan` → script writes and returns `nan`; `-nan` → `-nan`; `9007199254740993` → `9007199254740992` (the epoch goes down by one); `9000000000000000000` → current time in ms (the epoch goes down); `inf` and `0x10` → current time in ms |
| `sh ./mvnw -Psecurity dependency-check:check` | **Could not complete; left to CI.** The CISA KEV feed returned `403 Forbidden`, then `NoDataException: No documents exist`, the same as the M7 part 1 review. The diff changes no `pom.xml` and adds no backend dependency. |
| `npm audit --omit=dev --audit-level=high` (`nexus-frontend`) | **Exit 1: 7 vulnerabilities (6 moderate, 1 high), all pre-existing and unchanged since `07-security-review-M7.md`** (`@angular/*` 22.0.x; the fixes are in 22.1.x/22.2.x). This diff changes no frontend code and no lockfile. The only `package.json` change is a k6 script entry in `nexus-test/performance-test`, with no dependency. |
| k6 storm gate and NAT refresh gate | Not run here (no dev stack). Both remain open merge-checklist items. |

---

## Findings

```
[HIGH] T-014 is inert in production: application-prod.yml does not set require-auth, and the test that would catch it is @Disabled
File: nexus-backend/src/main/resources/application-prod.yml (key absent)
      nexus-backend/src/main/resources/application.yml:179 (require-auth: ${NEXUS_RBAC_REDIS_REQUIRE_AUTH:false})
      nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/cache/RedisAuthStartupAssertionTest.java:254-258
Issue: RedisAuthStartupAssertion itself is correct. It checks the effective password of all
       three factories, including the rediss:// userinfo and the Sentinel password, and its
       messages never include a credential (this closes the M7 part 1 Low on T-014). But it
       only runs when require-auth is true. The default is false and the prod profile does not
       override it. RC-45.1 asked for this exact line in application-prod.yml, so the property
       is not set and nothing tests it. The only remaining control is "Ops sets the env var",
       which RC-45.1 was written to remove. RC-45.1 also asked for
       nexus.rbac.throttle.require-shared-store=true in the same file, and that is absent too.
Risk: A production start against a Redis with no password succeeds. Anyone who can reach Redis
      on the network can then:
      - DEL or rewrite nexus:rbac:epoch:* to suppress revocation (A9);
      - write nexus:rbac:permset:* to inject permissions at the next mint;
      - corrupt epoch values (see L-1).
      T-T16 and RES-32 are "Low after RC-34 and RC-45" only once the property is enforced in the
      prod profile, so until then the threat model's mitigation is not visible in code.
      OWASP A05 (Security Misconfiguration), A07, A01.
Fix: A human edits application-prod.yml to add `nexus: rbac: redis: require-auth: true` (and
     `nexus.rbac.throttle.require-shared-store: true`, per RC-45.1), removes @Disabled from
     should_resolveRequireAuthTrue_when_prodProfileActive, and runs it green. This is the
     merge-blocking H-3 item in 04-tasks.md; this review confirms it blocks.
```

```
[MEDIUM] Unauthenticated junk refreshes at 5 req/s exhaust REFRESH_IP (300/60 s) and log out every SPA user behind the same IP; RES-40 does not name this, and the k6 gate stays below it
File: nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/LoginRateLimitFilter.java:36-40 (Javadoc), 206-210
      nexus-backend/src/main/resources/application.yml:230 (refresh-ip-max-attempts: 300)
      nexus-frontend/src/app/core/http/auth.interceptor.ts:112-113, 150-151 (clearSession on any refresh error)
      nexus-test/performance-test/config/environment.js:98 (STORM_ATTACKER_PER_MINUTE default 100)
Issue: The filter's per-IP total counts every POST /auth/refresh, cookie or not, before the use
       case runs. RC-43 moved the failure bucket into the use case, so 30 junk requests no
       longer block valid refreshes. The 300 total still counts junk, though, and the filter
       Javadoc is wrong when it says "failing refreshes can never block a valid one behind a
       shared IP". The SPA clears the session on any refresh error, including a 429. The NAT
       gate's attacker sends 100/min, deliberately under the total (README "Why the spread"),
       so the gate cannot see this attack. Under DF-1 (getRemoteAddr is the proxy), the bucket
       is platform-wide.
Risk: Someone on the same egress IP (a corporate NAT, campus or mobile CGNAT) sends 300 requests
      a minute with no cookie. They need no account, and a request with no cookie writes no
      audit row once REFRESH_IP_FAIL is exhausted. Every co-located user whose access token
      expires during that time gets a 429 on refresh and is logged out. Behind the proxy, this
      logs out the whole platform. Before this diff the same attack took 30 requests a minute,
      so this is not a regression, only 10x more expensive. But RES-40 accepts "ceiling raised
      for successful refreshes", not an attacker-driven mass logout, and T-D24 rated the same
      shape at 30/min as Medium. OWASP A04 (Insecure Design), availability.
Fix: Choose one of these, record it in ADR-0022 D8, and amend RES-40 to name the lever with an
     owner:
     (a) Preferred, frontend: on a refresh 429, keep the session and retry after Retry-After
         while the access token is still valid. Clear the session only on 401. This also keeps
         a 503 AUTH_005-style outage from logging anyone out.
     (b) Backend: keep the filter bucket only as a coarse flood guard (raise it well above 300),
         and enforce the 300/60 s per-IP total in the use case for found tokens only. Failures
         are already bounded by REFRESH_IP_FAIL and sessions by REFRESH_FAMILY.
     In both cases, add a k6 case with the NAT attacker at 400/min, assert zero forced logouts
     (or the documented accepted outcome), and correct the filter Javadoc.
```

```
[MEDIUM] A detach whose post-commit holder read fails twice loses the revocation for every holder for up to token TTL + cache TTL; it is paged but never replayed (T-E38 gap)
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java:379-383, 551-576
      nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java:725-727
Issue: When both holder reads fail (M-2 fix), the method returns Optional.empty(), so
       invalidateHolders is never called. As a result:
       - no epoch is bumped, and nothing is added to the replay queue;
       - no cache entry is deleted. The holder's permset under the current epoch survives, and
         the role-name fingerprint in RoleResolutionService does not detect a detach, because
         the holder's role set is unchanged.
       The only response is bump_failed{reason=holder_read} (paged) and a manual re-apply from
       runbook §8. A-21(4) rejects a role-level replay because "the holders are unknown". But
       they are unknown only on the request thread: the scheduler could read them later, once
       the pool recovers.
Risk: Every holder keeps the detached permission until their access token expires (900 s), and
      each refresh in the next 900 s re-mints it from the stale cache. Exposure is about 30
      minutes, which is the exact T-E38 shape that RC-30 was written to close, and is not one
      of RES-31's listed residuals (restart, failover, overflow). The trigger is pool
      exhaustion or a DB timeout at commit. An external attacker cannot easily time this, but
      it is the likeliest failure during an incident, which is also when admins detach.
      OWASP A01, A04.
Fix: On the second failure, enqueue a role-level replay (tenantId, roleId, failedAt). The 1 s
     tick re-reads the holders in a read-only transaction and calls invalidateHolders. Drop the
     entry after key-ttl-seconds, and keep the page. Add a PermissionFreshnessService or
     RoleManagementService test: the holder read fails twice, the next tick succeeds, and
     every holder is bumped and their permset under the old epoch is deleted. Add
     bump_failed{reason=holder_read} to RES-31 if you keep the current behaviour instead.
```

```
[LOW] The bump script and the Java parser disagree on which epoch values are valid: NaN passes the Lua guard, and values from 2^53 to Long.MAX make the epoch go down or stop rising
File: nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java:59-64 (script guard), 103-113 (parse), 151 (Long.parseLong of the script result)
      docs/features/US-018/03-design.md:718 ("not a non-negative long below 2^53 is treated as 0")
Issue: Verified on redis-server 7.0.15 (see Verification run):
       - Lua 5.1 tonumber("nan") is NaN, and `NaN < 0 or NaN > 2^53` is false, so the guard
         keeps NaN. The script writes "nan" with a fresh TTL and returns "nan". Java's
         Long.parseLong throws NumberFormatException after the script has already written
         every key in the batch. invalidateHolders and drainReplayQueue therefore treat the
         whole batch of up to 500 users as failed and requeue it. Each 1 s tick then bumps all
         of them again: their epochs rise every second, the queue never drains, and the
         replay logs ERROR every tick, for key-ttl (960 s) after the newest failure.
       - Java accepts any value up to Long.MAX, and mints and checks against it, but the script
         resets anything above 2^53 to 0. A bump then writes the current time in ms, which is
         below tokens already minted with the large value, so those tokens stay FRESH after a
         revocation. A stored 2^53 never increases at all (2^53 + 1 rounds to 2^53), so bumps
         have no effect for that user.
       - The design text says such values are "treated as 0". That is true for the script only;
         the read path does not apply the same rule.
Risk: All of this requires Redis write access (T-T16), which already allows DEL and permset
      injection, so no new privilege is gained. But one corrupt key can:
      - lock out up to 500 users of a tenant for about 16 minutes (their tokens go stale every
        second);
      - keep a degraded instance from leaving DegradedClosed, because the exit requires an
        empty queue, so it serves 503 for that long;
      - make a user's tokens immune to revocation for their lifetime (900 s, the pre-A9 bound).
      OWASP A04, A08.
Fix: Define one valid epoch range, 0 <= e < 2^53 - 1, as a shared constant:
     - Script: `if old ~= old or old < 0 or old >= 9007199254740991 then old = 0 end`.
     - Java parse(): reject anything outside the range as unparseable.
     - bump(): parse each returned value separately. For a value that does not parse, record
       the lower bound for that user, and do not report the other users as failed. A batch
       the script applied must never be replayed.
     - Add adapter ITs for "nan", "-nan", "9007199254740992" and "9223372036854775807", and
       correct design §9.2.
```

```
[LOW] RBAC_EPOCH_UNPARSEABLE is logged at WARN once per request, with no rate limit and no metric of its own
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java:309-312, 358-363, 376-381
Issue: Every check and every mint that reads an unparseable value logs one WARN, from the
       request thread. The response loop doubles the volume: the check returns STALE, the
       client gets 401, refreshes, the mint logs again and mints 0 unverified, and the next
       request is STALE again. The forward requirement in 07-security-review-M7.md:95-97 asked
       for a fourth bounded outcome tag. It was not added: these requests count as
       outcome=stale, so they cannot be told apart from real revocations, and the
       stale > 5x baseline ticket will misfire. The other noisy paths in this diff are bounded:
       the refresh throttles allow one WARN per window, and replay errors are logged once per
       tick.
Risk: If the keyspace is corrupted, by Redis write access or by a foreign client writing under
      the same nexus.redis.key-prefix, every authenticated request logs one WARN. That floods
      the log pipeline (cost, and real WARNs get buried). It requires corrupted keys. OWASP A09.
Fix: Rate-limit the WARN with the WarnWindow pattern from RefreshTokenUseCase (one per window,
     with a count of the occurrences since the last one, and tenantId only). Add a counter
     nexus.rbac.epoch.unparseable (or the outcome tag value) with no tenant or user tag.
     Ticket it when it is above 0.
```

```
[LOW] The last-seen map takes users first come, first served, so one large detach can switch off the M-1 defence for every other tenant on the instance
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java:122, 571-583
Issue: Once 100,000 live entries exist, no new user is recorded until older entries expire,
       which can take up to key-ttl (960 s). Entries are created by bumps and by any successful
       read with an epoch above 0. A routine detach on a role with about 100k holders in one
       tenant fills the map on the instance that ran it, and the holders' later requests fill
       it on the others. For the rest of the TTL, a revoked user who is not already in the map
       gets the old SKIPPED_ERROR or SKIPPED_DEGRADED fail-open (the 07 review M-1 lever). The
       drop counter exists, but the alert table in 04-tasks.md:545 does not include
       last_seen_dropped.
Risk: A defence-in-depth control can be saturated by one tenant's admin action, at the moment it
      matters most. This only matters during an induced or real read failure, and exposure
      stays within the token-TTL bound (RES-30). OWASP A04.
Fix: Do one of the following:
     (a) Cap entries per tenant (for example 10% of capacity) so one tenant cannot crowd out the
         others.
     (b) Use a bounded cache with O(1) eviction of the soonest-expiring entry instead of
         refusing new ones.
     Also add `last_seen_dropped > 0` to the §9.9 ticket alerts.
```

---

## Focus areas

**Revocation acceptance paths (A01).** A revoked token is still accepted only in these cases:
1. One failed read while Healthy, for a user not in the last-seen map (SKIPPED_ERROR, by design, counted).
2. DegradedOpen, up to `fail-open-window` (15 min) from `t0`, for users not in the map (RES-30, Gate 1).
3. A full map (L-3).
4. A replay queue lost on restart, or bumps lost to an async Sentinel failover (RES-31).
5. A detach whose holder read failed (M-2 above).
6. Corrupt values in Redis (L-1, needs Redis write).

DegradedClosed returns UNAVAILABLE for every non-public request before it consults the map, which is stricter. `STALE` always wins over `SKIPPED_*` when the map knows a higher epoch. A failed bump records `seen + 1`, which cannot exceed the store, so it cannot reject a valid token. I re-derived H-2: `rememberBump` records exactly the value the script returned, so no instance clock enters it, and the minted epoch can never be above a later revoke.

**State machine (T-D20, T-E43, T-E47, RC-31, RC-41, RC-52, RC-53).**
- Every transition runs under one lock. The Healthy fast path reads the volatile `state` field only.
- Entry: 3 failures in a 10 s sliding window, with `t0` at the first failure in the window. A relapse from Recovering keeps `t0`, so a flapping Redis goes straight to DegradedClosed once the window has elapsed. `t0` is cleared only after 60 s of sustain measured after the drain (L-2 fixed).
- Only read and probe failures count. Unparseable values and bump or drain failures do not. A read while the adapter is not ready counts as a failure (`:365`), and the probe is gated on readiness. The 07 review's "not-ready window" requirement is met piece by piece (adapter `NotReadyTest` plus `should_returnSkippedError_when_portEmpty`). There is no end-to-end test of an instance started against an unreachable Redis.
- `@EnableScheduling` is unconditional (RC-52, `EpochSchedulingIndependenceTest`).
- The probe catches any `RuntimeException` (N-3).
- An authenticated attacker can still drive the instance into DegradedOpen (07 M-1). The A-18 map narrows this. Parts (b), the alert content and the per-instance request-rate panel, and (c), the k6 overload profile, are still open. They are tracked as the M7 docs pass and the T-009 k6 gate. I found no request-rate panel in the alert table (`04-tasks.md:545`): **add it** when the alerts land.

**Replay queue (T-E38, T-E44, RC-30, RC-42).**
- Coalescing keeps the oldest and newest failure time, and expiry compares the newest (M-1 fixed). The newest failure + 960 s is at least the life of any token minted before the last lost bump (900 s, skew 0).
- `requeue` ignores capacity, so a retry never drops a user. Overflow drops the newest arrivals, counted and paged.
- Batches are per tenant. A batch only ever bumps keys under its own `tenantId`.
- One gap: a script that applied its writes but returned a bad value causes perpetual re-bumps (L-1).
- An in-memory queue lost on restart stays RES-31.

**Unverified mint (L-3).** When the store did not confirm the epoch (degraded, or two failed reads), `mintEpoch` returns `verified=false`, and `JwtRs256Service` calls `resolveUncached`, which reads the DB only and neither reads nor writes the cache. An unparseable value mints 0, unverified. Both are correct. Permissions in an unverified-mint token always come from the DB after commit, so a lower epoch can only cause one extra 401 after recovery, never an over-grant.

**503 `AUTH_005` and the public exemption (T-D17, RC-44.4).**
- Only the non-public branch calls `check`.
- `filterPublic` never consults the freshness service, so refresh and logout work while degraded-closed (`TokenFreshnessIT.should_return200_when_refreshCarriesBearerWhileDegradedClosed`).
- The 503 body is the fixed RFC 9457 shape. `instance` and `traceId` are JSON-escaped (quote, backslash, control characters), and the content type is `application/problem+json`, so it cannot be used for injection.
- The security context is cleared before the response is written.
- The SPA does not clear the session on a 503.

**Refresh tokens (T-D19, T-D24, T-E46, RC-32, RC-43, RC-51).**
- Order of checks:
  1. hash
  2. lookup
  3. the reuse branch (`revokeFamily`; if it revoked at least one token, a `TOKEN_REFRESH_REUSE` row and 401, with no bucket consulted)
  4. the family bucket
  5. expiry
  6. rotation under optimistic lock
- Reuse detection therefore cannot be suppressed (RC-51).
- The revoked count comes from the committed `REQUIRES_NEW` UPDATE and is never logged or returned.
- A replay that revoked nothing goes through `REFRESH_IP_FAIL`. 429 versus 401 after a family revocation therefore depends only on that bucket. Either way the session is already gone, and no path turns a reuse into a 429 (A-20(5); the k6 gate accepts 401 or 429 for the successor, never 200).
- The family bucket is keyed by SHA-256 of a DB-derived `familyId`. Only someone holding a valid, unrevoked token of that family can consume it, so a stranger cannot exhaust a victim's family bucket.
- Every use-case rejection throws `RefreshThrottledException`. The handler logs it at DEBUG, and the use case emits one WARN per window with `rejectedCount` only, with no IP and no family id, and has its own counters (`refresh_failure_throttled`, `refresh_family_throttled`).
- The audit volume of failures is bounded by `REFRESH_IP_FAIL`, consumed before the write (RC-43; `RefreshFailureThrottleIT` green).
- On the shared-NAT observation from the code review: see the Medium above. It is real, it is not covered by RES-40 as worded, and it is cheaper than it looks because the SPA treats a 429 as a logout.

**Redis authentication (T-T16, RC-34, RC-45).**
- The assertion inspects each factory's effective `RedisStandaloneConfiguration` or `RedisSentinelConfiguration`. That covers URL userinfo (`should_start_when_passwordSuppliedOnlyThroughRedissUrl`), whitespace-only passwords, username without password, and the Sentinel data-node and sentinel passwords.
- It runs before any connection is attempted.
- Messages name the factory and the properties to set, never a value (`should_notIncludeCredentialValues_when_failureMessageBuilt`).
- `AuthenticatedRedisIT` runs the epoch path against a Redis that requires auth.
- It is inert in prod until the High is fixed. TLS is still not asserted, which is acceptable under RC-34 (TLS where Redis is not on a private network is an ops prerequisite).

**Tenant isolation (A01).**
- Every epoch, roleset and permset key is `{prefix}:rbac:{kind}:{tenantId}:{userId}[:{epoch}]`. It is built only from typed `UUID`s that come from the verified token, from `actor.tenantId()`, or from a tenant-resolved role. The epoch is a `long`.
- No request string reaches a key or a script. Scripts receive keys through `KEYS` and stems through `ARGV`, and only append a number they formatted themselves, so neither key injection nor script injection is possible.
- `RbacRedisKeys` is the only place key shapes are defined.
- The holder query `JpaUserRoleRepository#findActiveUserIdsByRole` is still on `UNSCOPED_ALLOWLIST` (grandfathered, not added here). The role is tenant-resolved (404/403) and mutable-checked (409) before the query runs, and the bumps use `actor.tenantId()`. Because this query now feeds a revocation path, adding `ur.tenantId = :tenantId` would make an inconsistent cross-tenant `user_roles` row a no-op instead of a silently missed holder. Hygiene only, not a finding.
- `TenantIsolationArchitectureTest` passes. The allowlist is unchanged, so no sign-off is needed.

**Logs, PII and metrics (A09).**
- New log lines carry event, operation, tenantId, roleId, userCount or holderCount, instance (`HOSTNAME`), exception class and ages. They never carry a user id, IP, family id, token or epoch value.
- `RBAC_HOLDER_READ_FAILED` carries tenantId and roleId: opaque ids, not PII.
- Metric tags are bounded:
  - `outcome` has 5 values;
  - `state` has 3;
  - `holders` buckets have 5;
  - `operation` takes constants from callers (`revoke`, `detach`, `replay`, ...), and `reason` has 3 values.
- No tenant or user tag.
- Pre-existing, unchanged: the `TOKEN_REFRESH_SUCCESS userId` DEBUG line, and IPs in `auth_events` rows (audit by design).
- Carried over from 07 (Low, platform baseline): `/actuator/prometheus` is readable by any authenticated user. This diff adds `nexus.rbac.epoch.degraded{state}` and `replay_queue_users` to it, which makes timing a revoked token against DegradedOpen easier. Restricting the scrape is now more valuable.

**Detach fan-out resources (T-D23, accepted).**
- Holders are loaded in full: one `List<UUID>` read in a separate read-only transaction.
- They are bumped in sequential batches of 500 on the request thread, in `afterCommit`. The committed transaction's connection stays bound until `afterCompletion`, plus one connection briefly for the holder read.
- A down Redis costs one bump timeout (the first failed batch ends the fan-out, and the rest is queued). A slow but working Redis costs up to 500 ms per batch.
- This is admin-only, and an admin can run several large detaches at once, so pool pressure needs watching. It is covered by the `RBAC_EPOCH_FANOUT_LARGE` WARN and the fan-out buckets. No change requested beyond T-D23.

---

## Forward requirements from `07-security-review-M7.md`

| Item | Status |
|---|---|
| M-1 (a) last-seen map | **Done** (A-18). Saturable: see L-3 |
| M-1 (b) `skipped_error` page and a request-rate panel | Page specified in ADR-0022 and the §9.9 table. **The request-rate panel is not listed. Open** (M7 docs pass) |
| M-1 (c) k6 overload profile | **Open** (deferred to the T-009 k6 gate, A-18) |
| Low, unparseable epoch (`:83-98`) | STALE for that user ✓; WARN with tenantId only ✓; excluded from the window ✓; adapter tests for `"abc"` and `"9223372036854775808"` ✓ (`RedisPermissionEpochAdapterIT:204`); **fourth outcome tag ✗**; no rate limit on the WARN (L-2); script guard incomplete (L-1) |
| Low, not-ready window | Done (counted as a read failure, probe gated on readiness, not-ready bump queued). No end-to-end start-unreachable test |
| Low, MDC userId | Unchanged; M11 |
| Low, `/actuator/prometheus` | Unchanged; more valuable to fix now (see above) |
| Low, T-014 checks effective credentials | **Done**, including the `rediss://` userinfo test |

## Threat-model cross-reference (`03b-threat-model.md`)

| Threat / RC | Status in model | Mitigation visible in this diff |
|---|---|---|
| T-T16 / RC-34.1, RC-45.1, RC-45.2 | required | **Code yes, prod config no** (High). `RedisAuthStartupAssertion`, `AuthenticatedRedisIT` |
| T-E37 / RC-29.3 key-expiry race | required | **Yes**, `TokenFreshnessIT.should_notMintRevokedPermission_when_firstBumpRaceOutlivedByEpochKey` |
| M7 **S** epoch-keyed cache (Decision 17) | ✅ | **Yes**, `RbacRedisKeys`, the bump script deletes the sets under the old epoch, `should_notServeStaleSetAfterRefresh_when_mintRacesDetach` |
| T-D23 fan-out unbounded | ✅ accepted | Consistent: no cap, buckets, large-fan-out WARN, first failure ends the fan-out |
| T-E38 / RC-30, T-E44 / RC-42 replay | required | **Yes**, `EpochReplayQueue`, a drain on every tick, `should_replayWithinTwoSeconds_when_singleBumpFailsAndInstanceStaysHealthy`, `should_replayLostBumpAndRejectOldToken_when_redisRecoversAfterBeingPaused`. **Gap: the holder-read path (Medium)** |
| T-D20 / RC-31, T-E43 / RC-41, T-E47 / RC-53, RC-52 | required | **Yes** (state machine above; 127 `PermissionFreshnessServiceTest` cases) |
| T-D17 degraded half / RC-44.4 503 | required | **Yes**, `should_return503Auth005_when_staleEpochBearerOnNonPublicHandlerWhileDegradedClosed` |
| T-D19 / RC-32, T-D24 / RC-43 | required | **Yes** as specified (family bucket in the use case, failure bucket before the audit write). RC-32.3 and RC-43.3 k6 gates not run. **The NAT lever above 300/min is not covered (Medium)** |
| T-E46 / RC-51 reuse first | required | **Yes**, `RefreshTokenUseCase:166-178`, `RefreshTokenIT`, `RefreshTokenUseCaseTest` |
| RES-40 | Low, accepted | Accepted as worded; **needs an amendment** for the junk-exhausts-total lever |
| RES-31 | Low, accepted | Consistent; holder-read loss is **not** a listed residual (Medium) |
| RES-32 | Low after RC-34 and RC-45 | **Not yet**: depends on the High |

## OWASP Top 10 checklist (SECURITY.md §12)

- **A01 Broken Access Control:** Pass, with 1 Medium (holder-read revocation loss) and 1 Low (map saturation). Tenant ids only come from the token or a tenant-resolved role, and default-deny is intact.
- **A02 Cryptographic Failures:** Pass. SHA-256 is used only to keep a non-secret id out of keys. No change to algorithms, keys or randomness.
- **A03 Injection:** Pass. The scripts are static, and keys and arguments are parameterised from typed UUIDs and longs. The 503 body is JSON-escaped.
- **A04 Insecure Design:** 1 Medium (NAT refresh logout) and 2 Lows (epoch range mismatch, map saturation).
- **A05 Security Misconfiguration:** **1 High** (`require-auth` missing from the prod profile).
- **A06 Vulnerable Components:** **Not verified.** dependency-check is blocked by CISA KEV 403. No backend dependency changed. npm audit shows 1 high and 6 moderate, all pre-existing in `@angular/*`, and the frontend is unchanged.
- **A07 Identification & Authentication Failures:** Pass. Reuse detection cannot be suppressed by any bucket, the family bucket cannot be exhausted by a stranger, and stale tokens get 401.
- **A08 Software & Data Integrity Failures:** Pass, with the L-1 parsing gap (needs Redis write).
- **A09 Security Logging & Monitoring Failures:** 1 Low (an unbounded WARN, and no unparseable metric). No user id, IP or family id in any new log line or tag.
- **A10 SSRF:** Not applicable.

## Summary

| Severity | Count | Findings |
|---|---|---|
| Blocker | 0 | |
| High | 1 | H-1 `require-auth` not set in `application-prod.yml`; prod-profile test `@Disabled` |
| Medium | 2 | M-1 junk refreshes exhaust `REFRESH_IP` and the SPA logs out on 429 (NAT, or platform-wide behind the proxy); M-2 a failed detach holder read is never replayed |
| Low | 3 | L-1 Lua guard vs Java parser (NaN, ≥ 2^53); L-2 unbounded `RBAC_EPOCH_UNPARSEABLE` WARN, no metric; L-3 last-seen map saturable first come, first served |

**Verdict: BLOCKED** until H-1 is fixed (one human config edit plus re-enabling one test). M-1 and M-2 must be fixed or explicitly accepted with an owner before the M7 PR merges. L-1 to L-3 can be ticketed.

## Residual risk

- **RES-30 (Medium, Gate 1):** time-boxed fail-open of up to 15 min per instance, now with the last-seen narrowing. The attacker-induced lever from 07 M-1 is still open until the k6 overload profile and alerts land.
- **RES-31:** replay lost on restart or Sentinel failover; overflow.
- **RES-32:** Redis write access equals authorization, Low only after H-1.
- **RES-40:** as worded, plus the M-1 lever until it is fixed or accepted.
- **Pending:** A06 (CI dependency-check), the k6 storm gate and the NAT gate in the production ingress topology for both deployment shapes, and the k6 hot-path gate in staging.

## Relevant files

- `nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/EpochReplayQueue.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java` (lines 379-383, 551-576)
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RbacRedisKeys.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisAuthStartupAssertion.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/LoginRateLimitFilter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/service/RefreshTokenUseCase.java`
- `nexus-backend/src/main/resources/application.yml` (lines 164-179, 230-232), `application-prod.yml`
- `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/cache/RedisAuthStartupAssertionTest.java` (line 254)
- `nexus-frontend/src/app/core/http/auth.interceptor.ts` (lines 112-113, 150-151)
- `nexus-test/performance-test/scenarios/detach-refresh-storm.js`, `config/environment.js` (line 98)
- `docs/features/US-018/03b-threat-model.md` (T-E38 362, T-D19 378, T-T16 395, RC-30 607, RC-41 to RC-45 1002-1042, T-E46 1154, RES-40 1190/1334)

---

## Resolution

Recorded 2026-10-09 on `ccr-4e9e7cbe-4vl9v6`. Design decisions are A-22 in `04-tasks.md`.

| Finding | Status | What changed | Where documented |
|---|---|---|---|
| H-1 `require-auth` not set in `application-prod.yml`, test `@Disabled` | **Open, human action** | Untouched on purpose: a human edits `application-prod.yml` and removes `@Disabled` from `RedisAuthStartupAssertionTest.should_resolveRequireAuthTrue_when_prodProfileActive`. Still blocks the merge | `04-tasks.md` merge checklist (H-3) |
| M-1 junk refreshes exhaust `REFRESH_IP`, SPA logs out on 429 | **Fixed (decision a) and accepted** | Frontend keeps the session and retries after `Retry-After` on a refresh 429 (separate commit). `LoginRateLimitFilter` Javadoc corrected. RES-40, design §9.7, ADR-0022 D8 and A-20 state that invalid refreshes consume `REFRESH_IP`. New k6 case `refresh-junk-flood.js` (400 junk/min, valid users get 200 or 429 with a valid `Retry-After`, never 401, recover after the flood). **The k6 case has not been run** (no dev stack); `k6 inspect` and prettier pass | `03b-threat-model.md` RES-40, `03-design.md` §9.7, ADR-0022 D8, `04-tasks.md` A-20 (7), A-22 (2) and merge checklist, nexus-test README |
| M-2 failed detach holder read never replayed | **Fixed** | `RoleReplayQueue` (tenant, role, failedAt; bounded, coalesced, same TTL rule); the 1 s tick re-reads the holders (1 s timeout, own thread) and bumps them through `invalidateHolders`; paging counter kept; new `role_replayed`, `role_replay_queue_roles`, `bump_failed{role_overflow}` and `{operation=role_replay}` | design §9.3, ADR-0022 D3, RES-31, runbook §8, `monitoring.md` §6, A-22 (1) |
| L-1 Lua guard vs Java parser | **Fixed** | One range: 1 to 16 ASCII digits and at most `2^53 - 2`. Script rejects `nan`, `inf`, hex, exponent forms, signs and everything at or above `2^53 - 1`, and never writes a value Java rejects; Java rejects the same set. A bad value in a script result omits only that user. Verified against `redis:7.4-alpine` (IT) and a local `redis-server` 7.0.15 | design §9.2, runbook §8 (script updated), A-22 (3) |
| L-2 unbounded `RBAC_EPOCH_UNPARSEABLE` WARN, no metric | **Fixed** | WARN once per tenant per minute with `suppressed`; `epoch.check{outcome=unparseable}` | design §9.2 and §9.9, `monitoring.md` §6, runbook §8, A-22 (4) |
| L-3 last-seen map saturable | **Fixed** | Per-tenant cap on read-derived entries (`last-seen-tenant-percent`, 10), own-bump entries in a separate pool bounded per tenant and globally (a dropped own bump fails its tenant closed while the store is unavailable), `last_seen_dropped{reason=tenant_cap,capacity,bump_dropped}`, slot accounting released only on real removal | design §9.2 and §9.9, runbook §8, `monitoring.md` §6, merge checklist, A-22 (5) |
| Hygiene: tenant predicate on `findActiveUserIdsByRole` | **Not done, follow-up** | Needs an allowlist change in `TenantIsolationArchitectureTest` and a port signature change | A-22 (6) |
| Forward item: request-rate panel (07 M-1 b) | Listed in the alert content | Added to the merge-checklist alert list and `monitoring.md` §6; the panel itself is built with the alerts | `04-tasks.md`, `monitoring.md` |
