# Security Review (pre-PR): US-018 M7 part 2 (A9 per-user permission epoch, T-009 to T-014)

**Verdict as issued (HEAD `bdea089`): BLOCKED** for merge. The code had **no Blocker and no High**. Two things blocked the merge:
- **The open human item.** `application-prod.yml` did not set `nexus.rbac.redis.require-auth: true`, and `RedisAuthStartupAssertionTest.should_resolveRequireAuthTrue_when_prodProfileActive` was `@Disabled`. (`nexus.rbac.throttle.require-shared-store` was named too, but RC-45 sets it with M8.)
- **M-1** had to be fixed, or accepted with a named owner, following the convention of `10-security-review-M7-part2.md`.

**Status after the fixes (2026-10-09): both blockers are addressed, and the verdict has not been re-issued.**
- `require-auth: true` is in `application-prod.yml` and the test is enabled and passing (`0ec0ec1`).
- M-1 is fixed (`07b7626`) and L-1 to L-6 are resolved or recorded (`a14d789`); see the two Resolution sections below.
- **Not re-reviewed.** The reviewer has not re-checked any of this, and the ITs, e2e and k6 gates have not been run since (no Docker). Re-run `/security-review` and update this line to APPROVED only on that result.
- Two automated commit reviews raised MEDIUM points on the Low fixes: the strict per-tenant replay share (L-2), and whether the actuator matcher covers `/actuator/prometheus/` with a trailing slash (L-3). Neither is resolved yet.

**Scope:** `git diff origin/main...HEAD` on `ccr-4e9e7cbe-4vl9v6` at HEAD `bdea089` (102 files, +14415/-404).
- **Priority:** the commits made after `10-security-review-M7-part2.md`: `19f85a3`, `340c406`, `e443a44`, `e4dd1a2`, `ecfb9b2`, `9ccc890`, `f5dc670`, and the test-audit commits `46a55e0` to `4dd7060`.
- **Method:** every resolution in the prior reviews was re-derived from the code, not taken from their Resolution tables.
- **Read-only:** no application code, test or config file was modified, staged or committed. This file is the only file written.

**Auth, authorization, crypto and PII handling were reviewed explicitly.**
- **Authentication and freshness:** `JwtAuthenticationFilter`, `JwtRs256Service` (the `perm_epoch` mint and verify), `PermissionFreshnessService`, `RefreshTokenUseCase`, `LoginRateLimitFilter`, `PublicEndpointRequestMatcher`, `SecurityConfig`, and the SPA `auth.interceptor.ts`.
- **Authorization and tenant isolation:** `RoleManagementService`, `RoleAssignmentService`, `RoleResolutionService`, `RbacRedisKeys`, both Lua scripts, and the holder query.
- **Crypto:** SHA-256 of the family id (a key-hiding hash, not a MAC). No algorithm, key or randomness change.
- **Credentials:** `RedisAuthStartupAssertion`, `EpochRedisConfig` (TLS and credential propagation), `application*.yml`, and the k6 scripts.
- **PII:** every new log line, metric tag and audit field.

---

## Verification run

| Check | Result |
|---|---|
| Targeted unit tests, offline (`sh ./mvnw -o test`, with jacoco, spotbugs and checkstyle skipped): `PermissionFreshnessServiceTest` (194), `EpochReplayQueueTest` (23), `RoleReplayQueueTest` (15), `RefreshTokenUseCaseTest` (37), `JwtAuthenticationFilterTest` (19), `RedisAuthStartupAssertionTest` (20), `LoginRateLimitFilterTest` (18), `RbacRedisKeysTest` (4), `RedisPermissionEpochAdapterBumpResultTest` (3), `TenantIsolationArchitectureTest` (1) | **334 run, 0 failures, 0 errors, 1 skipped.** The skip is the `@Disabled` prod-profile test (open item). |
| ITs (`TokenFreshnessIT`, `RedisPermissionEpochAdapterIT`, `AuthenticatedRedisIT`, ...) | Not re-run in this pass. Their results are recorded in `11-test-audit-M7-part2.md`. |
| `npm audit --omit=dev --audit-level=high` (`nexus-frontend`) | **Exit 1: 7 vulnerabilities (6 moderate, 1 high), all in `@angular/*` 22.0.x.** The high is `@angular/router` GHSA-ff3f-86qr-9cv3. The moderates include `@angular/core`/`@angular/compiler` GHSA-hh8m-fm6v-7cvg and `@angular/common` GHSA-p297-fm68-3q8c. The fix is in 22.1.x/22.2.x. I re-ran it and got the same result. **Pre-existing:** `git diff origin/main...HEAD` shows no change to `nexus-frontend/package.json` or `package-lock.json`. The only manifest change on the branch is three k6 `scripts` entries in `nexus-test/performance-test/package.json`, which add no dependency. SECURITY.md §11 makes this CI gate fail regardless of this branch, so track it separately. |
| `./mvnw -Psecurity dependency-check:check` | **Not run.** Maven is offline and the CISA KEV feed returns 403 in this sandbox. Left to CI. No `pom.xml` changes on the branch. |
| k6 gates (`detach-refresh-storm`, `refresh-junk-flood`, `epoch-check-latency`, overload profile) | Not run (no stack). They remain open merge-checklist items. |

---

## Resolution of M-1 (after this review)

M-1 is fixed in `PermissionFreshnessService` (not re-reviewed by the reviewer; re-run `/security-review` to confirm):
- **(a)** In Healthy and Recovering, `check()` compares the token with the larger of the store value and the locally known epoch. It does not consult `revocationLost()` on that path, because the store answered, and failing a whole tenant closed for one key TTL on a healthy store costs more than it buys.
- **(b)** `mintEpoch()` returns the larger of the two, `verified=false`, when the store reads below the local bound or a failed bump is unreplayed, so the permission set is resolved uncached.
- **(c)** A failed bump records the failure instant on the user's entry. `check(tenant, user, epoch, iat)` treats a token issued at or before that second as stale until a replay or a read at or above that instant clears it. `JwtAuthenticationFilter` now passes `iat`; the three-argument `check` passes `Long.MAX_VALUE`, which never matches. A token issued in the failure's own second is refused once and refreshed.
- **(d)** `nexus.rbac.epoch.store_regressed` (no tags) is documented in `monitoring.md` as a page.
- **Tests:** six in `PermissionFreshnessServiceTest` (bump fails while reads succeed; unverified mint; key loss for a seen user; unseen user by `iat`; marker cleared by replay; unknown `iat`).
- **Residual:** the marker clears on an epoch at or above the failure instant, so a Redis clock behind the app clock keeps it until the key TTL; this only keeps the mint uncached.
- **`require-shared-store`:** the open item above overstates it. RC-45 sets it with M8, when the property is introduced. `require-auth: true` is now in `application-prod.yml` and the prod-profile test is enabled.

---

## Resolution of L-1 to L-6 (after this review)

Not re-reviewed by the reviewer; re-run `/security-review` to confirm.

| Low | Resolution |
|---|---|
| **L-1** | **Partly as proposed.** The global arithmetic (10 tenants fill the read pool, 5 the own-bump pool) is recorded in RES-31, and `last_seen_dropped{reason=capacity}` now pages (`monitoring.md`); `tenant_cap` stays a ticket. **Not adopted:** failing a tenant closed when a read-derived entry is refused. The read pool is full on any busy instance, so that would turn the fail-open grace into constant 401 loops. The eviction alternative is not built. |
| **L-2** | Both queues take a per-tenant share, `last-seen-tenant-percent` (default 10%) of each capacity: 10,000 users and 100 roles. A tenant over its share overflows itself and pages. **Tradeoff:** one tenant's fan-out above 10,000 holders during an outage now overflows at that point, not at 100,000. Tests in `EpochReplayQueueTest`, `RoleReplayQueueTest` and `PermissionFreshnessServiceTest`. |
| **L-3** | `/actuator/metrics/**` and `/actuator/prometheus` now require `ROLE_TENANT_ADMIN` (`SecurityConfig`), not just authentication. The k6 scrapes already use an admin token. **Open:** `TENANT_ADMIN` is tenant-scoped, so a tenant admin can still read the instance's metrics. A scrape network or a platform permission would close that, and is a deployment or product decision. |
| **L-4** | `utils/write-scenario.js`: both write scenarios refuse to start unless `BASE_URL` is loopback or a compose host (or `ALLOW_WRITE_SCENARIO=true`), generate the password per run (`k6/crypto`), and `seedStorm` revokes its assignments when setup aborts. README updated. Checked with `k6 run` against four URLs and `k6 inspect`; not run against a stack. |
| **L-5** | `isApiRequest` compares whole path segments. Specs for `/apiary/x`, `/api-docs`, `/api.v2/users`, and for the base path itself. |
| **L-6** | `server.forward-headers-strategy: none` is set in `application.yml` (all profiles), keeping T-1.3 and DF-1. `native` was the first assumption, but it is only safe with `server.tomcat.remoteip.internal-proxies` pinned to the ingress, which needs the real CIDR. Not in `application-prod.yml`, which is guarded. |

---

## Findings

```
[MEDIUM] M-1 (new; not raised in 10; the root cause predates the fix rounds)
The Healthy/Recovering check trusts a store epoch that is lower than one this instance knows,
so a revocation whose bump Redis refused is not enforced while Redis still answers reads
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java:497-515
        (Healthy/Recovering verdict: tokenEpoch < current only)
      PermissionFreshnessService.java:442-448 (mintEpoch: the verified store value; the local bound is ignored)
      PermissionFreshnessService.java:546-553, 915-925 (the local lower bound is consulted only on the unverified path)
Issue: When a bump fails, rememberFailedBump records seen+1 and the user is queued for replay. But
       the local map is read only when the store cannot answer or the instance is degraded-open.
       In Healthy and Recovering, the verdict compares the token with the store value alone.
       Several failure modes refuse or lose the write while GET keeps working, so the read
       path stays Healthy. These include:
       - maxmemory reached under the mandated `noeviction` policy (ADR-0016). Redis then refuses
         EVAL of a writing script with -OOM but still serves GET.
       - a bump timeout (500 ms) on a slow but answering Redis;
       - a key lost to async replication at a Sentinel failover, or a FLUSH, where the read
         returns 0, below what the instance saw.
       In each of these:
       - the revoked token, carrying the old epoch, is FRESH on every request;
       - a refresh mints a verified epoch equal to the old one;
       - for a detach, the epoch-keyed permset under the old epoch was never deleted (the
         script did not run), so the refresh re-mints the detached permission from cache.
       The replay retries every second, but a bump failure never moves the state machine
       (RC-53). With a persistent write refusal, the revocation is therefore unenforced until
       the cached permset expires and the last token minted from it expires (up to about cache
       TTL plus token TTL, roughly 30 min), and the replay entry drops after 960 s. The tests
       cover the lower bound only with failing reads
       (should_recordSeenPlusOne_when_bumpFailsForSeenUser and its neighbours). No test
       covers "bump fails, read succeeds".
       For a user the instance has not seen, the lower bound is 1, so it cannot stop a real
       token in any state, because real epochs are Redis-time milliseconds.
Risk: A revoked or detached user keeps the removed permission for tens of minutes, with every
      instance reporting Healthy. That is the T-E38 shape that RC-30 and RC-42 were written to
      close. The trigger is a Redis failure mode, not direct attacker action. But `noeviction`
      OOM is the designed failure mode for this Redis, and an insider who knows a revocation is
      coming benefits. Paged only through bump_failed. OWASP A01, A04.
Fix: Treat "store below what this instance knows" as a store regression, not as truth:
     (a) In evaluate() for Healthy and Recovering, compare against max(current, lastSeen for the
         key, if not expired). For an own-bump entry, also check revocationLost().
     (b) In mintEpoch(), when lastSeen is above the read value, mint with lastSeen and return
         verified=false, so the permset comes from resolveUncached and the minted token is not
         stale against (a). This keeps legitimate users out of a 401 loop. It is safe because
         the store always writes max(old+1, now) ≥ seen+1 when the replay lands.
     (c) Cover unseen users with a time marker instead of seen+1: record the bump-failure
         instant per (tenant, user) in the own-bump pool, and treat a token whose `iat` is
         at or before it as stale until the replay succeeds.
     (d) Count nexus.rbac.epoch.store_regressed (no tenant or user tag) and add it to the
         §9.9 page list.
     Tests:
     - the bump fails while reads succeed, and the old token is STALE in Healthy;
     - a refresh mints an unverified token without the detached permission;
     - store value 0 after a key loss for a seen user.
```

```
[LOW] L-1 (new: residual of the L-3 fix in 9ccc890 / f5dc670)
The global bounds of both last-seen pools are still shared, so a few large tenants can disable
M-1 for every other tenant (read pool, fail-open direction) or push every bumping tenant, and then
the whole instance, into fail-closed (bump pool)
File: PermissionFreshnessService.java:162-174 (LAST_SEEN_CAPACITY 100,000; per-tenant 10%;
      bump ceiling 4x; bump global 200,000; LOST_TENANTS_MAX 1,000)
      PermissionFreshnessService.java:820-844 (claim), 798-817 (markRevocationLost / revocationLost)
      nexus-backend/src/main/resources/application.yml:181
Issue: The per-tenant caps stop one tenant, but each global bound is only 10 (reads) or 5
       (bumps) tenants deep:
       - **Read pool.** Ten tenants, each with 10,000 users bumped within the key TTL and
         active on this instance, fill the 100,000 read slots. From then on, no other tenant's
         read-derived epoch is recorded. These are the entries that carry other instances'
         revocations to this one. A dropped read is only counted (`capacity`). Unlike a
         dropped own bump, it does not fail the tenant closed, so this is the fail-open
         direction.
       - **Bump pool.** Five tenants at their 40,000 ceiling fill the 200,000 own-bump slots.
         Every other tenant's next own bump is then refused and marks that tenant lost. Past
         1,000 marked tenants, `lostAllUntil` fails every tenant on the instance closed for
         960 s, which is a 401 loop during any outage. This is fail-safe but cross-tenant.
       Both require tenant-admin actions over tens of thousands of users, so they are not
       reachable by an unauthenticated or low-privilege caller. The checks are O(1) and no
       request path scans, so there is no request-path DoS. Slots are released only after
       remove(k, v) succeeds, which I confirmed at :727 and :860.
Risk: During a real or induced read outage, revoked tokens of unrelated tenants are accepted
      (read pool), or unrelated tenants lose the fail-open grace (bump pool). OWASP A04, A01.
Fix: Treat a refused read-derived entry like a refused own bump: mark the tenant lost (fail
     closed while unverified). Alternatively, evict the soonest-expiring entry of the largest
     tenant instead of refusing the newcomer. Page on last_seen_dropped{reason=capacity}, not
     only bump_dropped. Record the global-fill arithmetic (10 and 5 tenants) in RES-31 or RES-30.
```

```
[LOW] L-2 (EpochReplayQueue carried over and not raised before; RoleReplayQueue new in e443a44)
Both replay queues are global first-come-first-served with no per-tenant share, so one
tenant's failed fan-out during an outage drops other tenants' revocations
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/EpochReplayQueue.java:61-79
      nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleReplayQueue.java:52-64
      nexus-backend/src/main/resources/application.yml:174, 178
Issue: replay-capacity-users (100,000) and replay-capacity-roles (1,000) are shared by all
       tenants. Both queues drop the newest arrivals once full:
       - A detach on a role with about 100k holders during a Redis outage fills the user queue.
       - Two tenant admins detaching from their 500-role maximum during a DB pool outage fill
         the role queue.
       In either case, every other tenant's revocation in that window becomes `overflow` or
       `role_overflow`, paged, with a manual re-apply. After Redis recovers, a dropped user's
       old token is FRESH again. The local seen+1 helps only while the store is unverified,
       and see M-1. Cross-tenant replay itself is not possible: batches are per tenant, keys
       are built from the queued tenantId, and the role re-read bumps under the queued
       tenant. Memory is bounded: requeue may exceed capacity by one batch or one role. Logs
       carry tenantId, roleId and counts only.
Risk: Lost revocations for tenants that did nothing unusual, bounded by token TTL plus cache
      TTL. OWASP A04.
Fix: Reserve a per-tenant share in both queues, mirroring last-seen-tenant-percent. A tenant
     over its share overflows itself, not others. Name the cross-tenant case in RES-31.
```

```
[LOW] L-3 (carried over from 07 and 10; more valuable now)
/actuator/prometheus is readable by any authenticated user and now publishes the instance's
degraded state and drop counters
File: nexus-backend/src/main/resources/application.yml:79-83 (exposure: health,info,metrics,prometheus)
      PermissionFreshnessService.java:334-341 (nexus.rbac.epoch.degraded{state}), 348-356 (last_seen_dropped)
Issue: A low-privilege user can poll nexus.rbac.epoch.degraded{state="degraded_open"},
       replay_queue_users, and last_seen_dropped{reason=...} to learn exactly when an instance
       accepts SKIPPED_DEGRADED, and whether the M-1 map is saturated. They then present a
       revoked token, obtained earlier, through the same connection.
Risk: It makes the RES-30 fail-open window precisely timeable. OWASP A01, A05.
Fix: Restrict metrics and prometheus to a scrape network, or to a dedicated permission, in
     SecurityConfig.
```

```
[LOW] L-4 (new in refresh-junk-flood.js (ecfb9b2); same pattern carried over in detach-refresh-storm.js)
k6 write-path scenarios register accounts with a hard-coded password and cannot delete them
File: nexus-test/performance-test/scenarios/refresh-junk-flood.js:26
      nexus-test/performance-test/scenarios/detach-refresh-storm.js:36
Issue: The scenarios register synthetic @example.com accounts with a static, committed
       password. Teardown only revokes role assignments: no user-delete API exists, and teardown
       does not run when setup() fails after an assignment. The README says to run only
       against a disposable database. Nothing enforces that, and RC-32.3 asks for a run
       "through the production ingress".
Risk: If someone runs a scenario against a shared environment, it leaves verified accounts that
      anyone with repository read access can log into. Some still hold `role:read`/`user:read`
      if setup aborted. OWASP A07.
Fix: Generate the password per run (crypto.randomBytes, or an env var with no default). Refuse
     to start unless BASE_URL is a loopback/compose host or an explicit
     ALLOW_WRITE_SCENARIO=true is set. In seedStorm, revoke assignments in a try/finally when
     setup aborts.
```

```
[LOW] L-5 (carried over; pre-existing code, not changed on this branch)
SPA isApiRequest uses a raw prefix, so the bearer goes to any same-origin path beginning "/api"
File: nexus-frontend/src/app/core/http/auth.interceptor.ts:88-92
Issue: target.pathname.startsWith('/api') also matches '/apiary', '/api-docs', '/api.v2' and so
       on. The origin check is strict, so the bearer never reaches another origin. Absolute
       and protocol-relative URLs to third parties are refused (4dd7060 tests this).
Risk: Only matters if the SPA origin routes a sibling prefix to another service (a docs host,
      a static bucket, a future gateway route) whose logs then capture the access token. Low
      today: springdoc is disabled in prod. OWASP A01 or A05.
Fix: `p === base || p.startsWith(base.endsWith('/') ? base : base + '/')`, with a spec for
     '/apiary'.
```

```
[LOW] L-6 (carried over; configuration, platform-level)
The "getRemoteAddr only, never X-Forwarded-For" guarantee (T-1.3) depends on Spring Boot's
forward-headers default, which turns itself on under Kubernetes
File: nexus-backend/src/main/resources/application.yml (server.forward-headers-strategy absent)
      nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/LoginRateLimitFilter.java:119-120
      RefreshTokenUseCase.java:244 (REFRESH_IP_FAIL:{ip})
Issue: With the property unset, Spring Boot defaults it to NATIVE when it detects Kubernetes,
       Cloud Foundry or Heroku. Tomcat's RemoteIpValve then rewrites getRemoteAddr() from
       X-Forwarded-For for peers in the private ranges. The code never reads XFF itself, so
       there is no spoofing today, and the code is unaffected. But the effective key source
       of REFRESH_IP, REFRESH_IP_FAIL and the login buckets then depends on the ingress:
       - If the ingress appends the client IP, the buckets become per client, which
         contradicts DF-1's "platform-wide behind a proxy".
       - If the ingress passes the header through unmodified, an unauthenticated client can
         rotate XFF values. That gives a fresh REFRESH_IP_FAIL and login IP bucket per
         request, and a high key cardinality in the rate-limit store.
Risk: A brute-force or junk-refresh limit bypass, and a store-memory lever, decided by
      deployment rather than code. OWASP A05, A07.
Fix: For the human editing application-prod.yml (same open item): set
     `server.forward-headers-strategy` explicitly. Use `none` to keep the T-1.3 and DF-1
     semantics, or `native` with `server.tomcat.remoteip.internal-proxies` pinned to the
     ingress CIDR. Record which one in DF-1.
```

### Informational (no action needed for merge)

- **`findActiveUserIdsByRole` has no tenant predicate.** The holder query is `JpaUserRoleRepository.java:308-309`, carried over (A-22(6)). I assessed exploitability as **none**:
  - The request path resolves the role in `actor.tenantId()` (404/403) and checks mutability (409) before the read. Bumps use `actor.tenantId()`.
  - The role replay reuses the `(tenantId, roleId)` captured from that already-resolved detach.
  - Role ids are server-generated UUIDv7. No request value reaches the query or the keys.
  - The worst case for an inconsistent cross-tenant `user_roles` row is a bump under the wrong tenant prefix: a missed revocation, never an escalation. That user's permissions are also resolved under their own tenant.
  - The predicate is still worth adding when M8's composite FK lands. The allowlist is unchanged, so no sign-off is needed.
- **The `EVICT_SCRIPT` guard.** `RedisPermissionCacheAdapter.java` (attach eviction) still uses bare `tonumber`, without the L-1 digit guard. This is harmless: a corrupt value only means a DEL of a non-existent key, and attach eviction is fail-safe. Align it with the bump script's guard for consistency.
- **The scheduler thread can be held by the role replay.** `drainRoleQueue` calls `invalidateHolders` on the tick thread. A slow but answering Redis and a role with N holders costs up to N/500 × 500 ms before the tick's purge, probe and user replay run. The holder read itself is bounded at 1 s. This is availability only, and admin-triggered.

---

## Focus areas (re-derived)

### 1. `PermissionFreshnessService`: the last-seen map, pools, markers and state machine

**Fail-open paths.** A revoked token is still accepted in the following cases:
1. A single failed read in Healthy, for a user the instance has not seen.
2. DegradedOpen, for users not in the map (RES-30).
3. **The bump fails while reads succeed (M-1, new).**
4. Read-pool saturation (L-1).
5. Replay overflow (L-2), restart, or Sentinel failover (RES-31).

DegradedClosed returns UNAVAILABLE before it consults anything. STALE always wins over SKIPPED_* when the map knows a higher epoch. An unparseable value is STALE, is not counted as a store failure, and its WARN is limited to one per tenant per minute (`:525-541`). `unparseableWindows` is purged every tick.

**Own-bump pool.**
- Own bumps live in a separate pool: per tenant, `lastSeenTenantCap × 4`, and `2 × LAST_SEEN_CAPACITY` in total.
- A refused own bump marks the tenant lost (`:782-786`), and `revocationLost` makes it STALE on the unverified path.
- A refused read-to-bump move keeps the epoch as a read entry and is counted (`:769-776`, `:788-790`). No revocation is lost, because the epoch is still recorded.
- The marker set holds at most 1,000 tenants, then `lostAllUntil` applies. The `size()` check and the `put` are not atomic, so it can overshoot by a few entries under contention. That is harmless.

**Slot accounting.**
- Every claim happens inside `lastSeen.compute` for the key.
- Every release happens after a successful `remove(k, v)`, in the request path (`:727`) or the purge (`:860`).
- A purge racing a `remember` either removes first (the writer then claims a new slot) or loses the `remove(k, v)` (no release).
- I found no leak and no double release. The test hooks `lastSeenCountsFromMap` and `lastSeenCountsFromCounters` cover this.

**Request-path cost.** The request path does no scans: `lastSeenEpoch`, `claim` and `release` are O(1). `purgeExpiredSeen` iterates up to about 300k entries once a second on the scheduler thread only (H-1 holds).

**State machine.**
- Only read failures and probe failures count. Unparseable values, bump failures, drain failures and mint reads never count.
- `check()` runs only after RS256 verification on non-public paths, so **an unauthenticated caller cannot move the state machine**, and refresh and logout never call `check()`.
- An authenticated low-privilege user can still raise load until 50 ms reads time out. This is the 07 M-1 lever, carried over, and the k6 overload gate is still open. With L-3 they can also time it.
- Forcing the **global** fail-closed state takes own-bump refusals in more than 1,000 tenants. Only tenant administrators' revoke and detach actions create own bumps, so it is not reachable by an unauthenticated or low-privilege caller (L-1).
- Recovering is reset by any single read failure. That is availability only: Recovering checks like Healthy.

### 2. Epoch parsing, keys and Redis configuration

**Parsing.**
- Lua: `string.len(raw) <= 16`, `^%d+$`, `v == v`, `0 <= v <= 2^53-2`, otherwise 0. The new value is `min(max(old+1, TIME ms), MAX)`, formatted with `%.0f`.
- Java: 1 to 16 ASCII digits and `<= 2^53-2`, otherwise `EpochUnparseableException`. A result value that does not parse omits only that user (`:190-199`).
- The two agree for leading zeros, `0`, `nan`, `inf`, hex, exponent forms, signs, the empty string and the 17-digit case. Every value the script writes is one Java accepts, and the epoch never goes down.

**Injection.**
- Keys are built only from typed `UUID`s (canonical `toString`) and an operator-set prefix.
- The scripts receive keys in `KEYS` and stems in `ARGV`, and only append a number they formatted themselves.
- No request string reaches a key or a script. There is no key or script injection.

**Key TTL.** `EpochRedisConfig` refuses to start unless `key-ttl ≥ max(token TTL + skew, cache TTL) + 60`, which is 960 today.

**TLS and authentication.**
- The dedicated factories copy the main client's TLS flag, verify mode, StartTLS, `SslOptions` and client name.
- Credentials, including Sentinel passwords, come from the same `DataRedisConnectionDetails`.
- `RedisAuthStartupAssertion` checks the effective password of all three factories before any connection is attempted, treats a blank password as missing, and never puts a credential, username, URL or host in its messages.
- **Open item (human, not a finding):** `application-prod.yml` lacks `nexus.rbac.redis.require-auth: true` and `nexus.rbac.throttle.require-shared-store: true` (RC-45.1). The prod-profile test is `@Disabled`. I would add `server.forward-headers-strategy` to the same edit (L-6).

### 3. `EpochReplayQueue` and `RoleReplayQueue`

- **Bounds:** both queues are bounded by distinct users or roles, and `requeue` exceeds the bound by at most one batch or one role.
- **Expiry:** entries expire on the newest failure time.
- **Logs:** the queues log no user ids. Log lines carry tenantId, roleId, counts, ages, the exception class and the hostname.
- **Cross-tenant replay:** impossible, as described in L-2.
- **Gaps:** no per-tenant share (L-2), and M-1, where a queued replay is not reflected in the Healthy verdict.

### 4. Refresh rate limits

- **Order of checks.** In `RefreshTokenUseCase` the order is: hash, lookup, reuse branch (`revokeFamily` in `REQUIRES_NEW`, a reuse audit row, 401 with no bucket consulted), family bucket, expiry, optimistic-lock rotation. **Reuse detection cannot be suppressed** by any bucket (RC-51 is visible in code).
- **No oracle.** A 429 versus a 401 reveals nothing beyond possession of a valid token:
  - the family bucket is reachable only with a found, unrevoked token;
  - a replay that revokes something always gets 401;
  - a replay that revokes nothing goes through `REFRESH_IP_FAIL`.
- **Keys.** The keys are `REFRESH_FAMILY:{sha256(familyId)}` and `REFRESH_IP_FAIL:{remoteAddr}`. No XFF is read in code; see L-6 for the platform default. With `store-type: memory`, key cardinality is bounded by the store's sweeper (US-003 T-6.2).
- **Logs and metrics.** The WARN is limited to one per window and carries `rejectedCount` only. `GlobalExceptionHandler` logs `RefreshThrottledException` at DEBUG. No IP or family id appears in any log line or metric tag. IPs remain in `auth_events` rows (audit by design, SECURITY.md §10).
- **RES-40 junk-flood lever (carried over, accepted).** 300 junk requests a minute exhaust `REFRESH_IP`; behind the proxy (DF-1), that is platform-wide. The SPA now keeps the session on a 429. The k6 `refresh-junk-flood` gate has not been run, and a failed proxied run blocks the merge (README).

### 5. SPA `auth.interceptor.ts`

- **Retry-After handling.** A refresh 429 is retried at most twice. `Retry-After` must be delta-seconds (`^\d+$`), is clamped to 1 to 60 s, and defaults to 5 s. A huge or malformed value cannot stall or hot-loop the client. Concurrent callers share one in-flight refresh (`shareReplay`, reset in `finalize`).
- **Session clearing.** The session is cleared on any refresh error except 429. A 503 `AUTH_005` on a business request does not clear it. A STALE-then-refresh-then-STALE sequence surfaces an error after one retry, with no loop.
- **Bearer scope.** No bearer is sent cross-origin. The same-origin prefix issue is L-5.

### 6. Tenant isolation, authorization, PII and secrets

- **Tenant source.** Every tenant id on the new paths comes from the verified token (`JwtAuthenticationFilter`), `actor.tenantId()`, or the queued tenant of an already-resolved role.
- **Public endpoints.** A `@PublicEndpoint` request gets a permission-free principal (RC-44). `PublicEndpointRequestMatcher` fails closed and counts each fail-closed match.
- **Holder query.** See Informational.
- **New metric tags.** The tags are bounded: `outcome` has 6 values, `state` 3, `holders` 5, `reason` 7, and `operation` takes code constants. There is no tenant, user or IP tag.
- **New log lines.** They carry no user id, email, IP, family id, token or epoch value. Pre-existing and unchanged: the `TOKEN_REFRESH_SUCCESS userId` DEBUG line, the `userId`/`tenantId` MDC entries, and `revokedBy` in the detach INFO line.
- **Secrets.** There are no secrets in config: Redis and DB credentials come from the environment, with an empty default outside prod. The k6 scripts read admin credentials from the environment, but hard-code synthetic account passwords (L-4).

---

## Threat-model cross-reference (`03b-threat-model.md`)

| Threat / RC | Status in model | Mitigation visible in this diff |
|---|---|---|
| M7 **S** stale permissions under a fresh epoch (MC-7a/7b, Decision 17) | ✅ mitigated | **Yes.** `JwtRs256Service.issue` reads the epoch before resolving. The bump runs in `afterCommit`. The cache is keyed by epoch, and the bump script deletes under the old epoch. Unverified mints bypass the cache. |
| T-E40 attach without bump, v2 as epoch 0, M6 accepts v3 | ✅ attacked, survived | **Yes.** A v2 token verifies to epoch 0 (`JwtRs256Service` verify). An attach evicts without bumping. |
| T-D23 unbounded fan-out | ✅ accepted | **Yes**, consistent: no cap, 500-user batches, the first failure ends the fan-out, and buckets plus a WARN above 1,000. |
| T-E37 / RC-29 key TTL | required | **Yes.** `EpochRedisConfig` startup assertion and `TokenFreshnessIT` race test. |
| T-E38 / RC-30, T-E44 / RC-42 replay | required | **Yes, with a gap.** The queue, a drain every tick in every state, and the role-level replay (M-2 of 10) are present. **However, the Healthy verdict ignores a pending replay (M-1)**, and the queues have no per-tenant share (L-2). |
| T-D20 / RC-31, T-E43 / RC-41, T-E47 / RC-53, RC-52 | required | **Yes.** Sliding window, `t0` kept on relapse, sustain measured after the drain, unconditional scheduling. |
| T-D17 / RC-44 public exemption, 503 | required | **Yes.** `filterPublic` never calls `check`. The 503 is JSON-escaped and clears the security context. |
| T-D19 / RC-32, T-D24 / RC-43, T-E46 / RC-51 | required | **Yes in code.** The k6 gates (RC-32.3, RC-43.3 and the junk flood) have not been run. |
| T-T16 / RC-34, RC-45 Redis auth | required | **Code yes, prod profile no** (open human item; see the verdict). |
| RES-30 / RES-31 / RES-40 | accepted | RES-31 should name the cross-tenant overflow (L-2). RES-30's attacker-timing lever is sharpened by L-3. |

## OWASP Top 10 (SECURITY.md §12)

- **A01 Broken Access Control:** 1 Medium (M-1) and Lows L-1, L-2 and L-5. Default-deny is intact, every tenant id is token-derived, and there is no IDOR on the new paths.
- **A02 Cryptographic Failures:** Pass. SHA-256 is used for key hiding only. Redis TLS settings are carried over to the dedicated factories, and TLS stays an ops prerequisite under RC-34.
- **A03 Injection:** Pass. The Lua scripts are static and take parameterised keys and arguments built from typed UUIDs and longs. The 503 body is escaped.
- **A04 Insecure Design:** M-1, L-1 and L-2.
- **A05 Security Misconfiguration:** The prod-profile open item, L-3 and L-6.
- **A06 Vulnerable Components:** npm has 1 high and 6 moderate, pre-existing and unchanged on this branch. Backend dependency-check was **not run** (sandbox) and is left to CI.
- **A07 Identification & Authentication Failures:** Pass in code. Reuse detection comes first and the family bucket cannot be exhausted by a stranger. Low L-4 (test accounts).
- **A08 Software & Data Integrity Failures:** Pass. The script and the parser agree on one range.
- **A09 Security Logging & Monitoring Failures:** Pass. Log volume is bounded and there is no PII in new lines or tags. Add `last_seen_dropped{capacity}` and the proposed `store_regressed` to paging.
- **A10 SSRF:** Not applicable.

## Summary

| Severity | Count | Findings |
|---|---|---|
| Blocker | 0 | |
| High | 0 | (the prod-profile `require-auth` item is a human-owned open item, not counted) |
| Medium | 1 | M-1 Healthy/Recovering verdict and mint ignore the local bound after a refused or lost bump (new) |
| Low | 6 | L-1 global pool saturation (new) · L-2 replay queues lack a per-tenant share (partly new) · L-3 Prometheus exposes degraded state (carried over) · L-4 hard-coded k6 account passwords (new, plus carried over) · L-5 SPA `/api` prefix match (carried over) · L-6 forward-headers default (carried over, config) |

**Verdict: BLOCKED** until (1) the human edit to `application-prod.yml` lands and the `@Disabled` prod-profile test is green, and (2) M-1 is fixed or accepted with a named owner. Then it is **APPROVED**. L-1 to L-6 can be ticketed.

## Residual risk

- **RES-30:** time-boxed fail-open (15 min per instance). It can be induced by authenticated load, and timed via L-3, until the k6 overload profile and the alerts land.
- **RES-31:** replay lost on restart or failover, and overflow, including cross-tenant overflow (L-2).
- **RES-32:** Redis write access equals authorization. It is Low only once the prod profile enforces authentication.
- **RES-40:** the junk-flood lever, platform-wide behind the proxy, until the proxied k6 run passes.
- **Pending:** CI dependency-check, the npm `@angular/*` upgrade (pre-existing), and the k6 gates.
