# Security Review: US-018 M7 / T-009 (A9 per-user permission epoch, core)

**Verdict: APPROVED for the T-009 increment, with conditions.** Nothing in this diff is a Blocker or High. There is 1 Medium and 5 Low findings. The Medium is a defence-in-depth gap in the fail-open policy. It is not exploitable beyond the pre-A9 baseline, and its fix belongs to T-011.

The approval depends on these conditions:
1. **The one-PR rule holds.** T-009 does not merge to `main` and is not released except inside the single M7 PR with T-010..T-014 (`04-tasks.md` M7 merge checklist, first item). On its own, T-009 fails open on every request during a Redis outage, and nothing bounds that or pages anyone.
2. **M-1 is resolved by T-011, or Platform Security accepts it as part of RES-30,** before the M7 PR merges.
3. **A06 is closed by CI.** The OWASP dependency-check could not run here (see the scans section).

**Scope:** `git diff origin/main...HEAD` on `ccr-4e9e7cbe-4vl9v6` at HEAD `737a450`: commits `19bec79` (feature), `13a8e1f` (review fixes) and `737a450` (docs). `6294e24` and `9cf4156` are docs-only. 46 files, +3002/-165. No application code, test or config file was modified by this review.

**Auth, authorization, crypto, credentials and PII were reviewed explicitly.** This change is authentication and authorization code (`JwtAuthenticationFilter`, `SecurityConfig`, `JwtRs256Service`, `JwtClaims`, `PublicEndpointRequestMatcher`). It also handles credentials (Redis password, ACL username, Sentinel credentials and TLS settings copied in `EpochRedisConfig`). The concerns checked:
- token claim handling (`perm_epoch`, v2/v3 acceptance, downgrade to epoch 0)
- the authn/authz boundary and fail-closed paths
- the `permitAll` set built from `PublicEndpointRequestMatcher`
- the principal set from a verified bearer on a public endpoint
- IDOR and tenant isolation of the epoch key
- Lua script injection and key collision
- epoch monotonicity
- the fail-open scope, including DoS-induced fail-open and the warm-up window
- post-commit bump failure
- Redis TLS and credential propagation, secrets in logs
- PII and token material in logs and metrics, metric cardinality
- the k6 scripts

Findings and evidence below.

---

## Verification run

| Check | Result |
|---|---|
| Unit and slice tests, offline (`mvn -o test`, jacoco, spotbugs and checkstyle skipped): `JwtAuthenticationFilterTest`, `PermissionFreshnessServiceTest`, `EpochRedisConfigTest`, `JwtRs256ServiceTest`, `JwtRs256ServiceSecurityTest`, `JwtClaimsContractTest`, `JwtClaimsTest`, `PublicEndpointRequestMatcherTest`, `SecurityConfigWebTest`, `EndpointClassificationWebTest` (incl. `PermitAllOverlapProbe`), `AuthenticationDetailsContractTest`, `RedisPermissionEpochAdapterNotReadyTest`, `RoleAssignmentServiceTest`, `RequiresPermissionWebTest` | **487 run, 0 failures, 0 errors, BUILD SUCCESS** |
| ITs (`TokenFreshnessIT`, `RedisPermissionEpochAdapterIT`, `RefreshTokenPermissionResolutionIT`) | **Not run here.** No Docker daemon in this environment. The resolution note in `06-code-review-M7.md` records 376 ITs and 0 failures on the branch after the fixes. The test bodies were read and match RC-24.3 and RC-44.4 (see the cross-reference). |
| `JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64 mvn -Psecurity dependency-check:check` | **Could not complete, left to CI.** It was run once and not retried. Error: `UpdateException: ... known_exploited_vulnerabilities.json - Server status: 403 - Server reason: Forbidden`, then `NoDataException: No documents exist`. There is no local NVD cache. The diff changes no `pom.xml` and adds no dependency (Lettuce and Spring Data Redis were already present). |
| `npm audit --omit=dev --audit-level=high` (`nexus-frontend`) | **Ran, exit 1: 7 vulnerabilities (6 moderate, 1 high), all pre-existing.** The diff contains no frontend change and no lockfile change. The high is `@angular/router` 22.0.4, via "Angular SSR: Denial of Service via Numeric URL Matrix Parameters". The project has no `@angular/ssr` dependency. The moderates are Angular 22.0.x sanitisation-bypass and `HttpTransferCache` advisories, fixed in 22.1.x/22.2.x. This is outside this diff but must be triaged separately, because the CI `npm audit` (high+) gate fails on `main` as well. |

---

## Findings

```
[MEDIUM] Per-request fail-open can be induced from inside the app with a self-registered account, a cheaper lever than the threat model priced
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java:88-104
      nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java:110-118
      nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java:63-75
      nexus-backend/src/main/resources/application.yml:146 (command-timeout 50ms)
Issue: SKIPPED_ERROR proceeds with the token's full permissions. Any read that does not complete
       within 50 ms produces it, and that 50 ms is measured on the client: it includes queueing on
       the Lettuce event loop, the shared native connection and JVM pauses, as well as Redis time.
       Self-registration is open, so anyone can get a valid token (threat-model §0.2 #1). An
       attacker who also holds a revoked token T_r can drive one instance with a fresh token T_f
       (any authenticated endpoint, each request costing one epoch read plus normal handler work)
       until epoch reads exceed 50 ms. The attacker then sends T_r, and the share of T_r requests
       that hit SKIPPED_ERROR are served with the revoked permissions. T-D20 part 3 only priced the
       Redis-saturation lever through unauthenticated rate-limited endpoints ("hard at the scale
       needed"). App-side saturation by an authenticated caller is cheaper and was not modelled.
       In T-009 alone this is unbounded and unalerted. Under T-011 as designed, 3 such failures in
       10 s move the whole instance to DegradedOpen, where checks are skipped for everyone until a
       probe succeeds, and the probe shares the same 50 ms bound and the same saturated event loop.
Risk: Revocation (A9) can be suppressed on a targeted instance for as long as the load is held.
      Exposure per revocation stays bounded by the token TTL (900 s), which is the pre-A9
      baseline. Refresh re-resolves permissions, and the role-name fingerprint in
      RoleResolutionService catches a revoked role. Not a Blocker, because the Gate 1 decision
      accepted a time-boxed fail-open and the bound holds. It is still an attacker-controlled
      switch for a Gate 1 control. OWASP A01 (Broken Access Control), A04 (Insecure Design).
Fix (T-011 scope, or record as accepted under RES-30 with this lever named):
     (a) Keep a bounded per-instance "last seen epoch" map, keyed by (tenantId, userId) and
         expiring at key-ttl-seconds. Update it on every successful read and on every local bump.
         On SKIPPED_ERROR, compare the token epoch against it and return STALE when lower. A user
         this instance has already seen bumped is then rejected even while reads fail. A few
         hundred bytes per active user, no Redis call.
     (b) Make the §9.9 page on `epoch.check{outcome=skipped_error}` > 1% for 5 min part of the
         M7 PR's alert content, and add a per-instance request-rate panel next to it so an
         induced pattern is distinguishable from a Redis fault.
     (c) Extend the T-009 k6 gate with an overload profile (for example 2x the target rate on
         one instance). Record the `skipped_error` ratio, and with it the point at which the
         50 ms bound starts failing open.
```

```
[LOW] A corrupt or out-of-range stored epoch fails open, and under T-011 would count as a store failure
File: nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java:69-70
Issue: NumberFormatException from Long.parseLong is handled the same way as a timeout: OptionalLong.empty(),
       so the verdict is SKIPPED_ERROR and the request proceeds. A value Redis holds but Java cannot parse
       stays that way until the key TTL expires. Examples are a non-numeric string, or a number above
       Long.MAX_VALUE. The bump script writes string.format('%.0f', max(old+1, nowMs)), so a stored
       9223372036854775807 bumps to "9223372036854775808". Every request by that user then fails open.
       Once T-011 counts read failures, the same user's 3 requests in 10 s would also push the whole
       instance into DegradedOpen.
Risk: Requires Redis write access (T-T16). That access already allows DEL, so there is no new
      privilege for the attacker. But it turns a one-user data problem into instance-wide degraded
      state, and it fails open where failing closed is cheap. OWASP A04.
Fix: Treat a non-parseable value as STALE for that user (fail closed). Log
     `RBAC_EPOCH_UNPARSEABLE` at WARN with tenantId only, add a fourth `outcome` tag value (bounded),
     and exclude this outcome from T-011's failure window. Add an adapter test with values "abc" and
     "9223372036854775808".
```

```
[LOW] The not-ready window after startup is a silent fail-open; T-011 and T-012 must cover it explicitly
File: nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java:226-257
      nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java:64-66, 80-82
      nexus-backend/src/main/resources/application.yml:107-120 (readiness excludes Redis by design)
Issue: Until WarmedFactory connects, every check returns SKIPPED_ERROR and every bump throws. Both are
       correct choices (fixes H-1). But readiness does not include the epoch store (ADR-0016 §7), so a
       restarted instance takes traffic straight away. If Redis is unreachable it stays in that state
       indefinitely, and it logs a single WARN. An attacker cannot start this window; it needs a
       restart plus an unreachable Redis. A crash-restart caused by DoS is the only attacker-adjacent
       route.
Risk: The same exposure as an outage, but it begins before T-011's state machine has seen any
      failure. If T-011's window counts only reads that reached Redis, the time box never starts
      for an instance that never connected. Bumps during the window are lost until T-012 replays
      them. OWASP A04, A09.
Fix: In T-011, count a not-ready read as a read failure (so t0 starts at the first one), and gate
     the probe on the same readiness. In T-012, make sure a not-ready bump is enqueued. Add one
     T-011 test: an instance started against an unreachable Redis reaches DegradedOpen within 10 s
     and DegradedClosed after the window.
```

```
[LOW] User id in every log line of public-endpoint requests that carry a verified bearer (PII-adjacent, carried over)
File: nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java:136, 156-157
Issue: filterPublic -> authenticateAndContinue puts MDC userId (token `sub`) and tenantId on every log line
       of /auth/refresh and /auth/logout requests whose bearer verifies, including a stale-epoch bearer
       that is now accepted there. This continues the T-3.7 MDC behaviour; this diff adds no new log field
       carrying a user id. The new `RBAC_EPOCH_BUMP_FAILED` log deliberately carries tenantId and
       userCount, not the user id. Flagged under the org policy that user ids in log lines count as
       PII-adjacent.
Risk: No new disclosure versus main. Log readers can correlate a user's refresh and logout activity.
      OWASP A09 (logging hygiene).
Fix: No change required for T-009. Confirm the MDC userId policy (SECURITY.md §7 does not list user
     ids as PII) in the M11 documentation pass, or move MDC userId to a pseudonymous form.
```

```
[LOW] /actuator/prometheus is readable by any authenticated user, and the new k6 gate relies on that (pre-existing exposure)
File: nexus-backend/src/main/resources/application.yml:83 (exposure include ... prometheus)
      nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java:93 (anyRequest().authenticated())
      nexus-test/performance-test/tests/load/epoch-check-latency.js:79-85
Issue: Any self-registered user of any tenant can scrape platform-wide metrics. That now includes
       `nexus.rbac.epoch.check{outcome}` and `nexus.security.public_match_failed_closed`, which show
       revocation activity (`stale`) and fail-open episodes (`skipped_error`) in near real time. The
       k6 gate scrapes with the ordinary perf-user bearer, which makes the exposure a test dependency.
       The new meters carry no tenant or user tags (good).
Risk: Information disclosure to a low-privilege user. An attacker can watch `skipped_error` to time
      use of a revoked token, which makes the Medium above easier to tune. OWASP A01, A05.
Fix: Outside T-009. Restrict /actuator/prometheus and /actuator/metrics to a scrape principal or the
     management port. The k6 script then needs a separate scrape credential (env only, as today).
     Ticket it against the platform baseline.
```

```
[LOW] T-014's require-auth assertion must check the credentials the dedicated factories actually use
File: nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java:153, 163
      docs/features/US-018/04-tasks.md:774 (T-014 text: "spring.data.redis.password is blank")
Issue: The dedicated factories take username and password from DataRedisConnectionDetails. That source
       can be a `spring.data.redis.url` with userinfo or a service connection, not only the
       `spring.data.redis.password` property. As written, T-014 checks the property. If the two
       diverge, the assertion either fails a correctly authenticated start or passes a
       credential-less one.
Risk: The RC-34.1 or RC-45.2 production guard can be inert in one deployment shape. OWASP A05, A07.
Fix: When T-014 lands, assert on DataRedisConnectionDetails.getPassword() (and the Sentinel password
     if Sentinel is used). That is the object both dedicated factories are built from. Add a test
     with a password supplied only through `rediss://user:pass@host`.
```

---

## Focus areas

**Token claims (A02, A07, A08).**
- `perm_epoch` is read only after the RS256 signature and the explicit `alg` assertion pass (M6 phase 1, unchanged).
- For v3 it must be a non-negative `Integer`/`Long` (`JwtRs256Service.java:221-229`), otherwise it is rejected as `PERM_EPOCH`.
- A v2 token gets epoch 0. **Downgrade gives an attacker nothing:**
  - 0 is the lowest possible epoch, so a v2 token is STALE whenever a stored epoch exists. `TokenFreshnessIT.should_return401_when_v2TokenForRecentlyRevokedUser` covers this.
  - When no key exists, v2 and v3 are equally FRESH.
  - A token minted during a Redis failure carries 0, which is safe in the same way.
  - Only the platform key can mint any version.
- MC-7a holds: the epoch is read at `JwtRs256Service.java:118` before `resolve`, and an `InOrder` test pins it.
- RS256 signing, the key and the randomness source are unchanged. `perm_epoch` is a Redis-time counter, not a secret.

**Authn/authz boundary (A01, A07): fail-closed where it matters.**
- *Non-public request:* `verify` → canonical UUIDs (a non-UUID now gives 401, not 500, `:99-108`) → one `check`. STALE gives the entry point a 401 `AUTH_003` with the context cleared. Any unexpected runtime exception from the check propagates before `setAuthentication`, so it fails closed.
- `switch (verdict)` has no `default`, so T-011 verdicts must be handled explicitly.
- *Public request:* the epoch is never checked. A failed bearer leaves the request anonymous. A verified bearer gets `authorities=[]` and `PERMISSIONS=[]` (`:136`). So an epoch-unchecked token can satisfy `authenticated()` only on a request the matcher classed as public, and it can never satisfy `@RequiresPermission`.
- The only consumer of that principal is logout (`LoginController.java:137-141`), which revokes the caller's own refresh families. That is acceptable for a stale or revoked user (RES-43).

**`permitAll` from the matcher (A01, A05): stronger than before.**
- `SecurityConfig.java:89` replaces the path-only literal list with the matcher's method-plus-pattern decision. This closes security review F-5: `PermitAllOverlapProbe` now shows anonymous `GET` and `HEAD /api/v1/auth/login`, served by a non-public pattern, are denied.
- The filter and the `AuthorizationFilter` evaluate the same deterministic matcher on the same request, so they cannot disagree on a REQUEST dispatch. Not caching the answer is correct: the `AuthorizationFilter` re-runs on FORWARD and ERROR dispatches, `/error` is not public, and those dispatches re-evaluate fail-closed. The bearer filter is `OncePerRequestFilter` and does not re-run there, so the context on an ERROR dispatch is anonymous, as on `main`.
- Path normalisation, verified by `PublicEndpointRequestMatcherTest` (28 tests):
  - trailing slash, upper case, `//`, lower-case method and PROPFIND all answer non-public;
  - the context path is honoured;
  - a plain OPTIONS is not public, and a CORS preflight is public only for a public method;
  - HEAD on a public GET (JWKS) is public, matching MVC;
  - matrix parameters (`;`) are rejected earlier by `StrictHttpFirewall`. If they were allowed, `PathPattern` would strip them the same way for MVC dispatch, so matcher and dispatch would still agree.
- `EndpointClassificationWebTest` requires every `@PublicEndpoint` pattern to be a literal (no `{`, `*`, `?`).
- A wrong method on a public path now gets 401 `AUTH_003` instead of 405 (L-6, documented). This leaks nothing: the 401 body is the fixed template.
- SECURITY.md §1's baseline row ("only `/actuator/health/**`, `/actuator/info` ... are public") omits the `@PublicEndpoint` handlers. That was already true on `main`; noted for the M11 docs pass.

**Tenant isolation and IDOR (A01).**
- The epoch key is `{prefix}:rbac:epoch:{tenantId}:{userId}`. Both ids come from the verified token: canonical 36-character UUIDs, re-serialised through `UUID`. Neither ever comes from the request path or body.
- The fixed-width segments and `:` separators rule out collisions between tenants. Revoke bumps `actor.tenantId()` plus the target, and the target is already tenant-verified by the existing revoke path.
- `TenantIsolationArchitectureTest` and `UNSCOPED_ALLOWLIST` are untouched.

**Lua script (A03).** The script is a static constant. Keys go through `KEYS` and the TTL through `ARGV`, and no caller string is concatenated into script text, so injection is not possible. The `GET` → `false` → `'0'` path for a missing key is handled. Epoch values (about 1.7e12 ms) are far below 2^53, so double arithmetic is exact. Multi-key use is legal under standalone or Sentinel only (cluster is rejected at startup).

**Monotonicity and key loss.** `max(old + 1, TIME ms)` is monotonic while the key exists, and after key loss as long as the Redis clock does not go backwards. `RedisPermissionEpochAdapterIT.should_stayMonotonicAcrossKeyDeletion` asserts `>`. The remaining case, key loss plus a Sentinel failover to a lagging clock, is recorded as accepted residual in ADR-0022 (L-4). Key loss alone (flush or eviction) makes every token FRESH for at most one token TTL, which is the pre-A9 baseline (RES-31). The 960 s key TTL is checked at startup against `max(token TTL + skew, cache TTL) + 60`.

**Revocation race (S row).** The bump runs strictly in `afterCommit`, after the cache evict (`RoleAssignmentService.java:613-634`, MC-7b test). Here is the race that could re-fill the cache with the pre-commit set: a mint reads the DB before the commit, then writes the cache after the evict. It is caught by the existing role-name fingerprint in `RoleResolutionService` (a revoke always changes the live role set). The epoch-keyed cache from the threat model's S row is T-010 and is not needed for the revoke path.

**Post-commit bump failure (T-012 residual).** A failed bump is logged at ERROR as `RBAC_EPOCH_BUMP_FAILED` and never rethrown, so the committed revoke still returns success. The revoked token then stays valid for up to 900 s and nothing replays the bump. In T-009 the only signal is that log line: the `bump_failed` metric and the replay queue are T-011/T-012. This is acceptable only under the one-PR rule.

**Redis credentials and TLS (A02, A05, A07).**
- Host, port, database, ACL username and password, and the Sentinel master, nodes and credentials come from the same `DataRedisConnectionDetails` as the main factory.
- The TLS flag (including `rediss://`), verify mode, STARTTLS, `SslOptions` (bundle key and trust managers, ciphers, protocols) and the client name are copied from the main factory's client configuration. There is **no plaintext fallback**: if the main factory uses TLS, both dedicated factories do. The bundle and `rediss://` cases are tested (`EpochRedisConfigTest:193, 223`).
- `readFrom` is not copied, so epoch reads always go to the primary. This is the safe choice, because replica lag would read an older epoch.
- No credential reaches a log, an exception message or a metric. The warm-up logs only the thread name and the exception class name. The startup-assertion message contains only TTL numbers. Test literals (`"s3cret"`) are fixtures.

**Logging, PII and metrics (A09).**
- New log lines carry no token material, no claim values and no user ids. The read failure is DEBUG with the exception class only. The bump failure is ERROR with event, operation, tenantId, userCount and the exception class.
- Cardinality is fixed:
  - `nexus.rbac.epoch.check{outcome}` has 3 values, registered up front;
  - `nexus.rbac.epoch.check.latency` has no tags (p50, p95, p99);
  - `nexus.security.public_match_failed_closed` has no tags.
- There is no tenant or user tag (MC-8 respected). The MDC user id is covered by the Low above.

**k6 scripts.**
- No credential is committed. `ACCESS_TOKEN`, `PERF_USER_EMAIL` and `PERF_USER_PASSWORD` come only from `__ENV`.
- `results/*` is gitignored, and setup data (the token) is not part of `--summary-export`.
- `inspect-tests.sh` passes only the placeholders `BASE_URL=http://inspect.invalid` and `BASELINE_P95_MS=1`.
- The script's dependence on `/actuator/prometheus` is the Low above.

---

## Threat-model cross-reference (`03b-threat-model.md` M7/M7b table §2, §3, §11.5, §12.4; T-009 scope per `04-tasks.md`)

| Threat / RC | Status in model | Mitigation visible in this diff |
|---|---|---|
| M7 **S**: stale permissions under a fresh epoch (MC-7a, MC-7b, epoch-keyed cache) | ✅ | **Partly; the rest is T-010.** MC-7a: `JwtRs256Service.java:118` plus the `InOrder` test. MC-7b: `RoleAssignmentService.java:633` in `afterCommit` plus the test. The epoch-keyed cache is T-010. Meanwhile the revoke path is covered by the existing role-name fingerprint (see above). |
| **T-D17** (High) / RC-24.1: no freshness check or rejection on public auth paths, one source of "public" | ❌ → required | **Yes, for the epoch half.** `JwtAuthenticationFilter.java:89-92, 126-137`, with the matcher as the only source (`SecurityConfig.java:89`). The degraded-closed 503 half is T-011. |
| RC-24.3: refresh with a stale bearer → 200; logout with a stale bearer revokes the family; refresh with an expired bearer → 200 | required | **Yes**, `TokenFreshnessIT:182, 192, 203` and `SecurityConfigWebTest.should_return200_when_refreshCarriesInvalidBearer`. The degraded-closed case is T-011. ITs not re-run here (no Docker). |
| **T-E45** / RC-44.1, RC-44.3 (matcher fail-closed, method plus pattern, equivalence sweep) | ✅ (T-004, merged) | Consumed unchanged, plus the `public_match_failed_closed` counter and the literal-pattern sweep |
| **T-E45** / RC-44.2: permission-free principal on public requests | required (T-009 half) | **Yes**, `JwtAuthenticationFilter.java:136`. Test `should_setPrincipalWithEmptyPermissionsAndNoAuthorities_when_publicBearerVerifies` |
| **T-E45** / RC-44.4: logout with a stale bearer and no cookie revokes every family; stale bearer on a non-public handler → 401 | required | **Yes**, `TokenFreshnessIT:168, 217`. The "503 while degraded-closed" case is T-011. |
| **T-E37** / RC-29.1, RC-29.2: key TTL ≥ max(token, cache) + 60 s, startup fails otherwise | required | **Yes**, `EpochRedisConfig.java:69-84` (skew included, L-3). Boundary tests at 959/960. **RC-29.3** (key-expiry race IT) is T-010 |
| RC-42.2: bump on its own 500 ms template | required | **Yes**, second dedicated factory, `nexus.rbac.epoch.bump-timeout` |
| RC-45.2: dedicated factories use the same credentials and TLS | required | **Yes**, `EpochRedisConfig.java:114-165` plus `EpochRedisConfigTest`. The auth-enabled Redis IT and `require-auth` are **T-014** (see the Low above) |
| **T-E40** (Low): v2 = epoch 0, M6 accepts v3 | ✅ attacked and survived | **Yes**, `JwtRs256Service.java:221-229`. `TokenFreshnessIT:155`. RC-40.6 (rollback to M6 pages Security) is runbook content, due in the M7 docs pass |
| §9.5 hot path: 50 ms read bound, never the 2 s default, never connecting on a request thread | required | **Yes**, `EpochRedisConfig.java:114-165, 226-257` (H-1 fix); `RedisPermissionEpochAdapterIT:190, 220`; `NotReadyTest`. The k6 gate passed on local Docker only. The staging run is deferred. |
| **T-D20** part 3: can an attacker force fail-open? | ❌ → RC-31 (T-011) | **Partly.** Per-request fail-open is counted (`skipped_error`). **New lever not in the model: the Medium above.** |
| **T-T16** / RC-34.1: Redis is authorization state | ❌ → T-014 | Deferred to **T-014** |
| **T-E38** / RC-30, **T-E44** / RC-42 (except 42.2): replay lost bumps | ❌ → T-012 | Deferred to **T-012**. T-009 logs `RBAC_EPOCH_BUMP_FAILED` only |
| **T-D20** / RC-31, **T-E43** / RC-41, **T-E47** / RC-53, RC-52: degraded-state machine and time box | ❌ → T-011 | Deferred to **T-011** (plus the Low on the not-ready window) |
| **T-D19** / RC-32, **T-D24** / RC-43, **T-E46** / RC-51: refresh limits and NAT | ❌ → T-013 | Deferred to **T-013** |
| **T-D23** (Low): fan-out unbounded | ✅ | Deferred to **T-010** (fan-out does not exist yet) |
| RES-43: a verified bearer on a public endpoint sets an unchecked principal | Low, accepted | Consistent: only logout reads it |

Every threat marked mitigated (✅) that is in T-009's scope has a visible mitigation and a test in this diff. The one exception is the epoch-keyed cache leg of the S row, which belongs to T-010 and is covered on the revoke path by the existing fingerprint. **Deferred to T-010..T-014:** RC-29.3 and T-D23 (T-010); T-D20, T-E43, T-E47, RC-52, the degraded half of T-D17 and of RC-44.4 (T-011); T-E38 and T-E44 (T-012); T-D19, T-D24 and T-E46 (T-013); T-T16, RC-34.1 and RC-45.1 (T-014).

---

## OWASP Top 10 checklist (SECURITY.md §12)

- **A01 Broken Access Control:** Pass, with 1 Medium (induced fail-open) and 1 Low (actuator metrics, pre-existing). Default-deny is intact. `permitAll` is narrower than on `main`. Tenant-scoped key ids come only from the token.
- **A02 Cryptographic Failures:** Pass. No change to algorithm, key or randomness. Redis TLS matches the main factory with no plaintext fallback.
- **A03 Injection:** Pass. The Lua script is static, with parameterised `KEYS`/`ARGV`. No query, command or template is built from input.
- **A04 Insecure Design:** Pass, with the Medium and 2 Lows (unparseable epoch, not-ready window), all forward requirements for T-011/T-012.
- **A05 Security Misconfiguration:** Pass. The 401 is generic and the 405 to 401 change is documented. The Low on T-014's assertion source is a forward item.
- **A06 Vulnerable Components:** **Not verified.** The dependency-check failed on the CISA/NVD 403 and was left to CI. No dependency changed. `npm audit`: 1 high and 6 moderate, all pre-existing, frontend unchanged.
- **A07 Identification & Authentication Failures:** Pass. Stale tokens get 401. Public auth paths are never rejected (T-D17). Malformed identifiers get 401, never 500.
- **A08 Software & Data Integrity Failures:** Pass. Claims are trusted only after the signature verifies. `perm_epoch` is type-checked.
- **A09 Security Logging & Monitoring Failures:** Pass on content: no token material, no credentials, bounded tags. Alerting (`skipped_error`, `bump_failed`) is M7 docs-pass and T-011 content. 1 Low on the MDC user id (carried over).
- **A10 SSRF:** Not applicable. The only outbound connection goes to the configured Redis.

## Residual risk

- **Accepted by design (Gate 1, RES-30):** time-boxed fail-open. Per-revocation exposure is at most the token TTL. The Medium above adds an authenticated, attacker-driven lever to it.
- **T-009 standalone:** unbounded fail-open during an outage, no replay and no paging. Contained only by the one-PR merge rule (process control, not code).
- **Recorded in ADR-0022:** epoch regression after key loss plus a Sentinel failover to a lagging clock.
- **RES-31:** key loss without AOF degrades to the pre-A9 bound.
- **Pending:** A06 until CI dependency-check is green; the k6 hot-path gate in the staging topology; the ITs were not re-run in this review environment.

## Relevant files

- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java`
- `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/PublicEndpointRequestMatcher.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java` (lines 613-634)
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java`
- `nexus-backend/src/main/resources/application.yml` (lines 83, 107-120, 146-151)
- `nexus-backend/src/test/java/com/example/nexus/rbac/TokenFreshnessIT.java`
- `nexus-backend/src/test/java/com/example/nexus/config/EndpointClassificationWebTest.java`
- `nexus-test/performance-test/tests/load/epoch-check-latency.js`
- `docs/features/US-018/03b-threat-model.md` (§2 M7 table lines 221-235; T-D17 293; T-E37 351; T-D20 370; T-T16 395; T-E45 926; RC-24 563; RC-44/45 1031-1042)
