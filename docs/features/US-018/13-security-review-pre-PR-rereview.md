# Security Re-review (pre-PR): US-018 M7 part 2, fixes after `12-security-review-pre-PR.md`

**Scope.** `git diff origin/main...HEAD` on `ccr-4e9e7cbe-4vl9v6`. I re-read the following commits as new code, without relying on the Resolution tables in `12` or on the commit messages: `0ec0ec1`, `bf74776`, `07b7626`, `a14d789`, `050af29`, `a6e6249` and `07ee950`. For context I also read the unchanged code they depend on: `JwtRs256Service.issue`, `RoleResolutionService`, `RedisPermissionCacheAdapter`, the detach and revoke post-commit paths, `LoginRateLimitFilter`, `nexus-frontend/nginx.conf` and the k6 harness.

**Verdict: BLOCKED.** There is no Blocker and no High. Two Mediums attributable to this branch must be fixed, or accepted with a named owner, before merge. That follows the convention of `10` and `12`.
- **M-1 is closed only on the instance whose bump failed.** Every other instance still accepts the revoked token. For a detach, those instances also re-mint the detached permission from the epoch-keyed cache.
- **The L-3 fix gates platform-wide metrics on a tenant-scoped role.** Any tenant's administrator can now read other tenants' ids and their security counters.

**Explicitly reviewed:**
- **Authentication:** token `iat` and `perm_epoch` handling in the filter and the freshness service, the mint and refresh paths, and the actuator gate.
- **Cryptography:** k6 `runPassword()` uses the `k6/crypto` CSPRNG. No other crypto changed.
- **PII handling:** new log lines, metric tags, k6 console output, and audit fields.

The findings are below.

---

## Verification run

| What | Result |
|---|---|
| `sh ./mvnw -o -q test -Dtest=SecurityConfigWebTest,EndpointClassificationWebTest,PermissionFreshnessServiceTest,EpochReplayQueueTest,RoleReplayQueueTest,JwtAuthenticationFilterTest,RedisAuthStartupAssertionTest` | **All green.** SecurityConfigWebTest 17, EndpointClassificationWebTest 165 dynamic cases (the `.txt` summary shows 0 because they are dynamic; the XML has 165, 0 failures), PermissionFreshnessServiceTest 201, EpochReplayQueueTest 28, RoleReplayQueueTest 18, JwtAuthenticationFilterTest 19, RedisAuthStartupAssertionTest 20 with **0 skipped**. That confirms the prod-profile `require-auth` test (`should_resolveRequireAuthTrue_when_prodProfileActive`) is enabled and passes. The `0ec0ec1` message says it was never run. It now has been. |
| Integration tests (`TokenFreshnessIT`, `RedisPermissionEpochAdapterIT`, `AuthenticatedRedisIT`, `RefreshFailureThrottleIT`) | **Not run: Docker is not available.** I have not verified any Redis-backed behaviour against a real Redis, and in particular not OOM under `noeviction` or `READONLY` replies. |
| `./mvnw dependency:tree` | Ran (online; offline lacks the plugin), 198 lines. **No `pom.xml` change on the branch.** OWASP dependency-check (`-Psecurity`) was **not run**: it needs the NVD feed, so the backend CVE status is unverified here. |
| `npm audit --omit=dev` (nexus-frontend) | 7 runtime findings: 1 high (`@angular/router`, transitive via `@angular/common` and `@angular/core`) and 6 moderate (Angular sanitization bypass via host bindings; `HttpTransferCache` leak). **Pre-existing:** no `package.json` or lock change in `nexus-frontend` on this branch. Ticket the Angular bump separately. |
| Hand checks | Firewall defaults: no custom `HttpFirewall`, so `StrictHttpFirewall` applies. `EndpointRequest` path coverage. No `X-Forwarded-*` reads anywhere in `src/main`. Committed credentials in `nexus-test`: none. `UNSCOPED_ALLOWLIST`: unchanged on the branch. |

---

## Findings

```
[MEDIUM] RR-M1 M-1 is fixed per instance only: while Redis answers reads but refuses or loses a
bump, every instance other than the one that issued it accepts the revoked token, and for a
detach re-mints the detached permission from the cache
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java:553-563
        (Healthy/Recovering verdict: store value plus THIS instance's lastSeen/marker only)
      PermissionFreshnessService.java:454-467 (mintEpoch: verified unless THIS instance has a marker)
      PermissionFreshnessService.java:998-1004, 1085-1106 (failed bump: local entry + local replay queue)
      nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java:120-125
      nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java:64-69
      nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java:379-383 (detach: no evict besides the bump)
      docs/adr/0022-permission-token-freshness.md:159 ("This closes the case where Redis refuses writes...")
Issue: The 07b7626 fix keeps the failed-bump knowledge (seen+1, the iat marker and the replay
       queue) in the memory of the instance that ran the post-commit bump. On that instance (A),
       the fix works in every state: Healthy/Recovering via staleByLocalKnowledge, Degraded-open
       and single read failures via unverified(), Degraded-closed via 503. Mints there are
       unverified, so permissions come uncached. I traced users A had never seen: entry {1,
       marker} is created, the first read merges E_old and keeps the marker because
       E_old < failedAt ms, and the old token is STALE by iat. I also traced the store-regressed
       case (known > read).
       Instance B (any other pod behind the load balancer; deployment.md:114, design §9.6) has
       none of this. With reads working, B's verdict is `tokenEpoch < current`, and current is
       the pre-revocation E_old:
       - revoke: the target's pre-revocation token is FRESH on B (its role claims are stale);
       - detach: the holder's token is FRESH on B. Worse, a refresh routed to B gets a verified
         mint with E_old. RoleResolutionService then hits permset:{t}:{u}:{E_old}, because the
         bump script that deletes it never ran and the role set (the only fingerprint) is
         unchanged. B mints a NEW token with the detached permission, an iat after the failure,
         and epoch E_old. That token is FRESH on B and also on A: iat > marker, and the epoch
         equals A's known epoch.
       The trigger is the same as in the original M-1: maxmemory under the mandated noeviction
       (writes refused, GET served), a 500 ms bump timeout on a slow Redis, or a READONLY
       replica. RC-53 deliberately keeps write failures out of the state machine, so every
       instance stays Healthy. A's restart also loses the marker and the queue (RES-31).
       The design text (§9.5 "another instance ... about one probe interval") covers only the
       degraded-recovery case. The ADR D1 amendment claims the write-refusal case is closed.
       With N instances it is closed for 1/N of requests.
Risk: A revoked or detached user keeps the removed access on (N-1)/N of requests for as long as
      writes are refused. The bound is the cache entry's remaining TTL (up to 900 s from its put)
      plus the access-token TTL (900 s), so about 30 minutes, with every instance reporting
      Healthy. Only bump_failed pages. This is the T-E38 shape again, and an insider who knows a
      revocation is coming benefits. OWASP A01, A04.
Fix: Pick one, and record it in ADR-0022 D1 and the threat model:
     (a) Make write refusal visible to every instance. Add a write canary to probe(): a
         PX-bounded SET on a per-instance key through the bump factory, every tick. On N
         consecutive write failures, treat the store as unverifiable on that instance: degraded-
         open semantics for check(), and verified=false for mintEpoch(), so no cache reads. That
         puts write refusal under the existing time box (fail-open window, then 503) and the
         existing pages, on every instance, not only the one that bumped.
     (b) In addition, for the detach re-mint: on a failed bump, GET each user's epoch and issue a
         plain DEL of permset/roleset under it. DEL is not refused under noeviction OOM. A
         successful DEL forces B's next mint to the database.
     (c) Or accept explicitly: a RES entry with a named owner, ADR D1 reworded to "closed on the
         issuing instance; other instances bounded by cache TTL plus token TTL", and bump_failed
         {reason=redis} on the immediate page list.
     Tests: a two-service-instance unit test sharing one fake store (bump refused on A, read on
     B) asserting the chosen behaviour, and the B-side refresh not carrying the detached
     permission.
```

```
[MEDIUM] RR-M2 Metrics gated on TENANT_ADMIN: a tenant-scoped role now reads platform-wide
metrics, including other tenants' ids and security events
File: nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java:99-100
      nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:394-399
        (nexus.rbac.self_role_assignment{tenantId, privileged, callerIsAdmin})
      nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java:287-292
        (nexus.rbac.dangerous_permission_granted{permission, tenantId, holders})
      docs/features/US-018/runbook.md:147, deployment.md:98 ("scrape with a token of a tenant administrator")
Issue: The path coverage of the gate is sound (see focus area 3). But TENANT_ADMIN is a
       per-tenant customer role. /actuator/prometheus and /actuator/metrics/{name}?tag=tenantId:...
       are platform-wide. Two pre-existing counters carry a tenantId tag, so every tenant's
       administrator can list other tenants' UUIDs and see which tenants had self-role
       assignments or dangerous-permission grants, and how often. They can also read the
       degraded state, drop counters and replay queue depth that L-3 meant to hide. The runbook
       also tells operators to scrape with a tenant administrator's token. That puts a
       high-privilege customer credential (with a 14-day refresh family) into the monitoring
       stack.
       Before this commit every authenticated user could read the same data, so this narrows
       the exposure. It does not close the cross-tenant part.
Risk: Cross-tenant enumeration and security-posture disclosure to any tenant's administrator,
      and timing of the fail-open window by that administrator. OWASP A01 (cross-tenant), A05.
Fix: Do not authorize platform telemetry with a tenant role. Use one of:
     - management.server.port on a separate port that the ingress does not route, plus a
       NetworkPolicy limited to the scraper (preferred);
     - a platform-operator authority that no tenant role can hold.
     Then deny both endpoints on the public chain (denyAll). Update runbook §10 and deployment.md
     so no tenant credential is used for scraping. Independently, drop the tenantId tag from the
     two counters (the WARN logs already carry the tenant), to keep metric-tag cardinality and
     disclosure bounded.
```

```
[MEDIUM, carried / pre-existing, not counted towards this verdict] RR-M3 forward-headers-strategy
none is spoof-proof but, in the repository's own nginx topology, makes every per-IP bucket
platform-wide, so an anonymous client blocks all logins with 10 requests a minute
File: nexus-backend/src/main/resources/application.yml:72-78
      nexus-frontend/nginx.conf:37-49 (proxy_pass to backend:1000, X-Forwarded-For appended)
      nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/LoginRateLimitFilter.java:120, 153
      nexus-backend/src/main/resources/application.yml:243-251 (ip 10/60 s, refresh 300/60 s, forgot 10, reset 20)
Issue: `none` is the correct choice against XFF spoofing. No code reads X-Forwarded-For (I
       grepped all of src/main), and Tomcat no longer rewrites getRemoteAddr(). But the shipped
       nginx proxies /api/ to the backend, so getRemoteAddr() is nginx for every client. The
       login IP bucket (10 a minute), forgot (10), reset (20) and refresh (300, RES-40) are then
       platform-wide. Without the explicit `none`, Spring Boot would have chosen NATIVE under
       Kubernetes. Behind nginx's $proxy_add_x_forwarded_for, NATIVE gives per-client keys that
       a public client cannot spoof (RemoteIpValve takes the rightmost untrusted hop). DF-1
       already documents the platform-wide behaviour, and LoginRateLimitFilter's own precondition
       ("single instance, direct client TCP") is contradicted by nginx.conf.
       Side effects under `none` behind a proxy:
       - auth_events.ip records the proxy address, so audit attribution is lost (A09);
       - Spring's HSTS writer never fires, because isSecure() is false. nginx.conf sets no HSTS
         either, so HSTS depends on the outer LB.
Risk: Unauthenticated, cheap, platform-wide denial of login (and of password reset and
      refresh). OWASP A04, A07.
Fix: For the nginx or ingress topology, set `native` and pin
     server.tomcat.remoteip.internal-proxies to the nginx/ingress addresses only, plus
     remoteip.protocol-header. Re-run the DF-1 k6 gates, and bound rate-limit key cardinality.
     If `none` stays, the DF-1 owner must re-confirm the acceptance with the login figure
     (10 a minute, platform-wide) stated.
```

```
[LOW] RR-L1 The failed-bump marker is cleared by comparing a Redis-time epoch with the instance
clock
File: PermissionFreshnessService.java:856-860 (keep marker iff fresh.epoch < failedBumpAt.toEpochMilli())
      PermissionFreshnessService.java:998-1004 (failedBumpAt = instance clock)
Issue: Epochs are max(old+1, Redis TIME ms). The marker is the instance's Instant. Two cases:
       - Redis is ahead of the instance by d, or the user's epoch is already above wall-clock
         time (after a Redis clock jump the script stays in the old+1 regime). Then the first
         successful read returns E_old >= failedAt ms and clears the marker. For a user this
         instance had not seen, the entry then holds only E_old, and the revoked token
         (epoch E_old) is FRESH again on A as well. That reopens M-1 for unseen users.
       - The instance is ahead. A successful replay writes E_new < failedAt ms and the marker
         survives. This is harmless for tokens (only pre-failure iats are refused), but mints
         stay unverified and uncached for the key TTL.
       This also reintroduces an instance clock into the epoch decision, which H-2 removed. On
       lockout: a token is refused only if iat <= the failure second. A legitimate token minted
       after the failure is refused only when it is minted in that same second, or on another
       instance whose clock lags A's by s seconds within s seconds. The SPA then shows one error
       after its single retry. No logout and no loop. An attacker cannot set or clear the marker:
       it is set only by an admin's revoke or detach, and cleared only by a store value that
       only a real bump can write.
Risk: Under app-to-Redis clock skew (NTP is mandated but not checked), the M-1 fix silently does
      nothing for unseen users. OWASP A04.
Fix: Clear the marker only when this instance's own bump or replay of that user succeeds
     (rememberBump for that key), or when a read returns an epoch strictly greater than the
     first value read after the failure. Both are clock-independent. Add a test with Redis time
     ahead of the instance clock.
```

```
[LOW] RR-L2 A failed bump that the own-bump pool refuses leaves no local trace in Healthy or
Recovering
File: PermissionFreshnessService.java:840-844, 865-869 (claim refused, then markRevocationLost)
      PermissionFreshnessService.java:594-600 (revocationLost is consulted only on the unverified path)
      PermissionFreshnessService.java:553-563 (the Healthy verdict ignores revocationLost)
Issue: rememberFailedBump creates a new own-bump entry. If the tenant is at its ceiling (40,000
       at 10%), or all tenants together are at 200,000, the entry and its iat marker are not
       stored, and only the tenant is marked lost. markRevocationLost is read only when the
       store cannot answer. With reads working and writes refused, that user's revoked token is
       FRESH even on the issuing instance. Another tenant can trigger this: five tenants at
       their ceiling fill the global pool.
Risk: The M-1 fix is skipped for large fan-outs or a saturated pool. It needs tens of thousands
      of tenant-admin bumps within one key TTL. OWASP A04.
Fix: When rememberFailedBump's entry is refused, record a tenant-level failed-bump instant
     (bounded, like lostRevocations). In evaluate() for Healthy and Recovering, treat that
     tenant's tokens with iat <= the instant as STALE until the tenant's replay entries drain.
     The tenant then refreshes once (fail-safe).
```

```
[LOW] RR-L3 The k6 write guard accepts non-local targets
File: nexus-test/performance-test/utils/write-scenario.js:12-19
Issue: isDisposableHost treats any host without a dot as disposable. That includes Kubernetes
       short service names (http://nexus-backend:1000 from a pod in a staging or prod
       namespace), /etc/hosts aliases such as `staging`, and docker names. It also takes the
       host before the first ':' of the authority, so http://localhost:1@shared.example.com
       passes, and /^127\./ accepts http://127.example.com. On the positive side: no committed
       credential remains (I grepped nexus-test), the per-run password comes from k6/crypto
       randomBytes and is never logged, the guard runs before any write in both seed
       functions, and the storm's setup now revokes assignments when it aborts.
Risk: An accidental run against a shared environment leaves verified accounts. Their password
      is unknown, so it is clutter, not access. OWASP A05 (hygiene).
Fix: Parse with a URL parser and reject any userinfo. Accept only `localhost`, 127.0.0.0/8,
     [::1] and an explicit allowlist from an env var (for example WRITE_SCENARIO_HOSTS), not
     every dotless name.
```

### Informational

- **RES-31 wording.** The text says that a tenant over its share "overflows that tenant", but a tenant under its share also overflows once the queue is full. The arithmetic is in focus area 4. Reword RES-31 to "floor = min(share, capacity − size)".
- **`check(tenant, user, epoch)` overload** (`PermissionFreshnessService.java:501-503`) passes `iat = Long.MAX_VALUE`, which silently disables the marker. Only tests call it today. Consider removing it from the public API, or naming it so a future caller cannot pick it up by accident.
- **Hook guard.** `origin/main` carries the owner's commit `19f4c7c`, which comments out the `application-prod.*` write guard. `bf74776` restores it, so merging this branch re-enables it. If the branch is squashed or reverted, check that the guard survives.
- **Holder query** `JpaUserRoleRepository.java:308-309` is still unscoped. It is unchanged, and the assessment in `12` (not exploitable) still holds: the role is resolved in `actor.tenantId()` before the read, and the replay reuses that pair.
- **SECURITY.md §9** says nginx "implements the non-CSP/HSTS subset", but `nginx.conf:26` does set a CSP. The documentation is stale, and HSTS is absent from both nginx and the application (RR-M3).

---

## Focus areas (re-derived from code)

### 1. Q1: accepting a revoked or detached token while reads work and a bump is refused, timed out or lost

| Situation | Issuing instance A | Any other instance B |
|---|---|---|
| Healthy/Recovering, read OK, user seen by A | STALE (`tokenEpoch < known`) | **FRESH** (RR-M1) |
| Healthy/Recovering, read OK, user never seen by A | STALE by `iat <= marker`; clock caveat RR-L1; pool-refusal caveat RR-L2 | **FRESH** (RR-M1) |
| Key lost after a successful bump (store below known) | STALE; `store_regressed` counted; mint uses the local bound, unverified | FRESH (RES-31, accepted) |
| Single read failure in Healthy | `unverified`: local bound, marker, `revocationLost` | SKIPPED_ERROR (accepted per-request fail-open) |
| Degraded-open | Same as the row above | SKIPPED_DEGRADED (RES-30, time-boxed) |
| Degraded-closed | 503 | 503 |
| Mint or refresh | Unverified; permissions from the database; new token FRESH (iat after the marker) | **Verified E_old; cache hit re-mints the detached permission** (RR-M1) |
| Bump timed out but applied | Marker kept (E_new < failedAt ms); the replay re-bumps; one extra refresh | FRESH for new tokens (correct) |
| A restarts | Marker and queue lost (RES-31) | — |

A queued replay keeps A in a degraded state while writes stay refused. A then reaches Degraded-closed (503) 15 minutes after `t0`. That fails safe, but costs availability. This is pre-existing design.

### 2. Q2: the iat marker

- **Lockout.** No lockout is possible beyond one refusal in the failure second, or a few seconds of inter-instance clock lag. Only tokens with `iat <= the failure second` are refused, and those are the tokens being revoked.
- **Early clearing.** An attacker cannot clear the marker early. Only a store value of at least the failure millisecond clears it, and only Redis bumps (admin revoke or detach, or replay) can write one. Unparseable values throw. The weakness is clock-based (RR-L1), not something an attacker can trigger.
- **iat itself.** `iat` comes from the RS256-verified token in seconds (`JwtRs256Service.java:242`), so it cannot be forged.

### 3. Q3: actuator path variants

- **`EndpointRequest.to("prometheus","metrics")`** matches `/actuator/{id}` and `/actuator/{id}/**` for every HTTP method. It follows `management.endpoints.web.base-path`, so `/actuator/prometheus/`, `/actuator/prometheus/x` and `/actuator/metrics/{name}` are covered. Tests for those cases exist and pass.
- **Encoded and malformed variants.** Spring Security's default `StrictHttpFirewall` is in force: no custom firewall is configured. It rejects `;` path parameters, `%2F`/`%5C`/`%2E`/`%25` encodings, `//`, `/./` and `/../` with a 400 before any authorization runs.
- **Case and suffixes.** Upper-case variants and suffixes (`.txt`) are not mapped by MVC, which is case-sensitive and has no suffix matching. They fall to `anyRequest().authenticated()` and then a 404.
- **Other servlets and ports.** There is no other servlet and no `management.server.port`.
- **ERROR dispatch.** Spring Security 7 authorizes the ERROR dispatch as well.
- **Conclusion.** I found **no path** by which a non-TENANT_ADMIN reads these endpoints. I verified the encoded and path-parameter variants by reading the code, not by test. The issue is who passes the gate (RR-M2), not whether it can be bypassed.

### 4. Q4: replay-queue shares, quantified (defaults)

**User queue** (`EpochReplayQueue.java:68, 86`): capacity C = 100,000, share S = 10,000, borrow limit B = 50,000. A new user is admitted iff `size < C` and (`tenantQueued < S` or `size < B`).
- One tenant alone can hold at most B = 50,000, plus up to one in-flight batch (500) during a failing drain.
- Another tenant then still gets min(S, C − size) = 10,000 users. So **a single tenant cannot drop another tenant's revocation of up to 10,000 users**. It can only cut that tenant's headroom from 50,000 to 10,000.
- A victim's first user is dropped only when the queue is full. That takes one borrowing tenant at 50,000 plus five tenants at 10,000 each (or ten tenants at their share). That means six or more independent mass revocations during the same write outage, on the same instance, within 960 s, and each drop pages `overflow`.

**Role queue** (`RoleReplayQueue.java:57, 79`): C = 1,000, S = 100, B = 500. A tenant has at most 500 roles, so one tenant can hold at most 500. A victim's floor is 100 roles. Filling the queue needs one borrowing tenant plus five at their share.

Polling is FIFO per tenant. Batches are single-tenant, and keys come from the queued tenant id, so cross-tenant replay is not possible. Memory is bounded: `requeue` overshoots by at most one batch or one role.

### 5. Q5: `forward-headers-strategy: none`

Correct against spoofing, and no code reads `X-Forwarded-*`. It is the wrong trade-off for the nginx topology the repository ships: see RR-M3.

### 6. Q6: k6

- **Credentials.** No committed credential remains. The admin credentials come from the environment, and the per-run password is random.
- **Guard.** Both write seeds call the guard first. Non-local targets slip through by dotless name, userinfo or a `127.` prefix (RR-L3).
- **Other scripts.** The read-only scripts (`epoch-check-latency`, `rbac-read`) only log in.

### 7. Q7: tenant isolation

- **Redis keys** (`RbacRedisKeys`): `{prefix}:rbac:{epoch|roleset|permset}:{tenantId}:{userId}[:{epoch}]`, built only from typed UUIDs.
- **Tenant source.** The tenant comes from the verified token (filter), `actor.tenantId()` (bumps), `user.getTenantId()` (mint), or the queued tenant of an already-resolved role.
- **In-memory structures.** `lastSeen`, the markers, `lostRevocations` and both queues are keyed by tenant.
- **Holder query.** Unscoped and unchanged (Informational). `UNSCOPED_ALLOWLIST` is unchanged.
- **Cross-tenant gap.** The one cross-tenant gap found is in telemetry (RR-M2).

### 8. Q8: PII and token material

- **New code.** No new log line in the reviewed commits. `store_regressed` has no tags. The queues do not log.
- **Interceptor.** `auth.interceptor.ts` now matches whole path segments: `/apiary` no longer gets the bearer, and the strict origin check is kept. A spec covers it.
- **k6.** `console.log` prints counts and a timestamp only.
- **Pre-existing.** The `tenantId` metric tags (RR-M2), the `userId`/`tenantId` MDC entries, and the IP in `auth_events` (audit by design; under RR-M3 it is the proxy address).
- **Tokens, emails, epochs.** No token, email or epoch value appears in any log, tag or audit field.

---

## Threat-model cross-reference (items marked mitigated or required)

| Threat / RC | Status in model | Mitigation visible in code |
|---|---|---|
| M7 **S**: stale permissions under a fresh epoch (MC-7a/7b, Decision 17) | ✅ mitigated | **Yes, with a gap.** Epoch is read before resolve (`JwtRs256Service.java:120-125`); bumps run after commit; the cache is keyed by epoch; unverified mints skip the cache. **Gap:** when the bump is refused, the old-epoch permset is not deleted, and other instances' verified mints re-read it (RR-M1). |
| T-E38 / RC-30, T-E44 / RC-42: lost-bump replay | required | **Yes.** Replay every tick in every state, role replay, per-tenant shares and the borrow limit (focus area 4). **M-1 of 12 is closed on the issuing instance only** (RR-M1, RR-L1, RR-L2). |
| ADR-0022 D1 amendment (M-1): "closes the case where Redis refuses writes" | claimed | **Partly.** Closed on one instance of N (RR-M1). |
| T-T16 / RC-34, RC-45.1: Redis auth in prod | required | **Yes.** `application-prod.yml:31-36` `require-auth: true`; the prod-profile test is enabled and passes (I ran it). `require-shared-store` is deferred to M8, as RC-45(b) rules. |
| L-3 of 12: metrics readable by any user | required | **Path coverage yes; authorization model no** (RR-M2). |
| L-2 of 12 / RES-31: per-tenant queue share | required | **Yes**, quantified in focus area 4; RES-31 wording to be corrected (Informational). |
| L-4 of 12: k6 credentials and guard | required | **Credentials yes; guard partial** (RR-L3). |
| L-5 of 12: SPA prefix | required | **Yes.** |
| L-6 of 12 / DF-1, T-1.3: getRemoteAddr only | required | **Yes for T-1.3** (no XFF read, `none` set). **DF-1 consequence open** (RR-M3). |
| T-D20 / RC-31, RC-53: state machine | ✅ mitigated | **Yes.** Only read and probe failures count; mint reads never count; an unauthenticated caller cannot move it (the check runs after RS256 verification on non-public paths only). |
| T-E37 / RC-29: key TTL | required | **Yes**, unchanged since `12`: `EpochRedisConfig` asserts `key-ttl >= 960`. |

## OWASP Top 10 (SECURITY.md §12)

- **A01 Broken Access Control:**
  - RR-M1: revocation on other instances.
  - RR-M2: cross-tenant metrics.
  - Default-deny is intact, with no IDOR on new paths, and tenant ids come from the token.
- **A02 Cryptographic Failures:** no change to JWT or encryption. The k6 password uses a CSPRNG.
- **A03 Injection:** none. Redis keys are typed UUIDs; scripts take keys and stems as KEYS and ARGV; no request string reaches a key, script or query.
- **A04 Insecure Design:** RR-M1, RR-M3, RR-L1, RR-L2.
- **A05 Security Misconfiguration:**
  - RR-M2.
  - RR-M3 side effects: HSTS and audit IP.
  - RR-L3.
  - Prod disables springdoc and health details.
- **A06 Vulnerable Components:** the backend tree is unchanged, and OWASP dependency-check was not run. The npm runtime findings (1 high, 6 moderate) are pre-existing.
- **A07 Identification & Authentication Failures:** RR-M3 (platform-wide login bucket). Refresh reuse detection is unchanged and cannot be suppressed.
- **A08 Software & Data Integrity Failures:** none. The hook guard is restored.
- **A09 Security Logging & Monitoring Failures:** `store_regressed` was added (put it on the §9.9 page list). Write refusal pages only via `bump_failed` (RR-M1). The audit IP is the proxy's (RR-M3).
- **A10 SSRF:** none. There are no outbound URLs from user input.

## Summary

| Severity | Count | Items |
|---|---|---|
| Blocker | 0 | — |
| High | 0 | — |
| Medium | 2 (+1 carried) | RR-M1: M-1 closed per instance only. RR-M2: metrics gated on a tenant role, cross-tenant disclosure. RR-M3 (carried, pre-existing DF-1): platform-wide per-IP buckets behind nginx |
| Low | 3 | RR-L1: marker clock comparison. RR-L2: refused own-bump entry has no Healthy-path effect. RR-L3: k6 host guard |

**Verdict: BLOCKED.** RR-M1 and RR-M2 must each be fixed, or accepted with a named owner and the ADR-0022 D1 and runbook text corrected, before merge. Once both are done the verdict is **APPROVED**. RR-M3 needs the DF-1 owner to re-confirm or switch to `native` with pinned proxies, and is not attributable to this branch. RR-L1 to RR-L3 can be ticketed.

**Not verified:**
- Any Redis-backed integration test, including OOM, `READONLY` and timeout behaviour (no Docker).
- Backend CVEs (dependency-check not run).
- The production ingress and Kubernetes manifests: none are in the repository, so the real proxy chain, any `SERVER_FORWARD_HEADERS_STRATEGY` override and the scrape path are unknown.

---

## Resolution of RR-M1 and RR-M2 (after this review, 2026-10-09)

Not re-reviewed; run `/security-review` again before relying on this.

**RR-M1: partly closed; the rest is recorded as RES-46 and needs a named owner.**
- **Closed:** a failed bump now evicts the affected users' cached permission sets (`PermissionFreshnessService.evictCachedSets`, a plain `DEL` under the user's current epoch, which `noeviction` does not refuse). So another instance can no longer re-mint a detached permission from the cache while the epoch is unchanged. `FailedBumpCacheEvictionTest` runs two instances over one shared fake store and cache: with the eviction, instance B resolves from the database; without it (control test), B re-mints the detached permission.
- **Not closed:** a token already issued stays valid on the other instances for at most the access-token TTL (900 s) while Redis refuses writes, and every instance reports Healthy. The reviewer's option (a), a per-instance write canary that puts write refusal under the fail-open window, was **not built**: it would turn a Redis out-of-memory condition into a platform-wide 503 after 15 minutes, which is an availability decision for SRE and PM. `bump_failed{reason=redis}` pages immediately.
- A narrow race remains: a mint that resolved from the database before the detach committed could put its stale set after the eviction. It lasts at most the cache TTL.
- Docs: ADR-0022 Revision 4 (D1 clarified, no longer claims the case is closed), RES-46 in the threat model, the runbook.

**RR-M2: closed.** `ScrapeTokenFilter` (new) accepts only the operator's `nexus.management.scrape-token` as a bearer token on the Prometheus and metrics endpoints; a tenant administrator's JWT is a 401, the endpoints are closed when the token is unset, and a token shorter than 32 characters fails startup. `JwtAuthenticationFilter` skips a request the scrape filter handled. k6 scrapes use `SCRAPE_TOKEN`. Runbook section 10 and `deployment.md` no longer say to scrape with a tenant credential. **Not done:** dropping the two `tenantId` metric tags. Only operators can read the metrics now, and `RoleAssignmentEscalationIT` scopes its counters by that tag.

**RR-M3 (existed before this branch): not changed.** It needs the DF-1 owner to decide between `none` (platform-wide per-IP limits behind nginx) and `native` with pinned `internal-proxies`.

**RR-L1 to RR-L3: not changed.**

