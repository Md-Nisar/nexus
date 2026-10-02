# ADR 0022 — Permission Token Freshness: Per-User Epoch, Epoch-Keyed Permission Cache, and Token Version Policy

**Status:** Proposed (Revision 1: threat-model RC-24, RC-29 to RC-32, RC-34 and RC-40.1/.6 folded in, 2026-09-26; Revision 2: delta review RC-41 to RC-45 folded in, 2026-09-30; Revision 3: spot-check RC-51 to RC-53 folded in, 2026-10-01)
**Date:** 2026-09-26
**Feature:** EPIC-002 (RBAC Foundation), US-018 milestones M6 (A11) and M7 (A9, A10); B6's decision rule
**Supersedes in part:** ADR-0013 D1 (no per-request RBAC state) and D4 (accept cache lag); ADR-0016 D3 (the permission-cache key row), D4 (the RBAC-cache row, plus a new capability row), D5 (the "no bulk invalidation" non-goal)
**Related:** `docs/features/US-018/03-design.md` §8, §9; ADR-0007, ADR-0008

---

## Context

Access tokens are stateless RS256 JWTs with a 900 s TTL that carry `permissions[]` (ADR-0013 D1). A revoked role or a detached permission therefore kept working for up to 15 minutes from the token, plus up to 15 minutes from the Redis permission cache, which is fingerprinted on role names only and so does not notice a role's own permissions changing. Gate 1 fixed three things: the revocation marker is per user; a Redis outage is a time-boxed fail-open with an alert; and there are no new feature flags. The impact analysis showed that an epoch alone fails open, because the refreshed token is minted from the stale cache.

## Decision

### D1 — A per-user epoch claim, not a revoked-before timestamp

- Redis key `nexus:rbac:epoch:{tenantId}:{userId}` holds a millisecond value.
- A bump sets it to `max(old + 1, Redis TIME)` in one Lua script. The value is monotonic across app instances and survives key loss.
- **The key's TTL is `max(access-token TTL, permission-cache TTL) + margin`, with margin ≥ 60 s** (960 s today; revised in Revision 1, RC-29). The earlier "token TTL + 2 × skew" gave 900 s, because `AUTH_CLOCK_SKEW_SECONDS` is 0, which equals the cache TTL: zero margin. A stale cache entry written under the old epoch by a racing mint could then outlive the key, and mints in that gap would read epoch 0, hit it, and be accepted as fresh. The key must outlive every token **and** every cache entry that could carry an older epoch. Startup fails if the configured TTL does not exceed both the access-token TTL and the permission-cache TTL. An absent key reads as 0, meaning "no revocation".
- Access tokens carry `perm_epoch`, the value read at mint. A request is rejected with **401 `AUTH_003`** iff `perm_epoch < current`.
- `JwtClaims.CURRENT_VERSION` goes from 2 to 3.

Comparing a revoked-before timestamp with the existing `iat` was rejected. `iat` has one-second granularity, so either every token minted in the revocation second is rejected, including the refreshed one (logging users out on every change), or a token minted before commit in that second survives with stale permissions. Fixing either needs a sub-second claim.

### D2 — Ordering

- **Mint** reads the epoch **before** resolving permissions. A bump that lands between the two reads yields an old epoch with new permissions, which is rejected once (safe). The reverse order would accept stale permissions under a new epoch.
- **Bumps** happen only after commit.

### D3 — Triggers

- **Revoke** bumps the target user.
- **Detach** bumps every active holder, read after commit.
- **Assign, attach and role rename** do not bump. They only add permissions, and a token that lacks a new permission is fail-safe. This deviates from the story's AC text on purpose, and halves the refresh-storm exposure.
- **Lost bumps are replayed (revised, Revision 1, RC-30; Revision 2, RC-42).** A bump that fails after commit is counted, paged (it does not drive the D5 state machine; Revision 3, RC-53), and enqueued as `(tenantId, userIds, failedAt)` in a **bounded per-instance replay queue**.
  - The queue **coalesces by `(tenantId, userId)`**, keeping the oldest `failedAt`, so capacity counts distinct users.
  - **Overflow drops the newest:** arriving ids beyond capacity are rejected, and `bump_failed{reason="overflow"}` is incremented by the number dropped, which pages.
  - A scheduled 1 s task **drains a non-empty queue in every state, Healthy included**, off the request thread (in the degraded states, after that tick's probe succeeds). A single failed bump on a Healthy instance is therefore replayed within about a second instead of waiting for a degraded episode. A drain that fails partway re-enqueues the unreplayed remainder with its original `failedAt`.
  - The bump and its replay run on their own bounded timeout (500 ms per script call, sized for a 500-user batch), never on the 50 ms epoch-read factory (D5).
  - Replaying late is safe because the bump is monotonic and also evicts the old-epoch cache entry. Entries older than the key TTL are dropped, because their tokens have expired. Without replay, a lost bump would leave the revoked permission live for up to token TTL plus cache TTL **after Redis recovers**, and the administrator who revoked would not know. The queue is lost on instance restart, and a bump lost to async replication at a Sentinel failover is silent (RES-31, Low).

### D4 — The permission cache is keyed by epoch, and holders are evicted (A10)

- The key becomes `nexus:rbac:permset:{tenantId}:{userId}:{epoch}`.
- The bump script also deletes the entry under the old epoch, which is the per-holder eviction.
- Eviction alone is racy: a mint that read pre-commit permissions can write them back after the eviction. The epoch in the key makes that stale write unreachable by any later mint.
- Fan-out runs in batches of 500 users per script, pipelined, after commit, with **no cap** (a cap would silently leave holders unrevoked). Fan-outs above 1,000 holders are logged and bucketed.
- The role-name fingerprint is kept, because it covers assign and revoke.

### D5 — Failure policy

- A dedicated Redis connection factory with a **50 ms** command timeout serves epoch reads. The 2 s platform default must not apply on the hot path. A second dedicated factory, with a **500 ms** command timeout, serves the bump and its replay (Revision 2, RC-42.2). **Both are built from the same `spring.data.redis.*` properties as the main factory** (password, ACL username, SSL); only the timeout differs, and the startup assertion covers them (Revision 2, RC-45.2).
- **Public endpoints are exempt (Revision 1, RC-24).** The SPA attaches the current, possibly stale or expired, bearer to `POST /auth/refresh` and `/auth/logout`, and the filter verifies any bearer on any path. So on requests to `@PublicEndpoint` handlers the filter **never rejects**: no epoch check, no 503, and a bearer that fails verification is ignored (the request proceeds as anonymous). A bearer that verifies still sets the principal, because logout uses it to revoke every refresh family of a caller who has no cookie; skipping all bearer processing, which Security preferred, would silently drop that path. The exempt set is derived from the `@PublicEndpoint` markers, the same source the A8 classification test enumerates, never from a literal path list.
  - **Fail closed and permission-free (Revision 2, RC-44).** The matcher matches **HTTP method and pattern** using MVC's own path parsing, and any exception or ambiguity counts as **non-public**. On a public request the verified principal carries an **empty** `PERMISSIONS` detail and no authorities, so an epoch-unchecked token can never satisfy `@RequiresPermission`, even if a request is misclassified. Logout needs only the user id. Without this rule every revoke or detach would log affected holders out, degraded-closed would block refresh for everyone, and a logout with a stale bearer would skip server-side revocation.
- **Entry (revised, RC-31; Revision 2, RC-41).** A single failed or slow read fails open for that request only, and is counted. **3 or more failures within a 10 s sliding window** move the instance to **degraded-open**, with `t0` set at the first failure in that window: the epoch check is skipped, and a scheduled prober tries Redis once per second. "3 consecutive" (Revision 1) never tripped on an intermittent F F S pattern, which left per-request fail-open with no time box (T-E43).
  - **Only read-path failures count (Revision 3, RC-53; T-E47).** Only failures of the epoch read and of the probe count towards the 3-in-10 s entry and relapse window. Bump and drain failures keep their entries queued and page through `bump_failed`, but do not by themselves move the instance out of Healthy or Recovering, so a write-only Redis failure (OOM under `noeviction`, a read-only replica) cannot switch off epoch checks that reads can still enforce. The "replay queue drained" exit condition is unchanged.
  - **Scheduling (Revision 3, RC-52).** The 1 s probe-and-drain task is enabled by its own unconditional scheduling configuration, not by the audit retry buffer's `SchedulingConfig`, which is conditional on `nexus.identity.audit.retry-buffer.enabled`.
- **Recovery (revised, RC-31; Revision 2, RC-41).** The first successful probe drains the replay queue (D3) and moves the instance to *recovering*, where checks resume. The window's start `t0` is cleared only after **60 s** of consecutive successes, so a flapping Redis does not restart the window. A relapse from *recovering* uses the same 3-in-10 s rule. Three entries into degraded-open within 15 minutes page as flapping.
- After **15 minutes** from `t0` (the access-token TTL, so the exposure never exceeds the baseline ADR-0008 and ADR-0013 already accept) the instance moves to **degraded-closed**: non-public authenticated requests get **503 `AUTH_005`** with `Retry-After`.
  - A 401 there would put every client into a refresh loop and log users out platform-wide.
  - Login, refresh and logout are unaffected, **because of the public-endpoint exemption above**.
  - With the replay queue, a revocation made during the outage is applied on recovery, so the 503 does buy a revocation guarantee rather than only availability loss.
- **Paging (reconciled, RC-31.3):** page when degraded-open lasts more than 1 minute, not on entry; page (critical) on degraded-closed; page on flapping; **page when `skipped_error` exceeds 1% of checks for 5 minutes on an instance**, and **ticket when *recovering* lasts more than 10 minutes** (Revision 2, RC-41.2). A Redis latency early-warning ticket fires at epoch-check p99 > 25 ms for 5 minutes.
- State is per instance. **Pod restarts reset it**, including the runbook's own "raise the window, then rolling restart"; that is accepted because per-revocation exposure is bounded by token TTL plus cache TTL regardless.
- **A Redis outage longer than the window is a platform-wide authenticated 503** (RES-30). Owners SRE (Redis capacity) and PM; **acceptance pending at Gate 2** as an SLO item, not yet recorded. Redis capacity is part of the M7 runbook.
- The window is extended by configuration and a restart. There is deliberately no runtime toggle endpoint.
- Mint during an outage embeds 0.
- Readiness stays blind to Redis.

### D6 — Latency budget

The epoch check must stay **≤ 2 ms p95** at 200 RPS, within EPIC-002's < 5 ms p95 RBAC overhead. This is benchmarked before merge.

### D7 — Token version policy (A11 and rolling deploys)

- `verify()` rejects any `schema_version` outside `JwtClaims.ACCEPTED_VERSIONS`, any missing or non-UUID `tenant_id`, and (Revision 1, RC-40.1) any non-UUID `sub`, with 401. For `schema_version = 3` it also requires `perm_epoch` to be present and a non-negative long, even in M6, which ignores the value. It never returns 500.
- **v3 is frozen at M6 merge as v2 ∪ {`perm_epoch`}** (RC-40.1). Any other claim change is v4 and follows the steps below.
- The accepted set moves in expand/contract steps:
  - M6 accepts {2,3} and mints 2.
  - M7 accepts {2,3} and mints 3, treating a v2 token as epoch 0.
  - M7b accepts {3}, at least one TTL after M7 is everywhere.
- Accepting N+1 one release ahead prevents 401 ping-pong between mixed-version instances. It is safe because only this platform's key mints tokens.

### D8 — Refresh rate limit split

The per-IP refresh limit (30/60 s) would log out users behind a shared NAT after a detach on a large role. **Revised (Revision 1, RC-32)**, it is split into three buckets:
- a **per-refresh-family** bucket (30/60 s), enforced **in the refresh use case after the token lookup**, before rotation, because the cookie is opaque and the family is known only from the DB row. Unknown and invalid tokens have no family. The key uses a plain SHA-256 of the family id, which is not a secret and is hashed only to keep it out of logs;
- a **per-IP total** (300/60 s), in the filter;
- a **per-IP failure** bucket (30/60 s), **consumed and enforced only in the refresh use case, only on failure outcomes**, before the append-only `TOKEN_REFRESH_FAILURE` row is written (revised, Revision 2, RC-43). A valid token proceeds whatever this bucket says. A failing refresh that the bucket rejects gets 429 with `Retry-After` and writes no audit row; a counter and at most one WARN per window record it. The filter no longer checks this bucket, and the non-consuming `isExhausted` store method proposed in Revision 1 is dropped. This keeps unauthenticated audit writes and invalid-token probing at today's bound, and N concurrent failures still write at most 30 rows. Invalid refreshes from behind a shared NAT can no longer log out the valid users behind it (T-D24). Only successful refreshes are loosened (RES-40).
- **Reuse detection is never gated by the failure bucket (Revision 3, RC-51; T-E46).** When a revoked token is presented, the use case **always runs `revokeFamily` before the failure bucket is consulted**, and writes `TOKEN_REFRESH_REUSE` whenever that call revoked at least one active token. `revokeFamily` returns the number of tokens it revoked. Only a reuse that revoked nothing is subject to the failure bucket, like any other failure outcome. Otherwise an attacker holding a stolen, already-rotated family could keep the victim IP's failure bucket exhausted, so that the owner's replay got 429 with no revocation and no evidence while the attacker's valid refreshes passed.

Behind a proxy the per-IP key is the proxy's address (DF-1), so both per-IP buckets become platform-wide. Merge is gated on a load test that produces zero forced logouts, **run in the production ingress topology**, with the result recorded for both deployment shapes. It includes an attacker sending invalid refreshes from behind the same NAT (Revision 2, RC-43.3), and asserts that no reuse-detection revocation is suppressed (Revision 3, RC-51).

### D9 — B6 decision rule

After M7, keep the permission cache only if it lowers refresh p95 by at least 5 ms, or lowers MySQL QPS attributable to minting by at least 30%, at the benchmark load. Otherwise remove it; an inconclusive result also means remove. **Recorded consideration (Revision 1, RC-34.2):** removing the cache also removes a Redis-write → privilege path (permission injection at mint), so a "keep" result must state that the path is accepted under the Redis prerequisites below. The measured result is recorded as an addendum to this ADR.

## Corrections to accepted ADRs

**ADR-0008** (its trigger note) and **ADR-0016** (its D4 "JWT jti denylist" row and its Supersession bullet) state that a Redis `jti` denylist "is now implemented". **It is not.** No denylist code exists, and `JwtAuthenticationFilter` consulted only `JwtPort.verify` before this ADR. Access-token logout revocation remains TTL-only (ADR-0008 Option A). This ADR's epoch check is therefore the first per-request Redis dependency, and ADR-0016's "fail open, loudly alerted" rule is exercised for the first time here. The two ADRs receive dated amendment notes under US-018 D2. Their bodies are not rewritten.

## Supersession

| Point | Change |
|---|---|
| ADR-0013 D1 "no per-request RBAC state" | One O(1) Redis read per authenticated request. The JWT remains the permission source for the request |
| ADR-0013 D4 "accept cache lag, no bulk invalidation" | Reversed (D3, D4) |
| ADR-0016 D3 permset key | Gains `:{epoch}`; a new row for `nexus:rbac:epoch:{tenantId}:{userId}` |
| ADR-0016 D4 | New capability row "RBAC permission epoch": String key with TTL, time-boxed fail-open then 503 |
| ADR-0016 D5 non-goal "no bulk invalidation across holders" | Reversed for detach |

## Consequences

**Benefits:**
- A revoked role or detached permission stops working on the holder's next request, measured in under a second in integration tests.
- Stale caches can no longer re-mint a revoked permission.
- Token-contract changes gain a rolling-deploy-safe policy.

**Trade-offs:**
- Redis becomes part of the authorization decision, with a defined outage policy.
- One Redis read on every authenticated request.
- A detach on a large role causes a burst of refreshes.
- The refresh rate limit is loosened per IP for successful refreshes only.
- Per-instance degraded state can flap; flapping no longer restarts the window, and it pages.
- A Redis outage longer than the window is a platform-wide authenticated 503 (RES-30; acceptance by SRE and PM pending at Gate 2).

**Redis is authorization state (Revision 1, RC-34).** Redis write access equals **permission injection at mint** (write a permset entry, then refresh; pre-existing under ADR-0016) and, from this ADR, **revocation suppression** (delete an epoch key) and a targeted denial of service (set an epoch far ahead). **Redis write access therefore equals authorization** (RES-32). Production prerequisites:
- Redis authentication, with an ACL user limited to the `nexus:*` key patterns, or at minimum `requirepass`;
- network isolation, so only the application reaches Redis;
- TLS wherever Redis is not on a private network;
- a startup assertion: with `nexus.rbac.redis.require-auth=true` and a blank Redis password, startup fails. **Revision 2 (RC-45):** `require-auth=true` is set in `application-prod.yml` (M7), and `nexus.rbac.throttle.require-shared-store=true` is set there too (M8, where that property is introduced), so neither depends on an operator step; the runbook keeps both as checks. The assertion covers the main Redis factory and both dedicated epoch factories, and an IT runs the epoch path against an auth-enabled Redis.
The matching amendment note on ADR-0016 D2 is added under US-018 D2, as a dated note; its body is not rewritten.

**Rollback (Revision 1, RC-40.6).** Rolling back to the M6 release is always safe for sessions, but it silently disables the epoch check, so the rollback runbook pages Platform Security.

**Rejected alternatives:**
- A per-tenant epoch: rejected at Gate 1, because any change forces every session to re-authenticate.
- Pure fail-closed: rejected at Gate 1, because it turns a Redis blip into a platform outage.
- Server-side re-resolution of permissions for stale tokens instead of 401: it eliminates storms but contradicts AC A9 and puts a DB fallback on the hot path. Revisit if D8's load gate fails.
- A circuit-breaker library: one call site does not justify a dependency.
- A cap on fan-out: a silent fail-open.

## Follow-on rules

- Any new permission-reducing operation must bump the affected users' epochs after commit, through `PermissionFreshnessService`.
- Any change to the claim set follows D7: widen the accepted set one release ahead, then contract.
- Any new per-request Redis read uses the dedicated short-timeout factory and states its outage policy (ADR-0016 follow-on rule).
- Any new per-request rejection in the bearer filter states how it treats `@PublicEndpoint` requests; the default is that they are never rejected (D5).
- Any change to the access-token TTL or the permission-cache TTL re-checks the epoch key TTL (D1); the startup assertion enforces it.
