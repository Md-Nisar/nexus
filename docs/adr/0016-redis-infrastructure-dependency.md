# ADR 0016 — Redis as an Infrastructure Dependency: Topology, Client, Keyspace, and Failure-Mode Policy per Capability

**Status:** Accepted
**Date:** 2026-07-18
**Feature:** Platform infrastructure (see `docs/redis-integration-plan.md` for the full design)

---

## Context

Nexus has no caching, session store, or coordination layer today — MySQL 8.4 (via Flyway) is the
only datastore. Across three prior ADRs, the team identified needs a shared, fast store would
solve, and explicitly deferred every one of them pending "when Redis is added as a dependency":

1. **ADR 0008** (jti denylist) — Option B (Redis-backed `jti` denylist for near-instant logout
   revocation) was deferred as a "planned fast-follow." GA ships TTL-only revocation instead
   (≤15-min residual window after logout). Explicit re-evaluation trigger: *"Redis is adopted for
   another reason."*
2. **ADR 0009** (lockout counters) — the alternatives table explicitly lists "Redis atomic
   increment... deferred to when Redis is added as a dependency (future story)" to close DF-3, the
   concurrent-under-count race in `persistFailedAttempt`.
3. **ADR 0013 D4** (RBAC cache) — assumes, but does not build, a "15-minute Redis TTL" permission
   cache keyed `{tenant_id}:{user_id}`.
4. `identity/infrastructure/security/InMemoryRateLimitStore.java`'s own javadoc documents that its
   per-JVM counters are "not shared across replicas" and names
   `nexus.security.rate-limit.store-type=redis` as the intended fix — a config key already stubbed
   in `application.yml` pointing at `nexus.redis.*` properties that don't exist yet.
5. `docs/story/2-rbac/US-015.md` lists "External: Redis (if cache fan-out option (a) is chosen)"
   for role-permission cache invalidation.

This ADR bundles all five into one infrastructure decision, the same way ADR 0013 bundled its four
decisions for EPIC-002. The full design rationale, per-capability data structures, and phased
rollout live in `docs/redis-integration-plan.md`; this ADR records the decisions themselves.

---

## Decision

### D1 — Adopt Redis; topology is standalone (dev) / Sentinel-HA or managed service (staging/prod); not Cluster

Redis is adopted as a cache/coordination layer, never as a system of record — MySQL + Flyway
remains authoritative for all data (ADR 0003, unchanged). Standalone Redis for local/dev.
Sentinel-fronted primary + replica, or a managed Redis service if the deployment target offers
one, for staging/prod. Redis Cluster is explicitly rejected: every key this ADR introduces (rate
limit counters, a per-user 15-minute-TTL permission set, jti keys, lockout counters) is small and
low-fanout, with no evidence anywhere in the codebase that Redis itself (rather than MySQL) would
ever be the throughput bottleneck. Cluster's hash-slot constraints would also complicate the
multi-key Lua scripts several capabilities below use, for no offsetting benefit.

`maxmemory-policy: noeviction` (not `allkeys-lru`): several keys are security-relevant (jti
denylist, lockout counters), so silent eviction under memory pressure would be a silent security
regression. AOF persistence (`appendfsync everysec`) in prod; none needed in dev.

### D2 — Client library: Lettuce via `spring-boot-starter-data-redis` for everything; Redisson, `RLock`-only, deferred and evidence-gated for locks

Sync `RedisTemplate`/`StringRedisTemplate`, not the reactive API — the codebase already runs
virtual threads (`spring.threads.virtual.enabled: true`), so a blocking call parked on a virtual
thread is cheap. Hand-written adapters implementing hexagonal ports, not the declarative
`@Cacheable`/`RedisCacheManager` abstraction — every capability below needs atomic
check-and-increment, atomic one-time-consume, or set-membership semantics that declarative caching
doesn't express, and hand-written adapters match the existing port/adapter convention
(`RateLimitStore`, `AuthTokenPort`). Redisson is not added now; it is added later, scoped to
`RLock` only, only if a concrete distributed-lock race is confirmed (no such need is confirmed by
this ADR).

### D3 — Keyspace convention: `nexus:{bounded-context}:{concern}:{discriminators}`

Lowercase, colon-separated, mirroring ADR 0013 D1's `resource:action` idiom already established for
permission names. Tenant ID is embedded wherever data is tenant-scoped, for operability (e.g.
`SCAN`-by-tenant during an incident), even where a UUIDv7's global uniqueness would make it
technically redundant.

| Capability | Key pattern |
|---|---|
| Rate limiting | `nexus:identity:ratelimit:{bucket}` (`{bucket}` = existing `RateLimitStore` key verbatim: `IP:{ip}`, `USER:{emailHmac}`, `REFRESH_IP:{ip}`) |
| JWT jti denylist | `nexus:identity:jwt:denylist:{jti}` |
| RBAC permission cache | `nexus:rbac:permset:{tenant_id}:{user_id}` |
| Password reset / verification tokens | `nexus:identity:token:{reset\|verify}:{tokenHash}` |
| Account lockout counter | `nexus:identity:lockout:count:{tenant_id}:{user_id}` |
| RBAC invalidation stream | `nexus:rbac:invalidate:stream:{tenant_id}` |
| Distributed locks | `nexus:identity:lock:{concern}:{discriminator}` |

### D4 — Per-capability data structure and failure-mode policy

| Capability | Structure | Failure mode | Rationale |
|---|---|---|---|
| Rate limiting | ZSET + Lua-atomic sliding-window-log | **Fail open** | Defense-in-depth, not the primary auth guarantee; blocking all logins platform-wide on a Redis blip is worse than the risk it guards against |
| JWT jti denylist | Individual `SETEX`-style keys (own TTL = remaining token lifetime) | **Fail open, explicit security callout** | Reverts to ADR 0008's already-accepted TTL-only GA baseline, not a new vulnerability — must be alerted, not silent |
| RBAC permission cache | SET of permission strings, TTL 900s, consulted at JWT-mint time (login/refresh) — not per API request, since enforcement is a flat check against the JWT's own `permissions[]` claim per ADR 0013 D1 | **Fail to DB** (cache-aside) | MySQL is authoritative; only mint-time latency degrades |
| Account lockout counters | `INCR`/`EXPIRE` Lua, additive fast path only | **Fail closed to the unchanged ADR 0009 MySQL path** | Brute-force protection must never silently stop working; MySQL remains authoritative |
| Anti-enumeration one-time tokens | *(not migrated — remain in MySQL; see Non-Goals)* | n/a | See D5 |
| RBAC real-time invalidation | Redis Streams (not Pub/Sub), one per tenant, `MAXLEN ~1000` | **Fail open / degrade to no push** | Pure UX layer; the 15-min-TTL/7-day-refresh backstop (ADR 0013 D4) remains the correctness guarantee |
| Distributed locks | Redisson `RLock` (if/when triggered) | **Fail closed for the protected invariant** | Evidence-gated; not adopted by this ADR |

### D5 — Non-goals

- Redis never becomes the system of record for anything; MySQL + Flyway retains that role (ADR
  0003, unchanged).
- Anti-enumeration one-time tokens (password reset, email verification) are **not** migrated to
  Redis. Redis would introduce a new network-RTT timing channel the existing dummy-CPU-equivalent
  op doesn't equalize, and the durability trade (MySQL's replicated storage vs. Redis
  TTL-eviction) is unfavorable for a flow where a lost token is a user-visible failure, not a perf
  blip. Revisit only if a concrete operational driver appears.
- No leaderboards/sorted-set ranking, geospatial, HyperLogLog, or RediSearch/autocomplete —
  no gamification, location, cardinality-counting, or search feature exists anywhere in this
  codebase.
- Redis Streams are scoped narrowly to RBAC invalidation fan-out, not adopted as a general job
  queue — the existing in-process `AuthEventRetryBuffer` (ADR 0011) already covers bounded-retry
  audit writes at this scale.
- No bulk cache invalidation across all holders of a role on a role-permission edit — ADR 0013
  D4's decision to accept that lag stands unchanged; this ADR does not reopen it.

### D6 — Hexagonal boundary enforcement

Redis client types (`org.springframework.data.redis..`, `io.lettuce..`, `org.redisson..`) are
confined to `infrastructure/` packages via a new ArchUnit rule. Note this is a *new* restriction,
not an extension of an existing one: the codebase's current domain entities (`User`, `AuthToken`,
`RefreshToken`, `AuthEvent`) are annotated with `jakarta.persistence` directly, so no equivalent
JPA-import restriction exists today to model this after. The existing hexagonal rules
(`HexagonalArchitectureTest`) only block domain/application from depending on this codebase's own
`..infrastructure..`/`..interfaces..` packages — they don't block direct imports of specific
third-party client libraries, which is the gap this new rule closes for Redis specifically:

```java
noClasses().that().resideInAPackage("..domain..").or().resideInAPackage("..application..")
    .should().dependOnClassesThat().resideInAnyPackage(
        "org.springframework.data.redis..", "io.lettuce..", "org.redisson..");
```

---

## Consequences

**Benefits:**
- Closes ADR 0009's DF-3 concurrent-under-count race without changing MySQL's authoritative role.
- Implements ADR 0008's deferred Option B, giving near-instant logout revocation.
- Gives the RBAC runtime (previously entirely unwired — `JwtRs256Service.issue()` hardcoded
  `roles = List.of("USER")`) a cache-aside permission lookup at JWT-mint time, avoiding a
  `user_roles → role_permissions → permissions` join on every login/refresh.
- Fixes `InMemoryRateLimitStore`'s documented multi-replica gap without changing
  `LoginRateLimitFilter`'s use-case code — `RateLimitStore`'s own javadoc already promised this
  swap.
- Establishes one keyspace and failure-mode convention up front, so later features (real-time
  invalidation, locks) extend a settled pattern instead of inventing their own.

**Trade-offs:**
- A new operational dependency: on-call runbook addition, capacity planning, connection-pool
  sizing under virtual threads, a new Sentinel/managed-service topology to operate.
- The fail-open decisions in D4 (rate limiting, jti denylist, real-time invalidation) are an
  explicitly accepted residual-risk list, not an oversight — most critically, the jti denylist
  failing open on a Redis outage silently reverts to a pre-existing accepted baseline (ADR 0008),
  but this must be loudly alerted operationally, not left to be discovered later.
- `noeviction` requires proactive memory-usage alerting (see `docs/redis-integration-plan.md` §7)
  since the system fails loudly, not gracefully, past the memory ceiling.

**Supersession:**
- **ADR 0008** — Option B ("`jti` denylist in a fast store (Redis)") is now **adopted**, per D4
  above. ADR 0008's own status and triggers-for-re-evaluation section should be read as satisfied
  by this ADR rather than left open-ended.
- **ADR 0009** — the "Redis atomic increment" alternative is now **adopted** as an additive fast
  path in front of the unchanged MySQL mechanism, per D4 above. ADR 0009's core decision (MySQL
  `REQUIRES_NEW` + bulk `UPDATE` as the authoritative write path) is otherwise unchanged.
- **ADR 0013 D4** — this ADR does not change D4's decision (accept cache lag, no bulk
  invalidation on role edits); it specifies the mechanism (Redis SET, TTL 900s, consulted at
  JWT-mint time) that D4 assumed but didn't build.

---

## Alternatives Considered

| Decision | Alternative | Rejected because |
|---|---|---|
| D1 | Redis Cluster | No sharding-scale evidence anywhere in the codebase; hash-slot constraints would complicate multi-key Lua scripts for no benefit |
| D1 | `allkeys-lru` eviction | Silent eviction of security-relevant keys (jti denylist, lockout counters) is a silent security regression |
| D2 | Jedis | Per-thread-connection model; Lettuce is Spring Boot 4's default and fits the codebase's virtual-thread commitment better |
| D2 | Declarative Spring Cache (`@Cacheable`/`RedisCacheManager`) | Doesn't express the atomic check-and-increment / one-time-consume / set-membership semantics most capabilities need |
| D2 | Adopt Redisson broadly (as the general Redis client) | Would duplicate `RedisTemplate` coverage and create two overlapping Redis abstractions for no benefit; Redisson's value is specifically lock renewal/reentrancy/CAS-unlock |
| D5 | Migrate anti-enumeration tokens to Redis now | New network-RTT timing channel to equalize; unfavorable durability trade for low-QPS endpoints with no throughput evidence |
| — | MySQL-only for all five needs | Already rejected per-capability in ADR 0008/0009 on hot-path-DB-read-cost and race-condition grounds |
| — | An embedded in-JVM grid (Hazelcast/Ignite) | No existing embedded-grid expertise signalled anywhere in the repo; doesn't solve "shared across replicas" as simply as an external Redis instance |

---

## Follow-on rules for future work

- Any new capability needing a shared, fast, replica-visible store should default to Redis using
  the `nexus:{bounded-context}:{concern}:{discriminators}` keyspace convention (D3), not invent a
  parallel mechanism.
- Any new Redis-backed capability must state its failure-mode policy (fail open vs. fail closed vs.
  fail-to-DB) explicitly, following the reasoning pattern in D4 — silence on this point is not
  acceptable given the security-relevant precedent set by the jti denylist and lockout counters.
- Redis client types stay confined to `infrastructure/` packages (D6); do not import
  `org.springframework.data.redis..`/`io.lettuce..`/`org.redisson..` from `domain`/`application`.
- Full implementation detail (Lua scripts, adapter sketches, phased rollout) lives in
  `docs/redis-integration-plan.md` — treat this ADR as the decision record and that document as
  the design reference.
