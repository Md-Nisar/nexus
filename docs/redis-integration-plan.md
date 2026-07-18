# Redis Integration Plan

**Status:** proposal — input to a future ADR 0016 and phased implementation tasks.
**Scope:** design document only. No `pom.xml`, `docker-compose.yml`, or application code changes
are made by this document.

---

## 1. Why now — this isn't a new idea, it's five deferred ones converging

Nexus (Spring Boot 4.1, Java 25, hexagonal architecture, MySQL 8.4 + Flyway as the only
datastore) has no caching, session store, or coordination layer today. But across three separate
ADRs, the team has already identified needs that a shared, fast store would solve — and
explicitly deferred every one of them pending "when Redis is added as a dependency":

| Source | Deferred need |
|---|---|
| `identity/infrastructure/security/InMemoryRateLimitStore.java` (javadoc) | Per-JVM rate-limit counters aren't shared across replicas — "switch to `nexus.security.rate-limit.store-type=redis`." The config key is already stubbed in `application.yml` (`nexus.security.rate-limit.store-type: memory # memory \| redis; redis requires nexus.redis.* config`) but `nexus.redis.*` doesn't exist yet. |
| `docs/adr/0008-access-token-revocation-jti-denylist.md` | JWT `jti` denylist for near-instant logout revocation ("Option B") deferred as a "planned fast-follow." GA ships TTL-only revocation (≤15-min residual window after logout). Explicit re-evaluation trigger: *"Redis is adopted for another reason."* |
| `docs/adr/0009-requires-new-transaction-for-lockout-counters.md` | A concurrent-under-count race in login-lockout counters (two failed logins racing on `findById+save` can both read `count=4` before either writes `5`) — "Redis atomic increment... deferred to when Redis is added as a dependency (future story)." |
| `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` (D4) | Assumes, but doesn't build, a "15-minute Redis TTL" permission cache. More fundamentally: **the RBAC runtime isn't wired at all** — `JwtRs256Service.issue()` still hardcodes `.claim("roles", List.of("USER"))`; nothing in the codebase queries `user_roles → role_permissions → permissions` today, even without Redis. |
| `docs/story/2-rbac/US-015.md` | Lists "External: Redis (if cache fan-out option (a) is chosen)" for role-permission cache invalidation. |
| `docs/story/2-rbac/EPIC-002.md` | Lists "real-time permission invalidation without re-login" as an explicit **future** capability — not built, no websocket/SSE/polling infra exists anywhere in the Angular frontend today. |

This plan treats Redis as infrastructure the RBAC runtime wiring, JWT revocation, and future
real-time features can build on — not a one-off cache bolted onto a single endpoint. Every
capability area below is graded against actual evidence in this codebase; anything without such
evidence is explicitly excluded rather than force-fit (§5.8).

---

## 2. Current state (grounding)

- **Auth**: fully stateless RS256 JWT (`JwtRs256Service`, ADR 0007). `SecurityConfig` sets
  `SessionCreationPolicy.STATELESS`. No `HttpSession`, no Spring Session, anywhere.
- **Caching**: none. No `@Cacheable`, `@EnableCaching`, Hibernate 2nd-level cache, or Caffeine
  anywhere in `nexus-backend`.
- **Rate limiting**: `identity/application/port/out/RateLimitStore.java` is a hexagonal **port**
  (`RateLimitResult tryConsume(String key, int windowSeconds, int maxAttempts)`) with one adapter,
  `InMemoryRateLimitStore` (`ConcurrentHashMap`-backed sliding-window-log), gated by
  `@ConditionalOnProperty(name="nexus.security.rate-limit.store-type", havingValue="memory",
  matchIfMissing=true)`. The port's own javadoc already promises a Redis-backed adapter "without
  changing use-case code."
- **Lockout counters**: `identity/application/service/SecureEventService.java` —
  `persistFailedAttempt`/`persistResetAttempts`, both `@Transactional(REQUIRES_NEW)` per ADR 0009,
  writing to `users.failed_attempt_count`/`users.locked_until`. Threshold = 5, lock duration = 900s.
- **Anti-enumeration tokens**: `ForgotPasswordUseCase`/`ResetPasswordUseCase`/
  `ResendVerificationUseCase` persist one-time tokens (SHA-256 hashed) to a MySQL `auth_tokens`
  table, TTLs enforced in application code (verification 24h, reset 60min).
- **RBAC data model** (US-009): tables `permissions`, `roles`, `role_permissions`, `user_roles`
  exist (`V5__rbac_schema.sql`), with entities and plain-marker JPA repos in the `rbac` context —
  but **no `application`/`interfaces` layer yet**, and nothing consumes these tables at runtime.
- **Infra**: `pom.xml` has no `spring-boot-starter-data-redis`/Lettuce/Jedis/Redisson/Caffeine.
  `docker-compose.yml` has `mysql`, `flyway-migrate`, `backend`, `mailhog`, `frontend` — no Redis
  service. No message broker (Kafka/RabbitMQ) — only an in-process bounded retry buffer for audit
  writes (ADR 0011, `AuthEventRetryBuffer`) driven by `@Scheduled`.
- **Frontend**: no websockets, SSE, polling, or real-time UI of any kind today.
- Next available ADR number: **0016**.

---

## 3. Deployment topology

**Standalone Redis for dev/local. Sentinel-HA (primary + ≥1 replica + 3 sentinels), or a managed
Redis service if the eventual deployment target offers one, for staging/prod. Do not adopt Redis
Cluster.**

This is a modular monolith with multiple **stateless** backend replicas and moderate scale — every
key this plan introduces (rate-limit counters, a per-user 15-min-TTL permission set, jti keys,
lockout counters) is small and low-fanout. Nothing in the codebase suggests Redis itself, rather
than MySQL, would ever be the throughput bottleneck. Cluster's value is write-sharding for
datasets/throughput too large for one node — not this system's problem — and it would impose real
costs the design below would immediately feel: multi-key Lua scripts require every key to share a
hash slot, complicating the key-naming scheme for no benefit, and client-side slot routing adds a
new failure mode. Sentinel gives automatic failover without that complexity. If the deployment
target later gains a managed Redis offering, prefer it over self-hosting Sentinel, for the same
reason the team doesn't self-host MySQL HA.

**`docker-compose.yml` (future Phase 1 change — not made by this document):** add `redis` to the
**default** service set (no `profiles:` key, alongside `mysql`/`mailhog`, since it becomes an
IDE-run-backend dependency like MySQL already is):

```yaml
  redis:
    image: redis:7.4-alpine
    container_name: nexus-redis
    command: >
      redis-server
      --maxmemory 256mb
      --maxmemory-policy noeviction
      --appendonly yes
      --appendfsync everysec
      --save 900 1
    ports:
      - "6379:6379"
    volumes:
      - nexus-redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 10
```

`maxmemory-policy: noeviction`, deliberately not `allkeys-lru`: several keys here are
security-relevant (jti denylist, lockout counters). Silent LRU eviction under memory pressure is a
*silent security regression* — an evicted denylist entry un-revokes a token, an evicted lockout
counter un-limits a brute-force attempt, and nobody is paged. `noeviction` turns an out-of-memory
condition into a loud write failure instead, handled per-capability by the fail-open/fail-closed
policy in §7 — paired with conservative capacity planning and a memory-usage alert well before the
ceiling (§6), not with silent eviction as the safety valve.

**Persistence**: AOF (`appendonly yes`, `appendfsync everysec`) in prod, none needed in dev.
RDB-only snapshotting risks losing the last several seconds of writes on a crash — acceptable for a
pure cache, not acceptable for jti-denylist entries or lockout counters, where a Redis restart
mid-lockout-window silently unlocking an account, or shortly after logout un-revoking an access
token, would be a real (if narrow) regression. `everysec`, not `always` — nothing here needs
per-write fsync latency.

---

## 4. Client library choice

**Lettuce, via `spring-boot-starter-data-redis`, for everything except locks. Redisson, added
narrowly and only if triggered, for distributed locks (Phase 5, optional).**

- **Lettuce over Jedis**: Spring Boot 4's starter defaults to Lettuce already. Its netty-based,
  thread-safe, multiplexed connection model is a better fit for a codebase that has already
  committed to virtual threads (`spring.threads.virtual.enabled: true`) than Jedis's
  per-thread-connection model.
- **Sync `RedisTemplate`/`StringRedisTemplate`, not the reactive API**: a blocking Redis call
  parked on a virtual thread is cheap, so there's no concurrency-driven pressure to adopt Lettuce's
  reactive stack. Sync calls through explicit adapter methods also match how the rest of the
  codebase calls out through ports, rather than reactive pipelines.
- **Hand-written adapters over the declarative Spring Cache abstraction (`@Cacheable` +
  `RedisCacheManager`)**: most use cases below need atomic check-and-increment (rate limiting,
  lockout), atomic one-time consumption (`GETDEL`), or set-membership semantics (RBAC cache) —
  none of which `@Cacheable`'s "read-through, one-TTL-per-cache-name" model expresses naturally.
  Explicit adapters implementing hand-written port interfaces are also consistent with this
  codebase's existing convention (`RateLimitStore`, `AuthTokenPort`, etc.).
- **Redisson — deferred, optional, narrow scope.** Add only if a concrete distributed-lock need is
  confirmed (§5.6, §6 Phase 5), and scope it to `RLock` only — not Redisson's broader
  distributed-object suite (`RMap`, `RBucket`, ...), which would duplicate what `RedisTemplate`
  already covers elsewhere in this plan. Redisson's actual value here is lock renewal (watchdog),
  reentrancy, and a correct CAS-unlock — hand-rolling `SET NX PX` + a Lua unlock script is a
  well-known footgun (forgetting renewal, or unlocking a lock you no longer hold).

**Future `pom.xml` addition (Phase 1, not made by this document):**

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

---

## 5. Key naming convention & data structure per capability

### Naming scheme

`nexus:{bounded-context}:{concern}:{discriminators}` — lowercase, colon-separated, deliberately
mirroring ADR 0013 D1's `resource:action` lowercase-colon idiom already established for permission
names, so the codebase has one consistent identifier style rather than two. Tenant ID is embedded
wherever data is tenant-scoped, even where a UUIDv7's global uniqueness would make it technically
redundant — for operability (e.g. `SCAN`-by-tenant during an incident).

| Capability | Key pattern |
|---|---|
| Rate limiting | `nexus:identity:ratelimit:{bucket}` — `{bucket}` = the existing `RateLimitStore` key verbatim (`IP:{ip}`, `USER:{emailHmac}`, `REFRESH_IP:{ip}`) |
| JWT jti denylist | `nexus:identity:jwt:denylist:{jti}` |
| RBAC permission cache | `nexus:rbac:permset:{tenant_id}:{user_id}` |
| Password reset token | `nexus:identity:token:reset:{tokenHash}` |
| Email verification token | `nexus:identity:token:verify:{tokenHash}` |
| Account lockout counter | `nexus:identity:lockout:count:{tenant_id}:{user_id}` |
| RBAC invalidation stream | `nexus:rbac:invalidate:stream:{tenant_id}` |
| Distributed locks | `nexus:identity:lock:{concern}:{discriminator}` |

### 5.1 Rate limiting — ZSET + Lua-atomic sliding-window-log

**Keep the existing algorithm.** `InMemoryRateLimitStore`'s Retry-After semantics ("time until the
*oldest tracked request's* window expires") are sliding-window-log behavior already baked into the
`RateLimitResult` contract `LoginRateLimitFilter` depends on — switching to token-bucket or
fixed-window would silently change observable Retry-After values for existing callers.

Structure: a ZSET per key, score = epoch-millis, member = a collision-resistant value (e.g.
`"{millis}-{random}"`). The prune → count → conditionally-add sequence must be atomic across the
round trip (otherwise two concurrent requests can both observe `count = maxAttempts - 1` and both
be admitted), so it runs as a Lua script:

```lua
-- KEYS[1] = redis key (sorted set)
-- ARGV[1] = now (millis), ARGV[2] = window size (millis), ARGV[3] = max attempts
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local maxAttempts = tonumber(ARGV[3])
local windowStart = now - window

redis.call('ZREMRANGEBYSCORE', key, '-inf', windowStart)
local count = redis.call('ZCARD', key)

if count >= maxAttempts then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retryAfterMs = window - (now - tonumber(oldest[2]))
  return {0, math.max(1, math.ceil(retryAfterMs / 1000))}
else
  redis.call('ZADD', key, now, now .. '-' .. math.random(100000))
  redis.call('PEXPIRE', key, window)
  return {1, 0}
end
```

Adapter sketch:

```java
package com.example.nexus.identity.infrastructure.security;

@ConditionalOnProperty(name = "nexus.security.rate-limit.store-type", havingValue = "redis")
@Component
public class RedisRateLimitStore implements RateLimitStore {

  private final StringRedisTemplate redisTemplate;
  private final Clock clock;
  private final String keyPrefix;
  private static final DefaultRedisScript<List> SLIDING_WINDOW_SCRIPT = /* load from classpath */;

  @Override
  public RateLimitResult tryConsume(String key, int windowSeconds, int maxAttempts) {
    String redisKey = keyPrefix + ":identity:ratelimit:" + key;
    try {
      List<Long> result = redisTemplate.execute(SLIDING_WINDOW_SCRIPT, List.of(redisKey),
          String.valueOf(clock.millis()), String.valueOf(windowSeconds * 1000L), String.valueOf(maxAttempts));
      return result.get(0) == 1L ? RateLimitResult.permit() : RateLimitResult.reject(result.get(1));
    } catch (Exception e) {
      log.warn("RATE_LIMIT_REDIS_UNAVAILABLE key={}", key, e);
      return RateLimitResult.permit(); // fail open — see §7
    }
  }
}
```

`InMemoryRateLimitStore` remains the `memory`-mode default and the fast test double; this adapter
activates via the already-stubbed `nexus.security.rate-limit.store-type=redis`.

### 5.2 JWT jti denylist — individual TTL'd keys, not a Redis SET

`SETEX nexus:identity:jwt:denylist:{jti} <remainingSeconds> "1"`, checked via `EXISTS`. Not a
collection SET, because each `jti` needs its own independent TTL equal to *that specific token's*
remaining lifetime — a single SET has no native per-member expiry. An individual key is
self-cleaning (no reaper job needed) at the same O(1) lookup cost as `SISMEMBER`.

```java
public interface JwtDenylistPort {
  void denylist(String jti, long ttlSeconds);
  boolean isDenylisted(String jti);
}

@Component
public class RedisJwtDenylistAdapter implements JwtDenylistPort {
  @Override
  public void denylist(String jti, long ttlSeconds) {
    if (ttlSeconds <= 0) return; // already expired naturally
    redisTemplate.opsForValue().set(key(jti), "1", Duration.ofSeconds(ttlSeconds));
  }

  @Override
  public boolean isDenylisted(String jti) {
    try {
      return Boolean.TRUE.equals(redisTemplate.hasKey(key(jti)));
    } catch (Exception e) {
      log.warn("JWT_DENYLIST_REDIS_UNAVAILABLE jti={}", jti, e);
      return false; // fail open — reverts to ADR 0008's TTL-only baseline, see §7
    }
  }
}
```

`LogoutUseCase` writes the `jti` on logout with TTL = remaining access-token lifetime;
`JwtRs256Service`'s verification path consults `isDenylisted()` before accepting a token. This
finally implements ADR 0008's deferred Option B.

### 5.3 RBAC permission cache — Redis SET, consulted at JWT-mint time (not per API request)

**Important distinction, verified directly against ADR 0013 D1** (not just its D4 cache mention):
RBAC enforcement is a **flat set-membership check against the JWT's own `permissions[]` claim** —
"no hierarchy or wildcard support... keeps evaluation a flat set-membership check against the JWT
claim, with no traversal logic in the hot path." This means the permission set is baked into the
JWT at issuance/refresh time, and per-request authorization never touches Redis or the DB at all.

So this cache's actual job is narrower than "cache permission checks" — it's consulted **when
minting a JWT** (login and token refresh) to avoid a `user_roles → role_permissions → permissions`
join on every mint, not on every authenticated API call. State this plainly in any implementation
task derived from this plan, so it isn't mis-wired as a per-request authorization cache.

Structure: `SADD nexus:rbac:permset:{tenant_id}:{user_id} "tenant:read" "user:write" ...` +
`EXPIRE 900` (900s / 15 min, exactly per ADR 0013 D4). A native SET mirrors the flat
set-membership semantic directly — no JSON deserialization, no Hash (permissions aren't key-value
pairs).

```java
public interface PermissionCachePort {
  Optional<Set<String>> get(UUID tenantId, UUID userId);
  void put(UUID tenantId, UUID userId, Set<String> permissions);
  void evict(UUID tenantId, UUID userId); // best-effort; safe no-op on Redis-down
}
```

Usage at JWT-mint time (cache-aside):

```java
Set<String> permissions = permissionCachePort.get(tenantId, userId)
    .orElseGet(() -> {
      Set<String> fromDb = permissionQueryPort.findEffectivePermissions(tenantId, userId);
      permissionCachePort.put(tenantId, userId, fromDb);
      return fromDb;
    });
```

**Invalidation**: write-through `DEL` on the specific `(tenant_id, user_id)` pair on role
assignment/revocation (US-012's existing scope) — a missed delete just means a ≤15-minute-stale
cache read at the *next* mint, not a correctness bug, since MySQL remains authoritative. For
role-level edits (US-015), **no bulk invalidation across all holders of the role** — this
continues ADR 0013 D4's explicit decision; do not reopen it here. If Phase 4's Streams
infrastructure (§5.5) lands later, it may *additionally* emit an eager-invalidation event that a
listener uses to `DEL` early — purely additive on top of the TTL floor, never a replacement for it.

### 5.4 Account lockout counters — Redis as a race-closing fast path; MySQL stays authoritative

The most nuanced case. **Redis never becomes authoritative for lock state.** ADR 0009's MySQL
`REQUIRES_NEW` + bulk-`UPDATE` mechanism stays exactly as-is — it's what gives lockout its
durability and its audit trail (`ACCOUNT_LOCKED`, `ACCOUNT_LOCKED_WRITE_FAILED`), and lockout is
precisely the kind of security control that must not silently stop working if Redis is down (§7).

What Redis adds: an atomic `INCR` that closes ADR 0009's DF-3 race (two concurrent failed logins
racing on `findById+save` can both read `count=4` before either writes `5`; `INCR` cannot lose a
count).

```lua
-- KEYS[1] = lockout counter key
-- ARGV[1] = decay window seconds (counter TTL), ARGV[2] = threshold
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return {count, tonumber(ARGV[2])}
```

`LoginUseCase` consults this atomic count to decide *whether* the current failure should also flip
the MySQL lock; the MySQL write (`persistFailedAttempt`) still happens unconditionally and remains
what durably records the lock and its audit event. Redis failure → catch, fall back to exactly
today's MySQL-only threshold check (no regression — DF-3's pre-existing accepted race simply
returns). Treat this as an additive enhancement layered into Phase 2 (§6), not a phase of its own.

### 5.5 Anti-enumeration one-time tokens — pattern documented, migration recommended against

`SET nexus:identity:token:reset:{tokenHash} {userId} NX EX {ttlSeconds}` at creation; atomic
one-time consumption via `GETDEL` would fully replace today's optimistic-lock `markConsumed` +
flush dance:

```java
Boolean created = redisTemplate.opsForValue()
    .setIfAbsent(key(tokenHash), userId.toString(), Duration.ofMinutes(60));
...
String userId = redisTemplate.opsForValue().getAndDelete(key(tokenHash)); // atomic read+delete
if (userId == null) {
  tokenGenerator.generate();                                   // existing CPU-cost equalizer
  redisTemplate.hasKey(key("dummy-" + UUID.randomUUID()));      // would-need: equalizes Redis RTT
  throw new InvalidTokenException(...);
}
```

**Recommendation: do not migrate this.** Two reasons converge:

1. Redis introduces a *new* timing channel the existing dummy-CPU-equivalent-op doesn't equalize —
   a network round trip. If ever migrated, the not-found path must perform an equivalent-cost dummy
   Redis call, or the "found" path (SET + round trip) becomes distinguishable from "not found" (no
   round trip) by latency alone — reopening exactly the anti-enumeration timing oracle
   `ForgotPasswordUseCase`'s existing comment guards against.
2. The durability trade is unfavorable: MySQL gives replicated, backed-up storage; Redis
   TTL-eviction/AOF-lag is a strictly weaker guarantee for a flow where a lost token is a
   user-visible failure (a broken reset link), not a perf blip. Nothing in this codebase shows
   these low-QPS endpoints (password reset, verification) need the swap.

### 5.6 Real-time permission invalidation — Streams, not Pub/Sub

EPIC-002's target UX — "real-time permission invalidation *without re-login*" — implies a
reconnecting SSE client (network blips, tab refocus, mobile backgrounding are normal for a browser
client). Plain Pub/Sub messages published while a subscriber is disconnected are **lost forever**;
a revocation broadcast landing during exactly a reconnect window would be silently missed,
defeating the feature's purpose. Redis **Streams** let a reconnecting SSE bridge resume from its
last-processed ID and catch up on anything missed while disconnected.

One stream per tenant (`nexus:rbac:invalidate:stream:{tenant_id}`, bounding cardinality vs.
per-user streams), `MAXLEN ~ 1000` (approximate trim, since only a recent catch-up window matters),
published **after** the owning MySQL transaction commits — mirroring the existing
`@TransactionalEventListener(AFTER_COMMIT)` pattern already used for `PasswordResetEmailEvent`:

```java
redisTemplate.opsForStream().add(
    StreamRecords.newRecord()
        .in("nexus:rbac:invalidate:stream:" + tenantId)
        .ofMap(Map.of("type", "ASSIGNMENT_REVOKED", "userId", userId.toString(), "roleId", roleId.toString())));
redisTemplate.opsForStream().trim("nexus:rbac:invalidate:stream:" + tenantId, 1000);

// SSE bridge, per connected client, resuming from lastDeliveredId:
StreamOffset<String> offset = StreamOffset.create(streamKey, ReadOffset.from(lastDeliveredId));
List<MapRecord<String, Object, Object>> records = redisTemplate.opsForStream().read(offset);
```

This is the biggest lift in this plan: it requires a new backend SSE endpoint and a wholly new
Angular real-time consumption path (no existing websocket/SSE/polling infra to build on).

### 5.7 Distributed locks — flagged, not scheduled

Two candidates, neither confirmed as a real race:

1. **Refresh-token rotation** across replicas — before adding a lock, verify whether the existing
   DB-level family-revocation/unique-constraint semantics on `refresh_tokens` already close this.
   Don't add a speculative Redis lock for a race the schema may already prevent.
2. **Serializing the lockout INCR-triggers-MySQL-write step** — the `INCR` itself is already
   race-free; a lock would only matter if the threshold-reached-write-MySQL-lock trigger needed to
   fire exactly once, which isn't confirmed as a problem (a duplicate `lockAccount()` call is
   idempotent).

If a concrete race is confirmed later: **Redisson `RLock`**, not hand-rolled `SET NX PX` + Lua
unlock (§4).

```java
RLock lock = redissonClient.getLock("nexus:identity:lock:refresh-rotation:" + familyId);
boolean acquired = lock.tryLock(500, 2000, TimeUnit.MILLISECONDS);
if (!acquired) {
  throw new RefreshRotationContentionException(...); // fail closed for this specific invariant
}
try {
  // rotate refresh token
} finally {
  lock.unlock();
}
```

### 5.8 Explicitly excluded from this plan

| Capability | Why excluded |
|---|---|
| Leaderboards / sorted-set ranking | No gamification or ranking feature anywhere in the codebase. |
| Geospatial (`GEOADD`/`GEORADIUS`) | No location data model exists. |
| HyperLogLog | No approximate-cardinality/unique-visitor-counting requirement found. |
| RediSearch / autocomplete | No search feature — this is an auth/RBAC platform backend, not a search product. |
| Redis as a primary datastore | MySQL + Flyway remains the system of record (ADR 0003, non-negotiable); Redis is a cache/coordination layer only, never authoritative for anything in this plan. |
| Redis Streams as a general job queue | The existing in-process `AuthEventRetryBuffer` (ADR 0011) + `@Scheduled` already handles bounded-retry audit writes at this scale; Streams usage here is scoped narrowly to RBAC invalidation fan-out. |

Calling these out so a future reader doesn't assume "we have Redis now, might as well use every
feature it offers."

---

## 6. Phased rollout plan

**Phase 1 — Foundation + rate limiting** *(lowest risk: existing port, zero new abstractions)*
`docker-compose.yml` Redis service, `pom.xml` starter, `application.yml` `nexus.redis.*` block,
`RedisRateLimitStore` (§5.1), and an Actuator health indicator (auto-configured once the starter
is on the classpath — `RedisConnectionFactory`/`StringRedisTemplate` beans also come from Spring
Boot's own `RedisAutoConfiguration`, so no custom config class is needed). *Why first*: the port's
own javadoc already promises this exact swap "without changing use-case code" — the cheapest
possible end-to-end validation (docker-compose, connection pooling
under virtual threads, health check, config wiring) before anything security-critical depends on
the new dependency. Draft ADR 0016 (§8) at the start of this phase, since it informs every later
phase's key/TTL/failure-mode decisions.

**Phase 2 — RBAC permission cache + jti denylist + lockout fast-path** *(highest value: the only
phase that unlocks a currently entirely-missing runtime capability)* Wire the RBAC
`application`/`interfaces` layer (the `user_roles → role_permissions → permissions` join) —
required regardless of Redis, since nothing consults the RBAC tables today. Add
`PermissionCachePort`/`RedisPermissionCacheAdapter` (§5.3) as cache-aside in front of that new
query path. Add `JwtDenylistPort`/`RedisJwtDenylistAdapter` (§5.2), finally implementing ADR 0008's
deferred Option B. Add the lockout fast-path `INCR`/`EXPIRE` Lua counter (§5.4) in front of the
unchanged ADR 0009 MySQL write path. *Why here*: resolves two explicitly-deferred ADRs and
delivers the one capability — permission-aware JWTs — that doesn't exist in any form today.

**Phase 3 — Anti-enumeration token migration** *(flagged: evaluate, default to not migrating)*
Per §5.5, the recommended outcome is "keep MySQL, document why" unless a concrete operational
driver appears (e.g. `auth_tokens` demonstrably becoming a bottleneck — nothing today suggests
this). *Why here, not earlier*: the most durability-risky, least performance-justified candidate
identified — sequenced last among "do it" phases, gated on evidence rather than committed to.

**Phase 4 — Real-time permission invalidation (Streams + SSE)** *(biggest lift: frontend is
greenfield here)* Per §5.6: `nexus:rbac:invalidate:stream:{tenant_id}` Streams published after
MySQL commit, a new backend SSE endpoint, a new Angular real-time consumption path. *Why last*:
largest scope for a capability EPIC-002 itself lists as future, with no committed timeline —
sequence once Phases 1–3's foundational Redis usage is proven in production.

**Phase 5 — Distributed locks** *(optional, evidence-gated)* Only if a concrete race is confirmed
during or after Phase 2/3 rollout (§5.7). Redisson isn't added to `pom.xml` until this phase
triggers.

---

## 7. Monitoring & observability

- `spring-boot-starter-data-redis` auto-configures a `PING`-based Redis `HealthIndicator` —
  contributes a `"redis"` component to `/actuator/health` with no extra config beyond the
  (default-`true`) `management.health.redis.enabled`.
- Lettuce/Micrometer integration exports command-latency metrics through the already-present
  `micrometer-registry-prometheus` → `/actuator/prometheus`, matching the existing scrape setup
  rather than adding a second metrics pipeline.
- **What to watch**:
  - `used_memory` / `maxmemory` ratio — alert at 80%; `noeviction` means the next write past 100%
    is a hard failure, not a graceful degrade.
  - `evicted_keys` — should be **zero** given the `noeviction` policy; any nonzero value means
    writes are already being rejected and needs immediate attention.
  - `keyspace_hits` / `keyspace_misses` ratio — especially for the RBAC permission cache; a
    persistently low hit ratio means the 15-min TTL isn't paying for itself relative to its
    staleness cost.
  - `SLOWLOG` entries (alert above ~10ms) — every operation here (`GET`, `SET`, `INCR`, small Lua
    scripts, bounded `ZADD`/`ZREMRANGEBYSCORE`) should be sub-millisecond; a slowlog entry signals
    either an unbounded key or a Redis-side resource problem.
  - Connection pool saturation (`lettuce.pool` metrics vs. configured `max-active`) and
    `connected_clients`.
  - Replica lag / Sentinel failover events, once the Sentinel topology is in place.
- **Redis is excluded from `/actuator/health` entirely** (`management.health.redis.enabled:
  false`), not merely from the readiness/liveness groups. The original design (drafted before
  implementation) proposed mirroring ADR 0012's `authEventDbPrivilege` precedent — visible on the
  aggregate `/actuator/health`, excluded only from the readiness/liveness sub-groups. That
  precedent doesn't actually transfer: `authEventDbPrivilege` stays UP well over 99% of the time
  (a DB-privilege drift is rare), so it almost never drags the aggregate down in practice. Redis is
  routinely *absent* — in unit/slice test contexts, on a dev machine without `docker compose up`,
  in any environment still on `store-type=memory` — so letting Spring Boot's auto-configured Redis
  health indicator into the aggregate makes `/actuator/health` flaky wherever Redis isn't running,
  not just signal a real problem (confirmed the hard way: a `SecurityConfigTest` asserting
  `/actuator/health` returns 200 started failing with 503 in CI, since that test's Spring context
  has no reachable Redis). Given every Redis-backed capability in this plan is designed to fail
  open (§8), Redis reachability is deliberately not a signal of application availability at all —
  it's observed via the Lettuce/Micrometer metrics above instead.

---

## 8. Failure-mode handling, per capability

| Capability | Policy | Rationale |
|---|---|---|
| Rate limiting | **Fail open** — Redis-down ⇒ permit(), log WARN | Defense-in-depth, not the primary auth guarantee (Argon2id + lockout are). Blocking all logins platform-wide because a non-critical dependency hiccupped would be a worse self-inflicted outage than the risk it guards against. |
| JWT jti denylist | **Fail open, with an explicit security callout** — Redis-down ⇒ treat as not-denylisted | Rejecting every token platform-wide on a Redis blip is worse than reverting to ADR 0008's own already-accepted GA baseline (TTL-only, ≤15-min residual window). Must be documented prominently in the runbook — Redis-down silently reverts "near-instant revocation" to the pre-existing accepted baseline, not a new vulnerability, but the degradation must be *loud* (alerted). |
| RBAC permission cache | **Fail to DB** (cache-aside) | Correctness never depends on Redis — MySQL is authoritative; only mint-time latency degrades on a miss or outage. |
| Account lockout counters | **Fail closed to the existing MySQL path** | Brute-force protection must never silently stop working. "Fail closed" here means "revert to the pre-Redis mechanism" (which already handles its own benign race per ADR 0009) — no availability impact, just a temporary loss of the DF-3 fast-path benefit. |
| Anti-enumeration tokens (if ever migrated) | **Would need a fail-closed path that's awkward to build cheaply** | Exactly why §5.5/§6 Phase 3 recommend deferring: unlike the cache/denylist cases, Redis would become load-bearing for completing the reset/verify flow — a clean DB fallback would require maintaining a parallel DB write path anyway, largely negating the migration's benefit. |
| Real-time permission invalidation | **Fail open / degrade to no push** | Redis-down ⇒ the SSE bridge simply stops delivering proactive invalidations; the existing 15-min-cache-TTL / 7-day-refresh backstop (ADR 0013 D4) remains the actual correctness guarantee regardless. Pure UX layer, never a security boundary. |
| Distributed locks (if added) | **Fail closed for whatever invariant the lock protects** | Speculative/Phase 5 — exact policy decided against the concrete confirmed race, not abstractly now. |

---

## 9. Follow-up: ADR 0016

Before Phase 1 begins, draft **ADR 0016 — Redis as an Infrastructure Dependency** from this plan
(out of scope for this document itself). It should:

- Bundle the five converging deferred decisions above (ADR 0008 Option B, ADR 0009's DF-3, ADR
  0013 D4, `InMemoryRateLimitStore`'s multi-replica limitation, US-015's Redis note) into one infra
  ADR — the same way ADR 0013 bundled its four decisions.
- Record the topology (§3), client (§4), keyspace (§5), and per-capability failure-mode (§8)
  decisions as the ADR's core tables.
- State the explicit non-goals (§5.8).
- **Update ADR 0008 and ADR 0009's status** to mark their deferred alternatives ("Option B", "Redis
  atomic increment") as now *adopted*, pointing at ADR 0016, rather than leaving them as
  open-ended future deferrals.
- Add an ArchUnit rule confining Redis client types to `infrastructure/` packages, extending the
  existing hexagonal-layering suite the same way it already restricts JPA/JDBC imports:

  ```java
  noClasses().that().resideInAPackage("..domain..").or().resideInAPackage("..application..")
      .should().dependOnClassesThat().resideInAnyPackage(
          "org.springframework.data.redis..", "io.lettuce..", "org.redisson..")
  ```
