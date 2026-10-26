# Data-structure choices (T3, T4, T8)

Use this only when a trigger fires and **n** is known or bounded. Below about 10³ elements, pick the most readable structure; the choice does not matter for performance.

## Choice table

| Problem | Small n / low limit | Large n / high limit | Notes |
|---|---|---|---|
| Rate limit, per key | Sliding-window **log**: a deque in memory, or a Redis ZSET via Lua. Exact; memory is O(limit) per key. Good up to about 100 per window. | Sliding-window **counter** (two fixed buckets, O(1)) or **GCRA** (one timestamp, O(1)). Use it for per-tenant quotas of thousands per minute. | Redis: run in one Lua script, use `redis.call('TIME')` rather than the app clock, and make each member unique (pass a request id). |
| Token revocation | — | **Per-user watermark**: key `nbf:{userId}` = epoch seconds, TTL = access-token TTL. One `GET` per request; reject when `iat < nbf`. | A jti denylist can only revoke the tokens it is told about. It cannot revoke a user's other tokens, and every revocation here is per user. |
| Membership test | `Set`, or even a `List`. Examples: about 8 permissions (US-011, US-013). | Static corpus of 10⁵–10⁶ entries: a `HashSet<String>` costs about 60–100 MB. Use a sorted `long[]` of 64-bit hashes with binary search (8 B per entry), or a **Bloom filter** (about 1.2 MB per 1M entries at 1% false positives) where a false positive is acceptable. | Password denylist: a false positive only means "choose another password". |
| Subset / difference | `HashSet` of the larger side, then scan the other: O(\|a\| + \|b\|). Model: grant-subset in `RoleAssignmentService`. | Same algorithm. Push the work into SQL (anti-join) only when the sets live in the DB and are large. | "Replace a set" (e.g. a role's permissions): compute to-add and to-remove once, then bulk insert and bulk delete. Don't call add/remove per element. |
| Bounded buffer | `ArrayBlockingQueue.offer` (non-blocking) with an explicit drop policy and a drop metric. Model: ADR 0011 lanes. | Outbox table, if loss is unacceptable. | Never use an unbounded queue (`spring-boot-standards` → Resilience). |
| Per-key in-memory state | Map with a size cap. Each key is evicted on **its own** window (Caffeine `maximumSize` + `expireAfter`). | Move to Redis, because the limit must hold across instances. | Per-instance state multiplies limits by replica count. |
| Retention on append-mostly tables | Batched `DELETE … WHERE id < uuidv7_floor(cutoff) LIMIT k` on the clustered UUIDv7 primary key (ADR 0005); no extra index needed. | `PARTITION BY RANGE` on UUIDv7 boundaries, then `DROP PARTITION`. This also works where triggers block `DELETE` (`auth_events`). | Keep revoked tokens until their original expiry, so reuse detection still works. |

## Not worth it here

- **Bitsets or `EnumSet` for permissions:** not worth it until there are thousands, or a profile says otherwise.
- **A token bucket instead of the sliding log for login limits** of 5–30: no material gain.
- **A cache in front of a query** that runs at login or refresh rather than per request.
