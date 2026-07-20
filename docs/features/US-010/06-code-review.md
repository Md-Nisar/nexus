# US-010 — Code Review

**Feature:** US-010 — Populate JWT with resolved roles and permissions on login
**Branch:** feature/US-010 (no commits yet — reviewed as staged working-tree diff vs. `origin/main`)
**Reviewer:** code-reviewer sub-agent (fresh context)
**Diff scope:** `git diff origin/main...HEAD` was empty (branch has no commits); the diff reviewed was the full working-tree changeset (33 files changed, 1825 insertions, 29 deletions) staged against `origin/main` for review purposes only — nothing was committed.
**Cross-referenced against:** `docs/story/2-rbac/US-010.md` (Acceptance Criteria / Technical Notes — no `docs/features/US-010/03-design.md` exists, since this feature went from plan-mode design straight to implementation), `CLAUDE.md`, `docs/coding-standards.md`.

## Summary

| Severity | Count |
|---|---|
| Blocker | 1 |
| High | 2 |
| Medium | 2 |
| Low | 3 |
| Nit | 1 |

**Verdict: CHANGES REQUESTED** → **Blocker + both High findings fixed** (see Resolution below). Medium/Low/Nit findings are tracked as follow-up, not addressed in this pass.

---

## Resolution

| Finding | Outcome | What changed |
|---|---|---|
| [BLOCKER] Permission cache staleness silently defeats AC6 | **Fixed** | Redesigned the cache to store roles alongside permissions (`PermissionCachePort`/`RedisPermissionCacheAdapter` now key on `ResolvedPermissions`, via two Redis SETs — `roleset` + `permset` — sharing a TTL). `RoleResolutionService` always reads roles live (unchanged) and now uses that live read as a freshness fingerprint: a cache hit whose cached roles don't match the live role set is treated as stale and recomputed immediately. A role assignment/revocation is now reflected on the very next resolution (login or refresh) with zero lag, not bounded by the 15-min TTL. Also wired a real Testcontainers Redis into `RefreshTokenPermissionResolutionIT` (via `@DynamicPropertySource`) so the test genuinely exercises the cache-hit path instead of passing by accident on an unreachable `localhost:6379`. New unit tests in `RoleResolutionServiceTest` (`should_bypassStaleCache_when_liveRolesDifferFromCachedRoles`, `should_bypassStaleCache_when_aRoleWasRevokedSinceCaching`, `should_treatRoleOrder_asIrrelevant_forCacheFreshnessComparison`) directly cover this. |
| [HIGH] JPQL queries don't cross-check `roles.tenant_id` | **Fixed** | `JpaUserRoleRepository.findActiveRoleNames`/`findActivePermissionNames` now join `Role` and require `r.tenantId = :tenantId` in addition to `ur.tenantId = :tenantId`, closing the defense-in-depth gap. |
| [HIGH] No test proves cross-tenant isolation | **Fixed** | Added `should_returnEmpty_when_userHasRoleAssignedInADifferentTenant` (basic isolation) and `should_excludeRole_when_userRolesTenantIdMismatchesTheRolesOwnTenant` (proves the JPQL fix above specifically) to `RoleResolutionServiceIT`. |
| [MEDIUM] `RedisPermissionCacheAdapter.put()` not atomic | Not addressed | Tracked as follow-up; out of scope for this pass. |
| [MEDIUM] Cross-bounded-context dependency (`JwtRs256Service` → `rbac.application`) | Not addressed | Tracked as follow-up; out of scope for this pass. |
| [LOW] TOCTOU in `get()`, duplicated health-indicator code + LIKE-escaping bug, no-op `readOnly=true` | Not addressed | Tracked as follow-up. |
| [NIT] `schemaVersion` parsed but not enforced | Not addressed | Acceptable as scaffolding per original finding. |

**Verification after fixes:** `./mvnw verify -DskipITs` — 618 unit tests (up from 614), 0 checkstyle violations, JaCoCo coverage gate met, 0 SpotBugs findings. Docker was still unavailable in this environment, so the Testcontainers ITs (including the two new cross-tenant tests and the Redis-backed refresh test) were compile-checked but not executed — run `./mvnw verify` (without `-DskipITs`) before merging.

---

## Findings

### [BLOCKER] Permission cache staleness silently defeats AC6 ("token refresh re-resolves permissions") for newly-granted roles

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java:55-64`

`resolve()` is the single entry point used at both login and refresh (per its own Javadoc). `resolvePermissions()` checks the Redis cache keyed only by `(tenantId, userId)` before re-querying the DB. Nothing invalidates that cache when a role is assigned — eviction is explicitly deferred to US-012 (`PermissionCachePort.evict()` is documented as "unused until US-012"). Sequence:

1. User resolves once with no roles → the empty permission set is cached (via the `EMPTY_MARKER` technique) for 15 minutes.
2. A role is assigned.
3. User hits `POST /api/v1/auth/refresh` → `RoleResolutionService.resolve()` re-derives `roles[]` fresh (correct — `"MEMBER"` appears) but `resolvePermissions()` gets a cache **hit** and returns the stale, now-wrong empty permission set.
4. Result: JWT claims `roles=["MEMBER"]` but `permissions=[]` — an internally inconsistent, stale token, for up to 15 minutes after every role grant.

This is exactly Test Scenario 6 / AC6 (P0): *"Role assigned → token refreshed → New access token includes new permission,"* with no staleness tolerance stated. The story's "Out of scope" note ("real-time permission invalidation without re-login") is about pushing updates into an *already-issued* token, not about whether a *fresh* refresh-minted token reflects a grant — AC6 is explicitly about the latter.

The new `RefreshTokenPermissionResolutionIT` is supposed to validate exactly this, but it runs through the full Spring context with the real `RedisPermissionCacheAdapter`, whose `StringRedisTemplate` points at `localhost:6379` (`application.yml` default) — which `application.yml`'s own comment says is "routinely absent in unit/slice test contexts." Because the adapter fails open on any Redis error, if Redis isn't reachable during the test run (the normal case per that comment), every `get()` silently misses and the test passes by accident — never actually exercising the cache path it claims to prove. If Redis *is* reachable (e.g., local dev with `docker compose up`, or once CI adds a shared Redis for full-context tests), this exact test will start failing.

**Why it matters:** A P0, explicitly-tested acceptance criterion is not actually satisfied by the shipped design whenever the cache is warm — which is the common case, not an edge case. Worse, the token becomes internally inconsistent (claims a role with zero permissions), which could confuse or break any code that trusts `permissions[]` as authoritative (the entire stated point of this story).

**Suggested fix:** Either (a) scope the permission-cache TTL tradeoff explicitly against AC6 in the story/ADR and get sign-off that "up to 15 min lag on new grants too" is acceptable, updating Test Scenario 6 accordingly; or (b) invalidate/skip the cache specifically on the refresh path (refresh is comparatively rare/cheap vs. per-request, so re-querying permissions fresh on every refresh — while still caching for other paths — would satisfy AC6 without removing the general cache). At minimum, wire a reachable Redis into `RefreshTokenPermissionResolutionIT` (a Testcontainers Redis, like `RedisPermissionCacheAdapterIT` already does) so the test actually proves the claimed behavior instead of relying on Redis being down.

---

### [HIGH] JPQL role/permission queries trust the denormalized `user_roles.tenant_id` without cross-checking `roles.tenant_id`

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java:20-26, 34-40`

Both `findActiveRoleNames` and `findActivePermissionNames` filter exclusively on `ur.tenantId = :tenantId`. Neither query joins/filters on `Role.tenantId` (the authoritative tenant owner of the role itself). `user_roles.tenant_id` is a copy written at assignment time with no DB constraint (`V5__rbac_schema.sql` has no FK or check tying `user_roles.tenant_id` to `roles.tenant_id` — `roles.tenant_id` isn't even FK'd to anything, per the migration's own comment "no tenants table exists yet"). Correctness of tenant scoping here depends entirely on assignment-time code (US-012, not yet written) always setting `user_roles.tenant_id` consistently with the assigned role's own tenant — with zero redundant verification at read time.

**Why it matters:** This is precisely the class of bug the story flags as its highest-severity risk (AC9 / T-S1 — bootstrap tenant holds `TENANT_ADMIN`, so a tenant mix-up here is privilege escalation, not a data bug). A future US-012 bug that writes a mismatched `tenant_id` on `user_roles` (e.g. assigns a role from tenant A but stamps tenant B due to a copy-paste/parameter-order bug) would go completely undetected by this query and would silently grant/misattribute permissions across tenants — with no defense-in-depth catch.

**Suggested fix:** Add `AND r.tenantId = :tenantId` to `findActiveRoleNames` (joining `Role`, which it already does) and join `Role` in `findActivePermissionNames` purely to add the same redundant check:

```sql
SELECT DISTINCT p.name FROM UserRole ur, Role r, RolePermission rp, Permission p
WHERE ur.roleId = r.id AND r.tenantId = :tenantId
  AND ur.roleId = rp.id.roleId AND rp.id.permissionId = p.id
  AND ur.userId = :userId AND ur.tenantId = :tenantId
  AND ur.revokedAt IS NULL
```

This costs nothing extra (`Role` is already effectively free to join) and turns a silent cross-tenant leak into either a correct empty result or (with an added assertion/metric) a detectable anomaly.

---

### [HIGH] No test proves cross-tenant isolation — the single highest-risk assertion in this story is untested

**File:** `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleResolutionServiceIT.java` (whole file)

Every test in this file (and in `RefreshTokenPermissionResolutionIT`) resolves against `BOOTSTRAP_TENANT_ID` only — the sole tenant with seeded roles. There is no test that: (a) creates a second, non-bootstrap tenant's role, assigns it to a user, and asserts that resolving with the *wrong* `tenantId` returns empty roles/permissions (proving isolation); nor (b) asserts that a user with roles in tenant A gets nothing when queried under tenant B even though the `userId` matches.

**Why it matters:** AC9/T-S1 is called out by name in the story as the one scenario that, if wrong, is a privilege-escalation bug rather than a data bug. Given that, and combined with the previous finding (no `r.tenantId` cross-check in the query itself), this is the one test that most needed to exist and doesn't.

**Suggested fix:** Add a test seeding a second tenant + role (e.g., insert directly via `JpaRoleRepository`/`JpaUserRoleRepository` in the IT, no migration seed needed) and assert `roleResolutionService.resolve(userId, otherTenantId)` returns `ResolvedPermissions.empty()` even though the user has active roles under their real tenant.

---

### [MEDIUM] `RedisPermissionCacheAdapter.put()` is not atomic — a partial failure can leave a permanently non-expiring cache entry

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java:69-82`

`put()` issues three separate Redis round-trips (`delete`, `opsForSet().add(...)`, `expire(...)`) wrapped in a single try/catch that only logs on failure. If the connection drops (or times out) between `add()` succeeding and `expire()` running, the exception is swallowed and the method returns normally — but the key now has members with **no TTL**. It will never expire on its own.

**Why it matters:** The entire staleness analysis in this PR (and `application.yml`'s inline comment: "a stale cache only widens the window... TTL 15 min") assumes the worst case is a bounded 15-minute lag. This code path breaks that assumption: a single transient Redis hiccup at exactly the wrong moment can pin a user's permission set (correct or already-stale) in the cache indefinitely, until they happen to log in/refresh again (which overwrites it) — which could be days, given refresh tokens have a 7-day TTL. Combined with `evict()` also failing open (US-012's future invalidation calls could silently no-op the same way), a revoked permission could theoretically outlive the documented 15-minute bound by a wide margin, not just "a bit more" as currently reasoned about.

**Suggested fix:** Set the TTL as part of the same operation, or make the sequence effectively atomic, e.g. issue `add` then `expire` inside `redisTemplate.execute(new SessionCallback<>() {...})` with `MULTI`/`EXEC`, or catch failure between add/expire specifically and best-effort `delete(key)` in that catch branch so a partial write never lingers instead of silently persisting forever.

---

### [MEDIUM] Cross-bounded-context dependency bypasses identity's own port abstraction

**File:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java:11-12, 168`

`JwtRs256Service` (`identity.infrastructure.security`) imports and directly constructor-injects `com.example.nexus.rbac.application.RoleResolutionService` (a concrete application-layer `@Service` from a different bounded context) and `com.example.nexus.rbac.domain.ResolvedPermissions`. This is the only cross-context import in the codebase today (verified — no other `identity` file imports `rbac` or vice versa). ArchUnit's `HexagonalArchitectureTest` doesn't catch this because its rules are per-package-pattern ("`..domain..`" must not depend on "`..application..`"/"`..infrastructure..`", etc.) rather than per-bounded-context, so infrastructure→application is technically "outer depending on inner" and passes — but it's *another context's* inner layer, not identity's own.

**Why it matters:** This creates a hard compile-time coupling from `identity` straight into `rbac`'s application service, bypassing the port/adapter seam that the rest of this codebase uses everywhere else for exactly this kind of cross-cutting capability. It undermines the "modular monolith" premise (contexts should be separable/extractable) and makes identity's infrastructure layer untestable/uncompilable without `rbac` on the classpath. It also means a future rename/refactor inside `rbac.application` ripples directly into identity's infrastructure layer with no port to insulate it.

**Suggested fix:** Define a port in identity's own application layer (e.g., `identity.application.port.out.RoleAndPermissionResolutionPort` with a `resolve(UUID userId, UUID tenantId)` method returning a small identity-owned value type), have `rbac`'s own infrastructure (or a thin adapter) implement it by delegating to `RoleResolutionService`, and inject the port into `JwtRs256Service` instead of the concrete `rbac` class. This is a fairly mechanical follow-up, not a rewrite.

---

### [LOW] Minor TOCTOU in `RedisPermissionCacheAdapter.get()` at the TTL boundary

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java:49-66`

`hasKey(key)` and `opsForSet().members(key)` are two separate Redis round-trips. If the key's TTL expires in the (small) window between them, `members()` can return `null`/empty, and the code interprets that as `Optional.of(List.of())` — i.e., "cache hit, permission set is empty" — rather than falling through to the DB.

**Why it matters:** In the extremely narrow window where this race fires, a user with real permissions could momentarily be resolved as having none. This fails toward denial rather than escalation (safer direction), and the window is tiny, so this is low severity, but it's avoidable.

**Suggested fix:** Prefer a single round trip — call `members(key)` directly rather than `hasKey` + `members`; alternatively use a Lua script (`EXISTS` + `SMEMBERS` atomically) if this needs to be airtight. Given severity, this is a nice-to-have, not blocking.

---

### [LOW] ~140 lines duplicated verbatim between the two DB-privilege health indicators, and both share a LIKE-wildcard escaping bug

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacDbPrivilegeHealthIndicator.java:110-125, 131-143`

**Problem 1 (duplication):** `RbacDbPrivilegeHealthIndicator` is a near-line-for-line copy of the pre-existing `AuthEventDbPrivilegeHealthIndicator` (`identity/infrastructure/audit/`) — same `readCurrentUser`/`usernamePart` helpers, same overall `health()` structure, differing only in table name and which privilege types are checked (`UPDATE`+`DELETE` vs. `DELETE`-only).

**Problem 2 (bug, inherited from the original):** `preparedStatement.setString(2, "'" + userName + "'@%")` builds a SQL `LIKE` pattern from the raw username without escaping LIKE metacharacters. `userName` values like `nexus_app` contain a literal `_`, which in a LIKE pattern matches *any single character* — so this pattern will also match unrelated grantees like `nexusXapp`. This is present in both the new indicator and the original it mirrors.

**Why it matters:** The duplication makes future changes (e.g., adding a new privilege type to check) a two-file, easy-to-forget-one edit. The LIKE bug can produce false-positive DOWN reports if a differently-named DB user happens to differ from `nexus_app` by exactly one character in that position — low security impact (DB username isn't attacker-controlled) but a real correctness gap in a security-observability signal.

**Suggested fix:** Extract a shared `AbstractDbPrivilegeHealthIndicator(DataSource, String tableName, Set<String> privilegeTypes)` base class (or a small helper class) that both indicators delegate to, and escape `_`/`%`/`\` in `userName` before building the LIKE pattern, or compare `GRANTEE` via exact reconstruction / regex match in Java post-fetch instead of `LIKE`. Not a blocker for this PR since it's inherited behavior, but worth a follow-up ticket covering both indicators.

---

### [LOW] `RoleResolutionService`'s `@Transactional(readOnly = true)` is a no-op on both current call paths

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java:24`

Both current callers — `LoginUseCase` and `RefreshTokenUseCase` — are themselves `@Transactional` (default, read-write) at the class level. With Spring's default `REQUIRED` propagation, `RoleResolutionService.resolve()` joins the caller's already-open, non-readOnly transaction; the `readOnly = true` attribute here has no effect once joining an existing transaction (it only takes effect when a *new* transaction is started).

**Why it matters:** Not a bug, but a misleading annotation — a reader could reasonably assume this method gets JPA's read-only optimizations (e.g., dirty-checking skipped, potential read-replica routing) when it currently never does, given its only two call sites.

**Suggested fix:** Either add a short comment noting this is aspirational/defensive for future non-transactional callers, or drop `readOnly = true` if it's not meant to signal something for a future caller.

---

### [NIT] `JwtClaims.schemaVersion` is parsed and exposed but never used to gate/branch anything

**File:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java:134-135`

`schemaVersion` is required to be present (null-checked) but its actual value is never compared against `JwtClaims.CURRENT_VERSION` during `verify()` — any non-null integer passes. Effectively, forward-compatibility enforcement today comes entirely from the *other* required fields (`permissions` being non-null etc.), not from the `schema_version` claim itself.

**Why it matters:** Purely informational for now — fine as forward-looking scaffolding for a future V3, and the AC only requires it be present/bumped, which it is. Just flagging so it isn't mistaken for enforcement it doesn't provide.

**Suggested fix:** None required now; if a future migration needs strict version gating, add `if (schemaVersion > JwtClaims.CURRENT_VERSION) reject` at that time (a lower version should still degrade gracefully via the individual field-presence checks, as today).

---

## Things done well

- `ResolvedPermissions`'s dedup+sort in the compact constructor is clean and well-tested (`ResolvedPermissionsTest`), and correctly used to guarantee deterministic JWT claim ordering.
- The `EMPTY_MARKER` technique in `RedisPermissionCacheAdapter` to distinguish "cached empty" from "cache miss" is a good, well-documented, well-tested (unit + IT) solution to a real SADD limitation.
- `JwtClaims`/`JwtRs256Service` contract handling is thorough — every new claim is defensive-copied, null-checked symmetrically between issue/verify, and the existing freeze-gate contract test was correctly extended rather than loosened.
- `RbacDbPrivilegeHealthIndicator` correctly never issues a live DELETE to "test" the grant, and is properly excluded from liveness/readiness without any `application.yml` change needed — good reuse of the existing exclusion mechanism.
- Good test hygiene throughout: fail-open paths for the Redis adapter are unit-tested with mocked `StringRedisTemplate` *and* IT-tested against a real Testcontainers Redis instance covering the actual failure mode.
- The `UuidV7Converter` auto-apply reliance in the new JPQL (rather than an explicit `@Convert`) was verified correct against the entity mappings — good attention to a genuinely tricky Hibernate detail.
