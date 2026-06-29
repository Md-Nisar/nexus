#!/bin/bash
# =============================================================================
# EPIC-002 — RBAC Foundation
# GitHub CLI setup script
# Repo: Md-Nisar/nexus
#
# Prerequisites:
#   1. Install GitHub CLI: https://cli.github.com
#   2. Authenticate:       gh auth login
#   3. Run this script from anywhere:
#        chmod +x create-epic-002.sh
#        ./create-epic-002.sh
# =============================================================================

set -e  # Exit immediately on any error

REPO="Md-Nisar/nexus"

echo ""
echo "============================================="
echo " EPIC-002 — RBAC Foundation Setup"
echo " Repo: $REPO"
echo "============================================="
echo ""

# -----------------------------------------------------------------------------
# STEP 1 — Create Labels
# -----------------------------------------------------------------------------
echo "► Creating labels..."

gh label create "epic:rbac"            --repo "$REPO" --color "7B61FF" --description "All issues in EPIC-002 RBAC" --force
gh label create "type:feature"         --repo "$REPO" --color "0075CA" --description "Feature story" --force
gh label create "type:schema"          --repo "$REPO" --color "E4E669" --description "Migration / DB story" --force
gh label create "type:security"        --repo "$REPO" --color "D93F0B" --description "Security-enforcing story" --force
gh label create "type:frontend"        --repo "$REPO" --color "0E8A16" --description "Angular / frontend story" --force
gh label create "type:audit"           --repo "$REPO" --color "BFD4F2" --description "Audit / compliance story" --force
gh label create "priority:p0"          --repo "$REPO" --color "B60205" --description "Must ship this epic" --force
gh label create "priority:p1"          --repo "$REPO" --color "FF9F1C" --description "Should ship this epic" --force
gh label create "blocked:needs-review" --repo "$REPO" --color "CCCCCC" --description "Gate 1 not cleared" --force
gh label create "status:ready-for-dev" --repo "$REPO" --color "0E8A16" --description "Gate 1 cleared — ready for development" --force

echo "✓ Labels created"
echo ""

# -----------------------------------------------------------------------------
# STEP 2 — Create Milestone
# -----------------------------------------------------------------------------
echo "► Creating milestone..."

gh api repos/$REPO/milestones \
  --method POST \
  --field title="EPIC-002 — RBAC Foundation" \
  --field description="Delivers a Roles + Permissions model scoped to tenants. Populates the JWT roles[] and permissions[] claims, enforces permission checks on all API endpoints via @RequiresPermission, and provides Angular route guards and directives for frontend access control. Unblocks EPIC-003 (Tenant Management).

Blocked by: EPIC-001 (US-001 schema, US-003 JWT contract, US-008 audit pipeline)
Blocks: EPIC-003 Tenant Management

Total points: 24
Stories: US-009, US-010, US-011, US-012, US-013, US-014" \
  --field state="open" \
  > /tmp/milestone_response.json

MILESTONE_NUMBER=$(cat /tmp/milestone_response.json | grep '"number"' | head -1 | grep -o '[0-9]*')
echo "✓ Milestone created — number: $MILESTONE_NUMBER"
echo ""

# -----------------------------------------------------------------------------
# STEP 3 — Create Issues
# -----------------------------------------------------------------------------
echo "► Creating issues..."
echo ""

# ---- US-009 ----
echo "  Creating US-009..."
gh issue create \
  --repo "$REPO" \
  --milestone "EPIC-002 — RBAC Foundation" \
  --label "epic:rbac,type:schema,priority:p0,blocked:needs-review" \
  --title "US-009 — Establish RBAC data model and seed system roles and permissions" \
  --body '## GitHub Issue Metadata
**Milestone:** EPIC-002 — RBAC Foundation
**Labels:** `epic:rbac` `type:schema` `priority:p0` `blocked:needs-review`
**Story Points:** 5
**Blocked by:** US-001 (V2 migration must be applied)
**Blocks:** US-010, US-011, US-012 — and EPIC-003 kickoff gate

---

## User Story

As a platform development team,
I want a roles and permissions schema with system roles seeded via migration,
So that all future features have a stable, tenant-scoped permission model to build on.

---

## Background / Context

Extends the EPIC-001 schema (V2) with 4 new tables via Flyway migration `V3__rbac_schema.sql`.
System roles (`TENANT_ADMIN`, `MEMBER`) and the full permission set are seeded in the migration —
not configurable at runtime in Epic 2. `user_roles` uses soft-delete (`revoked_at`) to preserve
audit history; hard delete is blocked by a `BEFORE DELETE` trigger. This story is the gate for
Epic 3 kickoff: `TENANT_ADMIN` must exist before Tenant Management can enforce admin boundaries.

**Target database:** MySQL 8.4 Community
**ID strategy:** UUIDv7 stored as `BINARY(16)` — established in ADR-001
**Prerequisite:** ADR-003 (RBAC model + permission naming convention) signed off before merge

---

## Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | All 4 RBAC tables created | Flyway `V3__rbac_schema.sql` creates `permissions`, `roles`, `role_permissions`, `user_roles` with all columns and indexes; verified via Testcontainers | P0 |
| AC-2 | System permissions seeded | All 7 permissions (`tenant:read`, `tenant:write`, `user:read`, `user:write`, `role:read`, `role:write`, `audit:read`) present after migration | P0 |
| AC-3 | System roles seeded with correct permissions | `TENANT_ADMIN` has all 7 permissions; `MEMBER` has `user:read` only; verified by join query | P0 |
| AC-4 | `user_roles` hard delete blocked | `BEFORE DELETE` trigger raises `SQLSTATE '"'"'45000'"'"'`; test confirms DELETE fails | P0 |
| AC-5 | Tenant isolation on roles | Two roles with same name in different `tenant_id` values persist; same name in same tenant raises unique constraint | P0 |
| AC-6 | Migration clean-forward in CI | Testcontainers: V1 → V2 → V3 migration chain succeeds | P1 |

---

## Schema Specification

### `permissions`
```sql
CREATE TABLE permissions (
    id           BINARY(16)   NOT NULL,
    name         VARCHAR(64)  NOT NULL,
    description  VARCHAR(255) NOT NULL,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_permission_name (name)
);
```

### `roles`
```sql
CREATE TABLE roles (
    id             BINARY(16)   NOT NULL,
    tenant_id      BINARY(16)   NOT NULL,
    name           VARCHAR(64)  NOT NULL,
    description    VARCHAR(255) NULL,
    is_system_role BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_role_tenant_name (tenant_id, name),
    INDEX idx_roles_tenant (tenant_id)
);
```

### `role_permissions`
```sql
CREATE TABLE role_permissions (
    role_id       BINARY(16) NOT NULL,
    permission_id BINARY(16) NOT NULL,
    created_at    TIMESTAMP  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_rp_role       FOREIGN KEY (role_id)       REFERENCES roles(id),
    CONSTRAINT fk_rp_permission FOREIGN KEY (permission_id) REFERENCES permissions(id)
);
```

### `user_roles`
```sql
CREATE TABLE user_roles (
    id          BINARY(16) NOT NULL,
    user_id     BINARY(16) NOT NULL,
    role_id     BINARY(16) NOT NULL,
    tenant_id   BINARY(16) NOT NULL,
    assigned_by BINARY(16) NOT NULL,
    assigned_at TIMESTAMP  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at  TIMESTAMP  NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_ur_user     FOREIGN KEY (user_id)     REFERENCES users(id),
    CONSTRAINT fk_ur_role     FOREIGN KEY (role_id)     REFERENCES roles(id),
    CONSTRAINT fk_ur_assigner FOREIGN KEY (assigned_by) REFERENCES users(id),
    INDEX idx_ur_user_tenant (user_id, tenant_id),
    INDEX idx_ur_role (role_id)
);
CREATE UNIQUE INDEX uq_user_role_active ON user_roles (user_id, role_id) WHERE revoked_at IS NULL;
```

---

## Claude Code — Implementation Tasks

### Task 1 — Flyway migration
**File:** `src/main/resources/db/migration/V3__rbac_schema.sql`
- Create all 4 tables in dependency order: `permissions` → `roles` → `role_permissions` → `user_roles`
- Add `BEFORE DELETE` trigger on `user_roles`
- Seed 7 permissions
- Seed `TENANT_ADMIN` (all 7 permissions) and `MEMBER` (`user:read` only)

### Task 2 — JPA entities
**Package:** `com.example.nexus.rbac.domain`

| Class | Table | Notes |
|---|---|---|
| `Permission.java` | `permissions` | `@Entity`; `@Id` as `byte[]` with `UuidBinaryConverter` |
| `Role.java` | `roles` | `@Entity`; `@ManyToMany` to `Permission` via `role_permissions` |
| `UserRole.java` | `user_roles` | `@Entity`; `revokedAt` nullable; explicit join entity for audit fields |

Reuse `UuidBinaryConverter.java` from EPIC-001 — do not duplicate.

### Task 3 — Repositories
**Package:** `com.example.nexus.rbac.repository`

```java
// RoleRepository.java
Optional<Role> findByTenantIdAndName(byte[] tenantId, String name);
List<Role> findAllByTenantId(byte[] tenantId);

// UserRoleRepository.java
List<UserRole> findActiveByUserIdAndTenantId(byte[] userId, byte[] tenantId);

// PermissionRepository.java
List<Permission> findAllByRoleId(byte[] roleId);
```

### Task 4 — Testcontainers integration test
**File:** `src/test/java/com/example/nexus/rbac/migration/V3MigrationTest.java`
- All 4 tables exist after migration
- 7 permissions seeded with correct names
- `TENANT_ADMIN` has 7 `role_permissions` rows
- `MEMBER` has 1 `role_permissions` row (`user:read`)
- DELETE on `user_roles` throws `DataIntegrityViolationException`
- Duplicate role name in same tenant throws `ConstraintViolationException`

---

## Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | V1 → V2 → V3 migration on clean MySQL 8.4 | Integration | All tables, indexes, seed data present |
| T-2 | Duplicate role name same tenant | Integration | Unique constraint violation |
| T-3 | Same role name different tenants | Integration | Both rows persist |
| T-4 | DELETE on `user_roles` row | Security | `DataIntegrityViolationException` |
| T-5 | `TENANT_ADMIN` permissions join | Integration | Returns all 7 permission names |
| T-6 | `MEMBER` permissions join | Integration | Returns `user:read` only |

---

## Definition of Done

- [ ] `V3__rbac_schema.sql` committed and passes Flyway checksum in CI
- [ ] All 4 JPA entities created with correct mappings
- [ ] All 3 repositories created with required query methods
- [ ] `V3MigrationTest.java` green in CI (Testcontainers MySQL 8.4)
- [ ] No Hibernate schema validation warnings on startup
- [ ] ADR-003 linked in PR description
- [ ] PR reviewed and approved

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Partial unique index on `user_roles` not supported | Low | High | Verify in Testcontainers before merge |
| ADR-003 sign-off delays sprint start | Med | High | Start ADR draft in pre-sprint |'

echo "  ✓ US-009 created"

# ---- US-010 ----
echo "  Creating US-010..."
gh issue create \
  --repo "$REPO" \
  --milestone "EPIC-002 — RBAC Foundation" \
  --label "epic:rbac,type:feature,priority:p0,blocked:needs-review" \
  --title "US-010 — Populate JWT with resolved roles and permissions on login" \
  --body '## GitHub Issue Metadata
**Milestone:** EPIC-002 — RBAC Foundation
**Labels:** `epic:rbac` `type:feature` `priority:p0` `blocked:needs-review`
**Story Points:** 3
**Blocked by:** US-009 (RBAC schema), US-003 (JWT issuance)
**Blocks:** US-011, US-013

---

## User Story

As an authenticated user,
I want my roles and permissions included in my JWT on login,
So that every API and frontend permission check works without an extra database call per request.

---

## Background / Context

US-003 left `roles[]` as a placeholder empty array in the JWT. This story populates it — and adds
a `permissions[]` claim — by resolving `user → active user_roles → role_permissions → permissions`
at login time for the user'"'"'s tenant. The JWT is the single authority for permission checks;
no DB call is made per request. Redis caches the resolved permission set to keep login latency
within the 300ms p95 target.

**Token contract addition (frozen after this story):**
```json
{
  "sub": "<user-uuid>",
  "tenant_id": "<tenant-uuid>",
  "roles": ["TENANT_ADMIN"],
  "permissions": ["tenant:read", "tenant:write", "user:read", "user:write", "role:read", "role:write", "audit:read"],
  "token_version": 0
}
```

**Cache:** Redis key `permissions:{tenant_id}:{user_id}` TTL 15 min. Warmed on login. Invalidated by US-012 on role change.

---

## Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | `roles` claim populated on login | JWT `roles[]` contains names of all active (non-revoked) roles for the user in their tenant | P0 |
| AC-2 | `permissions` claim populated on login | JWT `permissions[]` contains deduplicated union of all permissions across the user'"'"'s active roles | P0 |
| AC-3 | Revoked roles excluded | Role with `revoked_at IS NOT NULL` absent from both claims | P0 |
| AC-4 | User with no roles gets empty claims | `roles: []`, `permissions: []` — login succeeds; no error thrown | P0 |
| AC-5 | JWT size within limit | Token with 5 roles + 20 permissions is < 4KB | P1 |
| AC-6 | Token refresh re-resolves permissions | New access token from `/auth/refresh` reflects role changes since last login | P0 |

---

## Claude Code — Implementation Tasks

### Task 1 — RoleResolutionService
**File:** `src/main/java/com/example/nexus/rbac/service/RoleResolutionService.java`

```java
@Service
@RequiredArgsConstructor
public class RoleResolutionService {
    private final UserRoleRepository userRoleRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    private static final Duration CACHE_TTL = Duration.ofMinutes(15);

    public ResolvedPermissions resolve(byte[] userId, byte[] tenantId) { ... }
    public void invalidateCache(byte[] userId, byte[] tenantId) { ... }
    private String cacheKey(byte[] tenantId, byte[] userId) {
        return "permissions:" + toHex(tenantId) + ":" + toHex(userId);
    }
}
```

**Record:**
```java
// ResolvedPermissions.java
public record ResolvedPermissions(List<String> roleNames, List<String> permissionNames) {
    public static ResolvedPermissions empty() {
        return new ResolvedPermissions(List.of(), List.of());
    }
}
```

**Repository queries to add:**
```java
// UserRoleRepository.java
@Query("SELECT DISTINCT p.name FROM UserRole ur JOIN ur.role r JOIN r.permissions p WHERE ur.userId = :userId AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL")
List<String> findActivePermissionNames(@Param("userId") byte[] userId, @Param("tenantId") byte[] tenantId);

@Query("SELECT r.name FROM UserRole ur JOIN ur.role r WHERE ur.userId = :userId AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL")
List<String> findActiveRoleNames(@Param("userId") byte[] userId, @Param("tenantId") byte[] tenantId);
```

### Task 2 — Modify JwtTokenService
**File:** `src/main/java/com/example/nexus/identity/service/JwtTokenService.java`
*(modify — created in US-003)*

```java
// Inject RoleResolutionService
// In buildAccessTokenClaims() replace empty placeholder:
ResolvedPermissions resolved = roleResolutionService.resolve(user.getId(), user.getTenantId());
claims.put("roles", resolved.roleNames());
claims.put("permissions", resolved.permissionNames());
```

### Task 3 — Update JWT contract test
**File:** `src/test/java/com/example/nexus/identity/JwtContractTest.java`
*(extend — created in US-003)*
- Assert `permissions` claim exists and is `List<String>`
- Assert `roles` populated for `TENANT_ADMIN` user
- Assert both claims are empty lists for user with no roles
- Assert token size < 4096 bytes for user with 5 roles + 20 permissions

### Task 4 — Redis configuration
**File:** `src/main/java/com/example/nexus/config/RedisConfig.java`
```java
// Configure RedisTemplate<String, Object> bean
// StringRedisSerializer for keys; Jackson2JsonRedisSerializer for values
```
**application.yml:**
```yaml
rbac.cache.permission-ttl-minutes: 15
```

---

## Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | Login with `TENANT_ADMIN` role | Integration | JWT contains all 7 permissions |
| T-2 | Login with `MEMBER` role | Integration | JWT contains `user:read` only |
| T-3 | Login with no roles | Integration | `roles: []`, `permissions: []`; 200 |
| T-4 | Login with revoked role | Integration | Revoked role absent from JWT |
| T-5 | JWT size: 5 roles + 20 permissions | Performance | Token < 4KB |
| T-6 | Role assigned → token refreshed | Integration | New access token includes new permission |
| T-7 | Redis unavailable — fallback to DB | Integration | Login succeeds; permissions resolved from DB |

---

## Definition of Done

- [ ] `RoleResolutionService.java` created with Redis cache + DB fallback
- [ ] `ResolvedPermissions.java` record created
- [ ] `JwtTokenService.java` updated — both claims populated
- [ ] `UserRoleRepository` extended with active role/permission queries
- [ ] `JwtContractTest.java` updated — new assertions green in CI
- [ ] Redis config in place; TTL configurable
- [ ] Token size benchmark test passing
- [ ] No regression on US-003 login tests

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| JWT bloat with large permission sets | Med | Med | Benchmark at T-5; short permission strings only |
| Redis unavailable causes login failure | Low | High | DB fallback — Redis failure must not propagate |'

echo "  ✓ US-010 created"

# ---- US-011 ----
echo "  Creating US-011..."
gh issue create \
  --repo "$REPO" \
  --milestone "EPIC-002 — RBAC Foundation" \
  --label "epic:rbac,type:security,priority:p0,blocked:needs-review" \
  --title "US-011 — Enforce permission checks on API endpoints via Spring Security" \
  --body '## GitHub Issue Metadata
**Milestone:** EPIC-002 — RBAC Foundation
**Labels:** `epic:rbac` `type:security` `priority:p0` `blocked:needs-review`
**Story Points:** 5
**Blocked by:** US-010 (JWT must contain `permissions[]` claim)
**Blocks:** US-012, US-013 — and all future epics that protect endpoints

---

## User Story

As a development team,
I want a standard `@RequiresPermission` annotation that enforces tenant-scoped permission checks on any API endpoint,
So that every future feature can be secured with a single annotation and no bespoke auth logic.

---

## Background / Context

The enforcement contract all future epics consume. Reads permissions from the JWT — no DB call per
request. The tenant boundary is enforced in `TenantAwarePermissionEvaluator`: a permission granted
in Tenant A **never** satisfies a check in Tenant B. Cross-tenant bypass is a critical security failure.

**Usage contract for future developers:**
```java
@GetMapping("/tenants/{tenantId}")
@RequiresPermission("tenant:read")
public ResponseEntity<TenantDto> getTenant(@PathVariable UUID tenantId) { ... }
```
No other configuration required.

---

## Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | `@RequiresPermission` enforces correctly | Method annotated returns 403 if JWT `permissions[]` does not contain the required permission | P0 |
| AC-2 | Tenant boundary enforced | User with `tenant:write` in Tenant A receives 403 on Tenant B endpoint — even if permission name matches | P0 |
| AC-3 | 403 response contract consistent | All failures return `403 + RBAC_001 + { "required_permission": "<name>", "message": "..." }` | P0 |
| AC-4 | Unauthenticated returns 401 not 403 | Missing/invalid JWT returns 401; permission check only reached for authenticated requests | P0 |
| AC-5 | Annotation usable on any controller | `@RequiresPermission` on new endpoint compiles and enforces without additional wiring | P0 |
| AC-6 | Permission check latency | Adds < 5ms to p95 response time on cache-hit path | P1 |

---

## Claude Code — Implementation Tasks

### Task 1 — `@RequiresPermission` annotation
**File:** `src/main/java/com/example/nexus/rbac/security/RequiresPermission.java`
```java
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("@tenantAwarePermissionEvaluator.hasPermission(authentication, #tenantId, '"'"'{permission}'"'"')")
public @interface RequiresPermission {
    String value();
}
```

### Task 2 — TenantAwarePermissionEvaluator
**File:** `src/main/java/com/example/nexus/rbac/security/TenantAwarePermissionEvaluator.java`
```java
@Component("tenantAwarePermissionEvaluator")
public class TenantAwarePermissionEvaluator {
    public boolean hasPermission(Authentication auth, UUID tenantId, String permission) {
        // CRITICAL: both must be true
        boolean hasTenantMatch = jwtTenantId.equals(tenantId);
        boolean hasPermission  = permissions.contains(permission);
        return hasTenantMatch && hasPermission;
    }
}
```

### Task 3 — Enable method security
**File:** `src/main/java/com/example/nexus/config/SecurityConfig.java`
```java
@EnableMethodSecurity(prePostEnabled = true)  // Add this annotation
```

### Task 4 — 403 error handler
**File:** `src/main/java/com/example/nexus/common/exception/GlobalExceptionHandler.java`
```java
@ExceptionHandler(AccessDeniedException.class)
public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex) {
    ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
    problem.setProperty("error_code", "RBAC_001");
    problem.setProperty("required_permission", extractPermissionFromException(ex));
    problem.setDetail("You do not have permission to perform this action");
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(problem);
}
```

### Task 5 — Verification controller (temporary)
**File:** `src/main/java/com/example/nexus/rbac/controller/RbacHealthController.java`
```java
@GetMapping("/api/v1/rbac/check")
@RequiresPermission("role:read")
public ResponseEntity<String> permissionCheck() {
    return ResponseEntity.ok("permission granted");
}
```
Remove or mark for deletion after US-012.

---

## Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | Caller JWT contains required permission | Integration | 200 |
| T-2 | Caller JWT missing required permission | Integration | 403 + `RBAC_001` |
| T-3 | Permission matches but wrong tenant | **Security — mandatory CI gate** | 403 |
| T-4 | No JWT on request | Integration | 401 (not 403) |
| T-5 | JWT with invalid signature + injected permissions | Security | 401 |
| T-6 | 200 RPS on guarded endpoint | Performance | p95 < 300ms |

---

## Definition of Done

- [ ] `RequiresPermission.java` annotation created
- [ ] `TenantAwarePermissionEvaluator.java` created with tenant boundary logic
- [ ] `@EnableMethodSecurity` added to `SecurityConfig.java`
- [ ] `GlobalExceptionHandler.java` handles `AccessDeniedException` → 403 + `RBAC_001`
- [ ] **T-3 cross-tenant test green — mandatory; PR cannot merge without it**
- [ ] Performance result documented in PR description
- [ ] Developer guide entry written

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Cross-tenant boundary bug in evaluator | Low | **Critical** | T-3 is a mandatory CI gate |
| SpEL `{permission}` binding not resolving | Med | High | Verify in unit test before wiring to production controllers |'

echo "  ✓ US-011 created"

# ---- US-012 ----
echo "  Creating US-012..."
gh issue create \
  --repo "$REPO" \
  --milestone "EPIC-002 — RBAC Foundation" \
  --label "epic:rbac,type:feature,priority:p0,blocked:needs-review" \
  --title "US-012 — Enable role assignment and revocation API" \
  --body '## GitHub Issue Metadata
**Milestone:** EPIC-002 — RBAC Foundation
**Labels:** `epic:rbac` `type:feature` `priority:p0` `blocked:needs-review`
**Story Points:** 5
**Blocked by:** US-009 (schema), US-011 (permission enforcement)
**Blocks:** US-013, US-014 — and EPIC-003 Tenant Management

---

## User Story

As a tenant administrator,
I want to assign and revoke roles for users within my tenant via an API,
So that I can control what each user is permitted to do on the platform.

---

## Background / Context

First admin capability on the platform. All endpoints protected by `@RequiresPermission` (US-011).
Assignment recorded in `user_roles` with `assigned_by`; revocation sets `revoked_at` — never
hard-deleted (trigger from US-009 enforces this). A lockout guard prevents the last `TENANT_ADMIN`
from revoking their own admin role.

---

## Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | Assign role to user | `POST /api/v1/users/{userId}/roles` creates active row; returns 201; requires `user:write` | P0 |
| AC-2 | Revoke role from user | `DELETE /api/v1/users/{userId}/roles/{roleId}` sets `revoked_at`; returns 204; requires `user:write` | P0 |
| AC-3 | List roles for a user | `GET /api/v1/users/{userId}/roles` returns active assignments; requires `user:read` | P0 |
| AC-4 | Tenant isolation | Tenant Admin in Tenant A cannot assign roles in Tenant B; returns 403 | P0 |
| AC-5 | Last admin lockout guard | Revoking last active `TENANT_ADMIN` returns 409 + `RBAC_002` | P0 |
| AC-6 | Cache invalidated on change | Redis key `permissions:{tenant_id}:{user_id}` deleted after assignment/revocation | P0 |
| AC-7 | Assignment events audited | `ROLE_ASSIGNED` / `ROLE_REVOKED` written to audit stream within 1s | P0 |

---

## API Specification

### POST /api/v1/users/{userId}/roles
**Permission:** `user:write` | **Request:** `{ "roleId": "..." }` | **Response 201:** `{ "userId", "roleId", "roleName", "assignedAt" }`

| Status | Code | Reason |
|---|---|---|
| 201 | — | Success |
| 403 | `RBAC_001` | Missing permission or cross-tenant |
| 404 | `USR_001` | User not found in tenant |
| 404 | `ROLE_001` | Role not found in tenant |
| 409 | `ROLE_002` | Role already assigned |

### DELETE /api/v1/users/{userId}/roles/{roleId}
**Permission:** `user:write` | **Response 204:** empty

| Status | Code | Reason |
|---|---|---|
| 204 | — | Success |
| 403 | `RBAC_001` | Missing permission or cross-tenant |
| 404 | `ROLE_003` | Active assignment not found |
| 409 | `RBAC_002` | Last active TENANT_ADMIN |

### GET /api/v1/users/{userId}/roles
**Permission:** `user:read` | **Response:** `{ "userId", "roles": [{ "roleId", "roleName", "assignedAt", "assignedBy" }] }`

---

## Claude Code — Implementation Tasks

### Task 1 — RoleAssignmentService
**File:** `src/main/java/com/example/nexus/rbac/service/RoleAssignmentService.java`
```java
@Service @RequiredArgsConstructor @Transactional
public class RoleAssignmentService {
    // assign(): validate user+role in tenant → insert user_roles → invalidate cache → publish ROLE_ASSIGNED
    // revoke(): lockout guard → set revoked_at → invalidate cache → publish ROLE_REVOKED
    // listActive(): query user_roles WHERE revoked_at IS NULL

    private void guardLastAdmin(byte[] roleId, byte[] tenantId) {
        // COUNT active TENANT_ADMIN rows; if <= 1 throw LastAdminException
    }
}
```

### Task 2 — RoleAssignmentController
**File:** `src/main/java/com/example/nexus/rbac/controller/RoleAssignmentController.java`
```java
@RestController @RequestMapping("/api/v1/users/{userId}/roles")
public class RoleAssignmentController {
    @PostMapping   @RequiresPermission("user:write") // assign
    @DeleteMapping("/{roleId}") @RequiresPermission("user:write") // revoke
    @GetMapping    @RequiresPermission("user:read")  // list
}
```

### Task 3 — DTOs
**Package:** `com.example.nexus.rbac.dto`
```java
public record AssignRoleRequest(@NotNull UUID roleId) {}
public record UserRoleDto(UUID userId, UUID roleId, String roleName, Instant assignedAt, UUID assignedBy) {}
public record UserRolesResponse(UUID userId, List<UserRoleDto> roles) {}
```

### Task 4 — Custom exceptions
```java
// LastAdminException      → 409 + RBAC_002
// RoleNotFoundException   → 404 + ROLE_001 / ROLE_003
// RoleAlreadyAssignedException → 409 + ROLE_002
```
Wire to `GlobalExceptionHandler.java` (US-011).

### Task 5 — Audit events
Reuse `AuditEventPublisher` from US-008:
```java
// ROLE_ASSIGNED: userId, tenantId, metadata: { role_id, role_name, assigned_by }
// ROLE_REVOKED:  userId, tenantId, metadata: { role_id, role_name, revoked_by }
```
> **Note:** `auth_events.metadata` JSON column must exist — resolve OQ-001 before this task.

### Task 6 — Additional repository methods
```java
// UserRoleRepository.java
long countActiveTenantAdmins(@Param("tenantId") byte[] tenantId); // lockout guard
Optional<UserRole> findByUserIdAndRoleIdAndTenantIdAndRevokedAtIsNull(...); // revocation lookup
```

---

## Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | Assign valid role — same tenant | Integration | 201; row active; cache invalidated |
| T-2 | Assign role — different tenant | **Security** | 403 |
| T-3 | Assign already-assigned role | Integration | 409 + `ROLE_002` |
| T-4 | Revoke role | Integration | 204; `revoked_at` set; not deleted |
| T-5 | Revoke last `TENANT_ADMIN` | Integration | 409 + `RBAC_002` |
| T-6 | List active roles | Integration | Only non-revoked assignments returned |
| T-7 | `ROLE_ASSIGNED` audit event | Integration | Event in `auth_events` with correct metadata |
| T-8 | `ROLE_REVOKED` audit event | Integration | Event in `auth_events` |

---

## Definition of Done

- [ ] `RoleAssignmentService.java` created with lockout guard, cache invalidation, audit publish
- [ ] `RoleAssignmentController.java` with all 3 endpoints
- [ ] DTOs and custom exceptions created and wired
- [ ] T-2 cross-tenant test mandatory CI gate
- [ ] T-5 last-admin guard test green
- [ ] Audit events verified (T-7, T-8)
- [ ] No regression on US-011 permission enforcement tests

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Tenant lockout if last admin removed | Med | High | Lockout guard + 409 + T-5 |
| `metadata` column absent from `auth_events` | Med | Med | Resolve OQ-001 before Task 5 |'

echo "  ✓ US-012 created"

# ---- US-013 ----
echo "  Creating US-013..."
gh issue create \
  --repo "$REPO" \
  --milestone "EPIC-002 — RBAC Foundation" \
  --label "epic:rbac,type:frontend,priority:p1,blocked:needs-review" \
  --title "US-013 — Implement Angular permission guard and directive" \
  --body '## GitHub Issue Metadata
**Milestone:** EPIC-002 — RBAC Foundation
**Labels:** `epic:rbac` `type:frontend` `priority:p1` `blocked:needs-review`
**Story Points:** 3
**Blocked by:** US-010 (JWT must contain `permissions[]`), US-011 (403 response contract)
**Blocks:** All future Angular feature modules that use guards or directives

---

## User Story

As a frontend developer,
I want a standard Angular route guard and permission directive that reads from the JWT,
So that every future feature can hide unauthorised UI elements and redirect unauthorised routes without bespoke logic.

---

## Background / Context

> ⚠️ **Frontend access control is UX only.**
> `@RequiresPermission` (US-011) is the true security boundary.
> This must be stated explicitly in code comments and the developer guide.

Both the guard and directive read from the decoded JWT already in `AuthService` — no additional API call.

---

## Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | `PermissionGuard` blocks unauthorised routes | Route with `data: { permission: '"'"'tenant:write'"'"' }` redirects to `/access-denied` if JWT lacks permission | P0 |
| AC-2 | Guard redirects to Access Denied — not login | Authenticated user sees Access Denied page, not login page | P0 |
| AC-3 | `*appHasPermission` hides elements | `<button *appHasPermission="'"'"'tenant:write'"'"'">` absent from DOM when permission missing | P0 |
| AC-4 | Directive degrades gracefully | No `permissions` claim in JWT → element hidden; no console error | P0 |
| AC-5 | Access Denied page meets WCAG 2.1 AA | Heading hierarchy; keyboard-complete; descriptive link text; contrast ≥ 4.5:1 | P0 |
| AC-6 | Documented with UX-only warning | Developer guide explicitly states guards are UX only | P1 |

---

## Claude Code — Implementation Tasks

### Task 1 — PermissionGuard
**File:** `src/app/core/guards/permission.guard.ts`
```typescript
@Injectable({ providedIn: '"'"'root'"'"' })
export class PermissionGuard implements CanActivate {
  canActivate(route: ActivatedRouteSnapshot): boolean {
    const permission = route.data['"'"'permission'"'"'] as string;
    if (this.authService.hasPermission(permission)) return true;
    this.router.navigate(['"'"'/access-denied'"'"']); // NOT /login
    return false;
  }
}
```
**Route config pattern:**
```typescript
{ path: '"'"'tenant-admin'"'"', canActivate: [PermissionGuard], data: { permission: '"'"'tenant:write'"'"' } }
```

### Task 2 — HasPermissionDirective
**File:** `src/app/core/directives/has-permission.directive.ts`
```typescript
@Directive({ selector: '"'"'[appHasPermission]'"'"' })
export class HasPermissionDirective implements OnInit {
  @Input('"'"'appHasPermission'"'"') permission = '"'"''"'"';
  ngOnInit(): void {
    // Show element if user has permission; hide otherwise
    // Graceful degradation: no permissions claim → hide; no error thrown
  }
}
```

### Task 3 — AuthService extension
**File:** `src/app/core/services/auth.service.ts` *(modify — US-003)*
```typescript
hasPermission(permission: string): boolean {
  const token = this.getDecodedToken();
  if (!token) return false;
  const permissions: string[] = token['"'"'permissions'"'"'] ?? [];
  return permissions.includes(permission);
}
```

### Task 4 — AccessDeniedComponent
**File:** `src/app/core/components/access-denied/access-denied.component.ts`
- Display user'"'"'s current roles from JWT for transparency
- "Contact your administrator" link with descriptive `aria-label`
- WCAG 2.1 AA: `<h1>` first; keyboard tab order correct; Axe scan green

### Task 5 — HTTP interceptor — 403 handling
**File:** `src/app/core/interceptors/auth.interceptor.ts` *(modify — US-003)*
```typescript
if (error.status === 403) {
  this.router.navigate(['"'"'/access-denied'"'"']); // NOT /login
  return EMPTY;
}
```

### Task 6 — Module declarations
**File:** `src/app/core/core.module.ts`
```typescript
declarations: [HasPermissionDirective, AccessDeniedComponent],
exports: [HasPermissionDirective] // exported for all feature modules
```

---

## Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | Navigate to guarded route without permission | E2E | Redirect to `/access-denied` |
| T-2 | Navigate to guarded route with permission | E2E | Route activates normally |
| T-3 | `*appHasPermission` with matching permission | Unit | Element in DOM |
| T-4 | `*appHasPermission` without matching permission | Unit | Element absent from DOM |
| T-5 | JWT with no `permissions` claim | Unit | Element hidden; no console error |
| T-6 | 403 API response — interceptor fires | Unit | `router.navigate(['"'"'/access-denied'"'"'"])` called |
| T-7 | Access Denied page — Axe scan | Accessibility | Zero critical issues |

---

## Definition of Done

- [ ] `PermissionGuard` created and registered
- [ ] `HasPermissionDirective` created and exported from `CoreModule`
- [ ] `AuthService.hasPermission()` implemented and unit tested
- [ ] `AccessDeniedComponent` created; WCAG checklist complete
- [ ] HTTP interceptor handles 403 → `/access-denied`
- [ ] All test scenarios green in CI
- [ ] Developer guide entry written with explicit UX-only warning

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Developers use directive as security boundary | Med | High | Code comment + developer guide + code review checklist |'

echo "  ✓ US-013 created"

# ---- US-014 ----
echo "  Creating US-014..."
gh issue create \
  --repo "$REPO" \
  --milestone "EPIC-002 — RBAC Foundation" \
  --label "epic:rbac,type:audit,priority:p0,blocked:needs-review" \
  --title "US-014 — Audit role assignment and revocation events" \
  --body '## GitHub Issue Metadata
**Milestone:** EPIC-002 — RBAC Foundation
**Labels:** `epic:rbac` `type:audit` `priority:p0` `blocked:needs-review`
**Story Points:** 3
**Blocked by:** US-008 (audit pipeline), US-012 (role assignment service)
**Blocks:** EPIC-007 (Audit Log UI)

---

## User Story

As a security and compliance team member,
I want every role assignment and revocation recorded immutably in the audit stream,
So that I can reconstruct who had access to what, and when, for any user in any tenant.

---

## Background / Context

Extends the US-008 audit pipeline with two new RBAC event types. No new audit infrastructure —
events appended to `auth_events` via the existing `AuditEventPublisher`. The append-only trigger
from US-009 already protects these rows.

> ⚠️ **Gate before coding:** Resolve OQ-001 — is the `metadata` JSON column added in V3
> migration (US-009) or a new `V4__auth_events_metadata.sql`? Do not start Tasks 2–4 until confirmed.

---

## Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | `ROLE_ASSIGNED` event emitted | Every successful assignment writes event within 1s: `user_id`, `role_id`, `role_name`, `assigned_by`, `tenant_id`, `correlation_id` | P0 |
| AC-2 | `ROLE_REVOKED` event emitted | Every successful revocation writes event within 1s with same fields plus `revoked_by` | P0 |
| AC-3 | Events are append-only | Existing trigger blocks UPDATE/DELETE; RBAC events inherit protection | P0 |
| AC-4 | Failed assignments not audited as success | 403 / 409 from US-012 does not write `ROLE_ASSIGNED` | P1 |
| AC-5 | Events queryable by tenant and user | Query by `tenant_id` + `user_id` + event type returns correct ordered history | P0 |

---

## Claude Code — Implementation Tasks

### Task 1 — Confirm `metadata` column (resolve OQ-001 first)
If V4 needed:
**File:** `src/main/resources/db/migration/V4__auth_events_metadata.sql`
```sql
ALTER TABLE auth_events ADD COLUMN metadata JSON NULL AFTER correlation_id;
CREATE INDEX idx_ae_tenant_user_type ON auth_events (tenant_id, user_id, event_type, created_at);
```

### Task 2 — Extend AuditEvent model
**File:** `src/main/java/com/example/nexus/audit/model/AuditEvent.java` *(modify — US-008)*
```java
Map<String, String> metadata; // serialised to JSON column

// New constants:
String ROLE_ASSIGNED          = "ROLE_ASSIGNED";
String ROLE_REVOKED           = "ROLE_REVOKED";
String ROLE_ASSIGNMENT_DENIED = "ROLE_ASSIGNMENT_DENIED"; // P1
```

### Task 3 — Extend AuditEventPublisher
**File:** `src/main/java/com/example/nexus/audit/service/AuditEventPublisher.java` *(modify — US-008)*
- Persist `metadata` map to `auth_events.metadata` JSON column
- If metadata is null → persist as SQL NULL (not empty JSON object)

### Task 4 — Verify US-012 audit calls
Confirm in `RoleAssignmentService.java` (US-012):

**ROLE_ASSIGNED:**
```java
auditEventPublisher.publish(AuditEvent.builder()
    .eventType(ROLE_ASSIGNED)
    .userId(targetUserId).tenantId(tenantId)
    .correlationId(requestContext.getCorrelationId())
    .metadata(Map.of("role_id", toHex(roleId), "role_name", role.getName(), "assigned_by", toHex(callerId)))
    .build());
```

**ROLE_REVOKED:**
```java
auditEventPublisher.publish(AuditEvent.builder()
    .eventType(ROLE_REVOKED)
    .userId(targetUserId).tenantId(tenantId)
    .correlationId(requestContext.getCorrelationId())
    .metadata(Map.of("role_id", toHex(roleId), "role_name", role.getName(), "revoked_by", toHex(callerId)))
    .build());
```

---

## Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | Assign role → query audit stream | Integration | `ROLE_ASSIGNED` with correct metadata fields |
| T-2 | Revoke role → query audit stream | Integration | `ROLE_REVOKED` with correct metadata fields |
| T-3 | Failed assignment (403) → audit stream | Integration | No `ROLE_ASSIGNED` event |
| T-4 | UPDATE on `ROLE_ASSIGNED` row | Security | Trigger blocks; `DataIntegrityViolationException` |
| T-5 | Query by tenant + user + event type | Integration | Ordered history; no cross-tenant rows |
| T-6 | Audit write fails → assignment still succeeds | Integration | Assignment committed; ops alert fired |

---

## Definition of Done

- [ ] OQ-001 resolved — `metadata` column confirmed in migration
- [ ] `AuditEvent` model includes `metadata: Map<String, String>`
- [ ] `AuditEventPublisher` persists metadata to JSON column
- [ ] `ROLE_ASSIGNED` and `ROLE_REVOKED` constants defined
- [ ] T-1 and T-2 integration tests green in CI
- [ ] T-4 append-only trigger test green
- [ ] No regression on US-008 existing audit tests

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| `metadata` column absent — blocks Tasks 2–4 | Med | Med | Resolve OQ-001 before sprint starts |
| Async audit write silently drops events | Low | Med | Retry buffer from US-008; ops alert on failure |'

echo "  ✓ US-014 created"

# -----------------------------------------------------------------------------
# DONE
# -----------------------------------------------------------------------------
echo ""
echo "============================================="
echo " ✓ EPIC-002 setup complete!"
echo "============================================="
echo ""
echo " Created:"
echo "   • 10 labels"
echo "   • 1 milestone  — EPIC-002 — RBAC Foundation"
echo "   • 6 issues     — US-009 through US-014"
echo ""
echo " Next steps:"
echo "   1. Open your GitHub repo: https://github.com/$REPO"
echo "   2. Go to Issues → Milestones to verify"
echo "   3. Run Gate 1 review on US-009 before Sprint 3 starts"
echo "   4. Resolve OQ-001 (metadata column) before US-014 dev starts"
echo ""
