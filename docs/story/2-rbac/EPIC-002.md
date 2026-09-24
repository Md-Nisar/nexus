
---

# Discovery: RBAC Foundation
## EPIC-002

---

## [PM] — Problem & Vision

**Problem statement:** EPIC-001 delivers authentication — we know *who* the user is. EPIC-002 answers *what they are allowed to do*. Without it, every API endpoint is implicitly open to any authenticated user, Epic 3 (Tenant Management) cannot enforce admin boundaries, and the platform cannot safely onboard enterprise customers who expect role-based access control as a baseline capability.

**Model confirmed:** Roles + Permissions — a role is a named collection of permissions; a user is assigned one or more roles within a tenant. This is the industry-standard model (similar to AWS IAM groups, Okta roles) and gives the most flexibility for future permission granularity without ABAC complexity.

**Scope confirmed:** Tenant-scoped role assignments only. A user's roles mean nothing outside the tenant they were assigned in. Platform-level roles (SUPER_ADMIN) are out of scope for Epic 2 — that belongs to an internal operations epic.

**User segments:**
- **Tenant Administrators** — assign/revoke roles for users within their tenant
- **Internal Employees / Business Users** — receive roles; experience permission-gated UI and API
- **Development Teams** — consume the permission-check contract (annotations, guards) for all future features
- **Security & Compliance** — need role assignment events in the audit trail

**Business goals (measurable):**
1. Every API endpoint introduced from Epic 3 onward is protected by a permission check — zero unguarded endpoints at GA.
2. Role assignment and revocation reflected in JWT within one token refresh cycle (≤ 7 days; immediately on next login).
3. 100% of role assignment/revocation events emitted to the audit stream (US-008 pipeline).
4. Development teams can add a new permission-guarded endpoint with a single annotation — no bespoke auth logic per feature.

**Success metrics (post-launch):** zero privilege-escalation findings in pre-GA pen test; RBAC overhead adds < 5ms to p95 API response time; at least one Epic 3 endpoint protected on day one with no contract changes to the RBAC layer.

**Scope boundary — explicitly OUT:** UI for role management (that is a Tenant Management UI concern, Epic 3); platform-wide / super-admin roles; permission inheritance / hierarchical roles; ABAC; dynamic permission creation at runtime (permissions are code-defined, not DB-configured); user provisioning / bulk role assignment.

**PM flag:** "Tenant Admin assigns roles" touches the Tenant Management boundary. In Epic 2 the assignment API is built and secured; the UI surface for a Tenant Admin to use it lives in Epic 3. The API must exist now so Epic 3 has something to call.

---

## [BA] — Business Analysis

**Workflow map:**

| Workflow | Current state (post EPIC-001) | Future state (post EPIC-002) |
|---|---|---|
| User accesses a protected feature | Any authenticated user can call any endpoint | Endpoint checks permission; 403 if user's roles don't include it |
| Tenant Admin grants access | No mechanism exists | POST /roles/assignments — assigns a role to a user within tenant scope |
| Tenant Admin revokes access | No mechanism exists | DELETE /roles/assignments — revokes; effective on next login or token refresh |
| Developer adds a protected endpoint | Ad-hoc; no standard | `@RequiresPermission("resource:action")` annotation; Spring Security evaluates against JWT claims |
| Compliance reviews who has access | No data exists | Role assignment events in audit stream; query by tenant + user |

**Stakeholder matrix:**

| Stakeholder | Impact | Needs from Epic 2 |
|---|---|---|
| Tenant Administrators | High — first admin capability | Assign/revoke roles for users in their tenant; see current assignments |
| Business Users | Medium — experience changes | Correct access to features they are entitled to; clear 403 messaging |
| Dev Teams | High — consume RBAC contract | Stable `@RequiresPermission` annotation; documented permission naming convention |
| Security & Compliance | High | Role assignment events audited; no privilege escalation possible |
| Epic 3 (Tenant Mgmt) | Hard dependency | Role assignment API + `TENANT_ADMIN` role seeded before Epic 3 dev starts |

**Permission naming convention (BA proposes, ARC confirms):**
`resource:action` — e.g. `tenant:read`, `tenant:write`, `user:read`, `user:write`, `audit:read`. Colon-separated, lowercase, code-defined only (not runtime-configurable in Epic 2).

**System dependencies:**
- EPIC-001 US-001 schema — `users` table (user_id, tenant_id) must exist
- EPIC-001 US-003 JWT contract — `roles[]` claim placeholder must be populated
- Redis — permission cache (ARC to confirm TTL). **Not currently a dependency anywhere in the backend** — this is net-new infrastructure (client, config, docker-compose service), not just a config decision; see US-010 Technical Notes.
- Audit event stream — US-008 pipeline; role events appended to `auth_events` (RESOLVED: existing table, no new `rbac_events` table needed — see Open Decisions)

**Compliance requirements:**
- Role assignment/revocation events must be immutable and auditable
- A user must never see data outside their `tenant_id` regardless of role
- Principle of least privilege: default role on registration is no permissions (explicit assignment required)
- Permission checks must be server-side enforced — frontend guards are UX only, never the security boundary

---

## [UX] — User Experience

**Scope note:** No role management UI in Epic 2 (that is Epic 3). UX scope here covers: the 403 experience, frontend route guards as a pattern, and the Angular permission directive used by all future feature UIs.

**403 — Insufficient permissions state:**
- API returns `403 + RBAC_001 + { "required_permission": "tenant:write", "message": "You do not have permission to perform this action" }`
- Frontend intercepts 403 in the existing HTTP interceptor (US-003) and routes to a platform-standard "Access Denied" page
- Page shows: friendly message, the user's current role (for transparency), a "Contact your administrator" CTA
- No technical detail (permission name, required role) exposed to the end user — only in the API response body for developer consumption

**Angular permission directive — `*appHasPermission`:**
- Structural directive: `*appHasPermission="'tenant:write'"` — hides the element if user lacks the permission
- Does NOT replace server-side checks — it is UX polish only, stated explicitly in the Angular coding standard comment
- Reads permissions from `AuthStore`'s current-user signal, which is populated from `GET /v1/users/me` on login/refresh — **not** a decoded JWT. The existing frontend never parses the access token client-side; it already fetches `roles[]` this way (US-013 extends the same `/users/me` contract with a new `permissions[]` field, see US-010). No new JWT-decode dependency, no extra API call beyond what already runs today.
- Degrades gracefully: if the current-user signal has no `permissions`, treats as empty — element hidden, no error thrown

**Angular route guard — `PermissionGuard`:**
- Functional guard (`CanActivateFn`, matching the existing `authGuard` pattern); checks `AuthStore`'s `permissions` signal before activating the route
- On failure: redirects to Access Denied page (not login — the user is authenticated, just unauthorised)
- Configuration: `{ path: 'tenant-admin', canActivate: [PermissionGuard], data: { permission: 'tenant:write' } }`

**Edge states:**
- User's role is revoked mid-session — they remain on the page until next navigation or token refresh; on next route activation the guard catches it and redirects
- User has no roles assigned — Access Denied on any protected route; registration confirmation page explicitly states "Your administrator will grant you access"
- Multiple roles — user receives the union of all permissions across their roles within the tenant

**WCAG 2.1 AA:** Access Denied page keyboard-complete; heading hierarchy correct; error message linked via `aria-describedby`; "Contact your administrator" link has descriptive text (not "click here").

---

## [ARC] — Technical Architecture

**Core data model (new tables):**

`permissions` — code-seeded, not runtime-created:
`id` BINARY(16) UUIDv7, `name` VARCHAR(64) UNIQUE (e.g. `tenant:read`), `description`, `created_at`

`roles` — tenant-scoped named collections:
`id` BINARY(16) UUIDv7, `tenant_id` BINARY(16), `name` VARCHAR(64), `description`, `is_system_role` BOOLEAN DEFAULT FALSE, `created_at`, `updated_at`
UNIQUE `(tenant_id, name)`

`role_permissions` — join table:
`role_id` FK, `permission_id` FK, `created_at`
PK `(role_id, permission_id)`

`user_roles` — tenant-scoped assignment:
`id` BINARY(16) UUIDv7, `user_id` FK → users.id, `role_id` FK → roles.id, `tenant_id` BINARY(16), `assigned_by` FK → users.id, `assigned_at`, `revoked_at` NULL
UNIQUE `(user_id, role_id)` (soft-delete via `revoked_at`, not hard delete — audit requirement)

**JWT integration (US-003 `roles[]` claim — now populated):**
On login, the auth service resolves `user → roles → permissions` for the tenant, and writes both into the token:
```
"roles": ["TENANT_ADMIN"],
"permissions": ["tenant:read", "tenant:write", "user:read", "user:write"]
```
Permission evaluation happens against the JWT — no DB call per request. Token refresh picks up role changes within 7 days; immediate effect requires re-login (documented, acceptable for MVP).

**Frontend note:** the JWT `permissions[]` claim above is for the *backend's* stateless enforcement (US-011) only. The Angular frontend does not decode the JWT (see UX section) — it receives the equivalent data via `GET /v1/users/me`, which US-010 must also extend with a `permissions[]` field alongside the existing `roles[]`.

**Contract-versioning note:** the JWT claims record is a documented frozen contract — adding `permissions[]` is a breaking addition and requires bumping the token schema version and updating the existing contract test, not just adding a field (see US-010 Technical Notes).

**Permission check — Spring Security:**
Custom `@RequiresPermission("tenant:write")` annotation backed by a Spring Security `MethodSecurityExpressionHandler`. Evaluated via `@PreAuthorize("hasPermission(#tenantId, 'tenant:write')")`. Tenant boundary enforced in the evaluator — a `tenant:write` permission in Tenant A does not satisfy a check in Tenant B.

**API endpoints:**

| Method | Path | Permission required | Purpose | Story |
|---|---|---|---|---|
| GET | `/api/v1/users/{userId}/roles` | `user:read` | List roles assigned to a user | US-012 |
| POST | `/api/v1/users/{userId}/roles` | `user:write` | Assign role to user in tenant | US-012 |
| DELETE | `/api/v1/users/{userId}/roles/{roleId}` | `user:write` | Revoke role from user | US-012 |
| GET | `/api/v1/roles` | `role:read` | List roles in caller's tenant | US-015 |
| POST | `/api/v1/roles` | `role:write` | Create a role in caller's tenant | US-015 |
| GET | `/api/v1/roles/{roleId}/permissions` | `role:read` | List permissions on a role | US-015 |
| POST | `/api/v1/roles/{roleId}/permissions` | `role:write` | Assign permission to role | US-015 |
| DELETE | `/api/v1/roles/{roleId}/permissions/{permissionId}` | `role:write` | Remove permission from role | US-015 |
| GET | `/api/v1/permissions` | `role:read` | List all available permissions (code-seeded) | US-015 |

**Ownership decision (resolves Open Decision #2 below):** role/permission management (US-015) stays in EPIC-002, not Epic 3 — `roles`/`permissions`/`role_permissions` are `rbac`-bounded-context aggregates, and that context (controllers, services, tenant-scoping) is already being built by US-009–US-012. It is **not** part of the Epic 3 kickoff gate (still just US-009 seed + US-012 assignment) — it's scheduled after the gate, in Sprint 5, so it doesn't compete with gating work. System roles (`TENANT_ADMIN`, `MEMBER`, `is_system_role = TRUE`) are immutable through this API regardless of who calls it.

**Seeded system data (Flyway migration):**
- Permissions: `tenant:read`, `tenant:write`, `user:read`, `user:write`, `role:read`, `role:write`, `audit:read`
- System role: `TENANT_ADMIN` (per-tenant, seeded on tenant creation in Epic 3; pre-seeded for default tenant in Epic 2)
- System role: `MEMBER` — default role for new users; `user:read` permission only

**Permission cache:** Redis; two keys per entry sharing a TTL — `{nexus.redis.key-prefix}:rbac:roleset:{tenant_id}:{user_id}` and `{nexus.redis.key-prefix}:rbac:permset:{tenant_id}:{user_id}` (`nexus.redis.key-prefix` defaults to `nexus`); TTL 15 min; invalidated via `PermissionCachePort.evict(tenantId, userId)` on role assignment/revocation. Fallback: DB query if cache miss. Cache is a performance optimisation — the JWT is the authority.

**Effort estimate:** ~36 points total (US-009: 8, US-010: 3, US-011: 5, US-012: 5, US-013: 3, US-014: 3, US-015: 9 — US-009 revised from 5 to 8 after Gate 1 requirements analysis added JPA entities/repositories and `nexus_app` DB grants to its scope, see ADR-0014). Confidence: medium-high (model is well-understood; main uncertainty is Spring Security method security configuration complexity, and — for US-015 — cache-invalidation fan-out when a role's permission set changes under already-assigned users).

**Technical risks:**

| Risk | L | I | Mitigation |
|---|---|---|---|
| JWT size growth (roles + permissions array) | Med | Med | Benchmark token size; permissions as short strings; drop verbose descriptions from token |
| Permission check in wrong tenant context | Med | High | Tenant boundary enforced in `PermissionEvaluator`; integration test: user with role in Tenant A cannot pass check in Tenant B |
| Cache invalidation lag (15 min) | Low | Med | Acceptable for MVP; document in security runbook; re-login is the immediate-effect path |
| `user_roles` soft-delete audit gap | Low | Med | `revoked_at` preserves history; hard delete blocked at DB trigger level |
| Active-assignment uniqueness needs a MySQL-valid mechanism | Low | High | MySQL 8.4 does not support Postgres-style partial (`WHERE`) unique indexes; use a `STORED` generated column that is `NULL` for revoked rows and a deterministic `(user_id, role_id)` value for active rows, with a plain `UNIQUE INDEX` on it — MySQL never treats two `NULL`s as duplicates. See US-009 Technical Notes. |
| Editing a role's permissions (US-015) leaves stale JWT/cache permissions for every user already assigned that role | Med | Med | US-012's cache invalidation only targets one `{tenant_id}:{user_id}` key on assignment/revocation; a `role_permissions` edit must invalidate the cache for **all** active `user_roles` rows referencing that `role_id` — bulk-delete matching keys, or accept the existing 15-min TTL / 7-day refresh lag and document it the same way as US-012's revocation lag. See US-015 Technical Notes. |

---

## [QA] — Quality & Test Strategy

**Test strategy:**
- **Unit:** `PermissionEvaluator` tenant boundary logic; JWT permission claim builder; permission cache key generation; `*appHasPermission` directive with mock JWT
- **Integration:** all 9 role/assignment endpoints (happy path + 403 + 404 + tenant isolation); Flyway migration with seeded data; cache invalidation on revocation
- **E2E:** assign role → logout → login → access protected route succeeds; revoke role → next login → access denied
- **Security:** cross-tenant permission escalation (user in Tenant A attempts endpoint in Tenant B — must 403); JWT with manually injected permissions claim rejected if signature invalid; no permission = 403 not 401 (user is authenticated); `user_roles` hard-delete blocked at DB trigger
- **Performance:** permission resolution at login < 50ms with 10 roles + 50 permissions per user; Redis cache hit < 5ms; 200 RPS on a permission-guarded endpoint p95 < 300ms

**Quality gates:** all ACs pass; zero high/critical SAST findings on the permission evaluator; cross-tenant test suite green; JWT size < 4KB with maximum realistic role/permission set; code review approved.

**Release readiness:** RBAC layer pen-tested before Epic 3 begins; `@RequiresPermission` annotation documented in developer guide; at least one Epic 3 endpoint using it as proof of contract.

---

## [SYNTHESIS]

EPIC-002 delivers the permission enforcement layer the platform needs before any admin surface can exist. The model (Roles + Permissions, tenant-scoped) is the right balance between simplicity and extensibility — flat enough to build fast, structured enough to support future granularity without schema rework. Three things to watch: JWT size as permission sets grow (benchmark early), the 15-minute cache lag on role revocation (document and accept for MVP), and the cross-tenant boundary test (must be in CI before Epic 3 starts — this is the highest-consequence failure mode on a multi-tenant platform).

The one handoff dependency to flag: **Epic 3 cannot start until the `TENANT_ADMIN` system role is seeded and the role assignment API is working.** That means US-002 of this epic (role + permission seeding) is the hard gate for Epic 3 kickoff, not the full epic completion.

---

## [JIRA]

```
EPIC ID: EPIC-002
EPIC TITLE: RBAC Foundation
Description: Delivers a Roles + Permissions model scoped to tenants. Populates
the JWT roles[] and permissions[] claims, enforces permission checks on all API
endpoints via @RequiresPermission, and provides Angular route guards and
directives for frontend access control. Unblocks Epic 3 (Tenant Management).
Business Goal: Zero unguarded endpoints from Epic 3 onward; role assignment
audited from day one.
Success Metric: Zero privilege-escalation findings in pre-GA pen test; RBAC
overhead < 5ms p95; Epic 3 ships on RBAC contract with no changes.
Priority: P0
Story Points (total): 36 (corrected from an earlier 34 — see Open Decision #2 for the US-015 addition, and the ARC effort estimate for US-009's Gate-1 revision from 5 to 8)
Dependencies: Blocked by EPIC-001 (US-001 schema, US-003 JWT contract).
Blocks: EPIC-003 Tenant Management.
```

---

### US-009 — Establish RBAC data model and seed system roles and permissions

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 8 | EPIC-002: RBAC Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a platform development team,
I want a roles and permissions schema with system roles seeded via migration,
So that all future features have a stable, tenant-scoped permission model to build on.

### Background / Context
Extends the EPIC-001 schema with 4 new tables. System roles (`TENANT_ADMIN`, `MEMBER`) and the full permission set are seeded in the migration — not configurable at runtime in Epic 2. `user_roles` uses soft-delete (`revoked_at`) to preserve audit history; hard delete is blocked by trigger. This story is the gate for Epic 3 kickoff: `TENANT_ADMIN` must exist before Tenant Management can enforce admin boundaries.

**Gate 1 note:** requirements analysis (`docs/features/US-009/01-requirements.md`) found this is genuinely greenfield — no `rbac` code exists yet — and surfaced two decisions not covered by ADR-0013, now resolved in **ADR-0014**: how the seeded system roles get a correct `tenant_id` at migration time (D5), and least-privilege `nexus_app` DB grants for the 4 new tables, which no existing provisioning artifact currently covers (D6). Both are folded into this story below.

**Gate 2 threat-model note:** the STRIDE pass (`docs/features/US-009/03b-threat-model.md`) found two design changes needed before Gate 2 closed, now resolved in **ADR-0015**: the `user_roles` UPDATE grant is tightened to column-scoped `UPDATE (revoked_at)` (D7 — a table-wide grant left every other column protected only by the JPA mapping, not the database), and the bootstrap-tenant `application.yml` fallback originally planned in ADR-0014 D5 is **not** added to base config (D8 — it would have converted prod's fail-fast-on-unset into a silent default into the tenant holding the seeded `TENANT_ADMIN` role). Both are reflected below; a `CHECK` constraint closing a third finding (`active_key` semantics under a hypothetical future scheduled-revocation feature) is also added.

### Explicit Column Lists

**`permissions`**

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | `BINARY(16)` | PK UUIDv7 |
| `name` | `VARCHAR(64)` | NOT NULL UNIQUE — e.g. `tenant:read` |
| `description` | `VARCHAR(255)` | NOT NULL |
| `created_at` | `DATETIME(6)` | NOT NULL DEFAULT CURRENT_TIMESTAMP(6) |

Seeded: `tenant:read`, `tenant:write`, `user:read`, `user:write`, `role:read`, `role:write`, `audit:read`

**`roles`**

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | `BINARY(16)` | PK UUIDv7 |
| `tenant_id` | `BINARY(16)` | NOT NULL |
| `name` | `VARCHAR(64)` | NOT NULL |
| `description` | `VARCHAR(255)` | NULL |
| `is_system_role` | `BOOLEAN` | NOT NULL DEFAULT FALSE |
| `created_at` | `DATETIME(6)` | NOT NULL DEFAULT CURRENT_TIMESTAMP(6) |
| `updated_at` | `DATETIME(6)` | NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6) |

UNIQUE `(tenant_id, name)`. Seeded: `TENANT_ADMIN` (all permissions), `MEMBER` (`user:read` only), both scoped to the bootstrap default tenant (see Technical Notes — ADR-0014 D5).

**`role_permissions`**

| Column | Type | Constraints |
|--------|------|-------------|
| `role_id` | `BINARY(16)` | FK → roles.id |
| `permission_id` | `BINARY(16)` | FK → permissions.id |
| `created_at` | `DATETIME(6)` | NOT NULL DEFAULT CURRENT_TIMESTAMP(6) |

PK `(role_id, permission_id)`

**`user_roles`**

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | `BINARY(16)` | PK UUIDv7 |
| `user_id` | `BINARY(16)` | FK → users.id NOT NULL |
| `role_id` | `BINARY(16)` | FK → roles.id NOT NULL |
| `tenant_id` | `BINARY(16)` | NOT NULL |
| `assigned_by` | `BINARY(16)` | FK → users.id NOT NULL |
| `assigned_at` | `DATETIME(6)` | NOT NULL DEFAULT CURRENT_TIMESTAMP(6) |
| `revoked_at` | `DATETIME(6)` | NULL — CHECK: `revoked_at IS NULL OR revoked_at >= assigned_at` |
| `active_key` | `BINARY(32)` | GENERATED ALWAYS AS (`CASE WHEN revoked_at IS NULL THEN CONCAT(user_id, role_id) ELSE NULL END`) STORED |

UNIQUE INDEX on `active_key` (see Technical Notes — replaces the invalid Postgres-style partial index below). Hard delete blocked via trigger; **only** the DELETE path is blocked — `revoked_at` is set via `UPDATE` and must remain permitted (deliberate divergence from the `auth_events` trigger pair, which blocks both). The `revoked_at` CHECK constraint (threat model T-T2 / ADR-0015) enforces that revocation is always immediate/past-dated, never scheduled.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | All 4 RBAC tables created | Flyway migration `V5__rbac_schema.sql` creates `permissions`, `roles`, `role_permissions`, `user_roles` with all columns and indexes per explicit lists above; verified via Testcontainers | P0 | Repo is already at V4 (EPIC-001); this is the next available version, not V3. Temporal columns use `DATETIME(6)`, matching V2-V4 convention (corrected from an earlier draft's bare `TIMESTAMP`) |
| 2 | System permissions seeded | All 7 permissions (`tenant:read`, `tenant:write`, `user:read`, `user:write`, `role:read`, `role:write`, `audit:read`) present after migration, with format-valid UUIDv7 literal PKs | P0 | See Technical Notes on seed-literal format |
| 3 | System roles seeded with correct permissions | `TENANT_ADMIN` has all 7 permissions; `MEMBER` has `user:read` only; both scoped to the bootstrap default tenant ID; verified by join query in migration test | P0 | Tenant ID sourcing resolved by ADR-0014 D5 |
| 4 | `user_roles` hard delete blocked | `BEFORE DELETE` trigger raises `SQLSTATE '45000'` for both single-row and multi-row delete attempts; test confirms DELETE fails; `revoked_at` (via `UPDATE`) is the only soft-delete path | P0 | |
| 5 | Tenant isolation on roles | Two roles with the same name in different `tenant_id` values both persist; same name in same tenant raises unique constraint | P0 | |
| 6 | Only one active role assignment per (user, role) | Inserting a second active (`revoked_at IS NULL`) row for the same `(user_id, role_id)` raises a unique constraint violation on `active_key`; re-assigning after revocation succeeds; two concurrent insert attempts for the same pair result in exactly one success | P0 | Replaces the invalid partial-index AC from the original draft |
| 7 | Migration clean-forward in CI | Testcontainers: EPIC-001 migrations (V1-V4) → V5 migration → schema assertions all pass | P1 | |
| 8 | JPA entities and repositories exist | `Permission`, `Role`, `RolePermission`, `UserRole` entities (+ Spring Data repositories) exist in `com.example.nexus.rbac`, mirroring `identity`'s hexagonal layout; `active_key` mapped read-only (`insertable=false, updatable=false`); passes `HexagonalArchitectureTest` with zero configuration changes | P0 | Resolves an ambiguity between this story's Technical Notes and its original AC list — entities ship with the migration that defines their schema, not deferred to US-010 |
| 9 | `nexus_app` granted least-privilege access to all 4 tables | Per-table grants (see Technical Notes — ADR-0014 D6) added to all 3 existing provisioning artifacts (dev init SQL, Testcontainers grants callback, prod runbook); verified by a docker-compose `full`-profile smoke check, since Testcontainers ITs run as a different DB user and cannot detect a missing grant | P0 | Without this, the first real deployment after `V5` ships hits `Access denied for user 'nexus_app'` on the first RBAC query |

### Technical Notes (ARC)
- Migration file: `V5__rbac_schema.sql`; runs after V4 (EPIC-001) — **corrected from `V3`, which is already used by EPIC-001's identity schema**
- UUIDv7 via `uuid-creator` library (established in US-001 ADR-001), through the existing `UuidGenerator` port / `UuidV7Generator` adapter — reuse directly, no new pattern, for any runtime-created rows
- **Seed-row PK literals:** Flyway SQL cannot invoke the Java `UuidGenerator` port. The 9 seeded PKs (7 `permissions` + 2 `roles`) must be hardcoded, format-valid UUIDv7 literals (correct version/variant nibbles), fixed and documented in the migration's own header comment — not arbitrary 16-byte values.
- JPA entities in `com.example.nexus.rbac` bounded context, mirroring `com.example.nexus.identity`'s hexagonal layout (`domain/`, `application/` + `port/out`, `infrastructure/persistence`, `interfaces/rest/dto`) — see AC8; entities + repositories only, no application services (those belong to US-010/US-012/US-015)
- **Active-assignment uniqueness (corrected):** MySQL 8.4 (the confirmed Testcontainers target) does not support Postgres-style partial/filtered unique indexes (`CREATE UNIQUE INDEX ... WHERE ...`). Use a `STORED` generated column instead: `active_key BINARY(32) GENERATED ALWAYS AS (CASE WHEN revoked_at IS NULL THEN CONCAT(user_id, role_id) ELSE NULL END) STORED`, with a plain `UNIQUE INDEX uq_user_role_active (active_key)`. MySQL never treats two `NULL`s as duplicates, so revoked rows (where `active_key` is `NULL`) never collide with each other or with active rows, while two active assignments for the same `(user_id, role_id)` compute the same non-null value and correctly collide.
- **Append-only enforcement for `user_roles`:** follow the `trg_auth_events_no_delete` shape (`BEFORE DELETE ... BEGIN SIGNAL SQLSTATE '45000' ...; END;`). Add **only** the DELETE-blocking trigger — do **not** also copy `trg_auth_events_no_update`; `revoked_at` is set via `UPDATE` and must remain a permitted path.
- **Bootstrap tenant sourcing (ADR-0014 D5, amended by ADR-0015 D8):** `roles.tenant_id` for the seeded system roles uses the literal `00000000-0000-7000-8000-000000000001`, matching the value already hardcoded independently in `application-dev.yml` and `application-smoke.yml`. **Do not add this as a fallback to base `application.yml`** — the threat model (T-E2) found that would convert prod's fail-fast-on-unset `NEXUS_IDENTITY_DEFAULT_TENANT_ID` into a silent default into the tenant holding the seeded `TENANT_ADMIN` role, since `default-tenant-id` is live-consumed by `RegistrationController` for every self-registered user. `application.yml` needs **no change** in this story. Bootstrap-only mechanism; Epic 3's per-tenant-creation role seeding is the long-term path for every tenant provisioned after that ships.
- **`nexus_app` grants (ADR-0014 D6, amended by ADR-0015 D7):** add to all 3 existing provisioning artifacts, applied after `V5` runs:
  ```sql
  GRANT SELECT                ON nexus.permissions      TO 'nexus_app'@'%';
  GRANT SELECT, INSERT        ON nexus.roles            TO 'nexus_app'@'%';
  GRANT SELECT, INSERT, DELETE ON nexus.role_permissions TO 'nexus_app'@'%';
  GRANT SELECT, INSERT        ON nexus.user_roles       TO 'nexus_app'@'%';
  GRANT UPDATE (revoked_at)   ON nexus.user_roles       TO 'nexus_app'@'%';
  ```
  `user_roles`'s `UPDATE` grant is **column-scoped to `revoked_at` only** (ADR-0015 D7) — a table-wide grant left every other column protected only by the JPA mapping, not the database. No `DELETE` grant on `user_roles` — defense-in-depth on top of the trigger, matching `auth_events`'s existing pattern. Known residual gap (pre-existing): Testcontainers ITs run as the container's default `test` user, not `nexus_app`, so a green IT suite can't catch a grants mistake.
- Feature flag required: No
- ADRs: **ADR-0013** (RBAC model, permission naming convention, `active_key` technique), **ADR-0014** (bootstrap tenant sourcing, `nexus_app` grants), and **ADR-0015** (Gate-2 threat-model hardening: column-scoped `user_roles` grant, non-prod-only tenant fallback) — all Accepted

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Clean migration: V1 → V2 → V3 → V4 → V5 | Integration | All tables, indexes, seed data present |
| 2 | Duplicate role name same tenant | Integration | Unique constraint violation |
| 3 | Same role name different tenants | Integration | Both rows persist |
| 4 | Single-row DELETE on `user_roles` | Security | `SQLSTATE '45000'` raised |
| 5 | `TENANT_ADMIN` permissions join query | Integration | Returns all 7 permissions |
| 6 | `MEMBER` permissions join query | Integration | Returns `user:read` only |
| 7 | Assign same user+role twice while both active | Integration | Second insert violates unique constraint on `active_key` |
| 8 | Revoke then re-assign same user+role | Integration | Second (new) active row inserts successfully; original revoked row untouched |
| 9 | Multi-row DELETE on `user_roles` (bulk statement matching several rows) | Security | Whole statement aborts on the first row evaluated; `SQLSTATE '45000'`; zero rows deleted |
| 10 | Two concurrent INSERT attempts for the same `(user_id, role_id)`, both active | Integration | Exactly one succeeds; the other fails on the `active_key` unique constraint |
| 11 | Explicit `INSERT ... (active_key) VALUES (...)` attempting to set a non-generated value | Security | Rejected by MySQL (generated column cannot be written directly) — threat model T-T3 |
| 12 | `nexus_app` attempts `UPDATE user_roles SET assigned_by = ?` (any column other than `revoked_at`) | Security | Denied at the grant level (`ERROR 1143`) — proves the column-scoped grant (ADR-0015 D7), not just the JPA mapping, blocks it — threat model T-T1 |

### Dependencies
- Blocked by: US-001 (V2 migration must be applied)
- Blocks: US-010 through US-015; Epic 3 kickoff gate
- External: none

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Generated-column uniqueness technique behaves unexpectedly under concurrent inserts | Low | Med | Standard MySQL pattern; covered by Test Scenario 10 |
| `nexus_app` grants added to the provisioning artifacts but never verified in a real (non-Testcontainers) environment before this ships | Med | High | AC9's docker-compose `full`-profile smoke check is mandatory, precisely because Testcontainers CI cannot see this class of bug |
| Bootstrap default-tenant literal (migration) drifts from each non-prod environment's own hardcoded literal if changed without the other | Low | Med | Both values are documented together in this story, ADR-0014 D5, and ADR-0015 D8; any future change to one must update the others in the same PR. **Not** mitigated via a base-`application.yml` fallback — see ADR-0015 D8 |
| ~~`user_roles` UPDATE grant permits rewriting immutable columns via raw SQL~~ | ~~Med~~ | ~~Med~~ | **RESOLVED (ADR-0015 D7):** grant tightened to column-scoped `UPDATE (revoked_at)`; covered by Test Scenario 12 |

### Out of Scope
- Runtime permission creation (permissions are code-defined only)
- Platform-wide / super-admin roles
- UI for role management (Epic 3)
- Role creation and role-permission management APIs (US-015 — kept in Epic 2, non-gating; see EPIC-002 Open Decisions)

---

### US-010 — Populate JWT with resolved roles and permissions on login

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 3 | EPIC-002: RBAC Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As an authenticated user,
I want my roles and permissions included in my JWT on login,
So that every API and frontend permission check works without an extra database call per request.

### Background / Context
US-003 left `roles[]` as a placeholder empty array in the JWT. This story populates it — and adds a `permissions[]` claim — by resolving `user → active user_roles → role_permissions → permissions` at login time for the user's tenant. The JWT becomes the authority for permission checks; no DB call is made per request.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | `roles` claim populated on login | JWT `roles[]` contains the names of all active (non-revoked) roles for the user in their tenant | P0 | |
| 2 | `permissions` claim populated on login | JWT `permissions[]` contains the deduplicated union of all permissions across the user's active roles | P0 | |
| 3 | Revoked roles excluded | A role with `revoked_at IS NOT NULL` does not appear in `roles[]` or contribute to `permissions[]` | P0 | |
| 4 | User with no roles gets empty claims | `roles: []`, `permissions: []` — no error thrown; downstream guards treat as no access | P0 | |
| 5 | JWT size within limit | Token with maximum realistic role/permission set (5 roles, 20 permissions) is < 4KB | P1 | Benchmark in performance test |
| 6 | Token refresh re-resolves permissions | A new access token issued via POST /api/v1/auth/refresh reflects any role changes made since the previous login | P0 | Effective within 7-day refresh TTL |
| 7 | JWT contract version bumped | The JWT claims schema (`JwtClaims`) is a documented frozen contract; adding `permissions[]` bumps `token_version` and the existing contract test is updated to assert the new field and version | P0 | Corrects a gap in the original story — `JwtClaims` explicitly forbids field additions without a version bump |
| 8 | `permissions[]` also exposed via `/users/me` | `GET /api/v1/users/me` response gains a `permissions: string[]` field, sourced from the same `RoleResolutionService`, so the frontend never needs to decode the JWT (see US-013) | P0 | Resolves a frontend/backend contract mismatch found in feasibility review |
| 9 | JWT `tenant_id` never defaults to the bootstrap sentinel | `RoleResolutionService`/token issuance sources `tenant_id` exclusively from `user.getTenantId()`; a user whose tenant cannot be resolved is denied, never silently assigned the bootstrap tenant | P0 | Forward-tracked from US-009's Gate-2 threat model (T-S1) — the bootstrap tenant holds the seeded `TENANT_ADMIN` role, so an incorrect default here is a privilege escalation, not just a data bug |
| 10 | Runtime DB-grant self-check | A startup/actuator health indicator warns if the live DB connection can `DELETE` from `user_roles` or holds `ALL PRIVILEGES`/is `root`, mirroring `AuthEventDbPrivilegeHealthIndicator` | P1 | Forward-tracked from US-009's Gate-2 threat model (T-E3) — Testcontainers CI cannot exercise `nexus_app`, so this is the only runtime detection for an over-grant or still-on-`root` environment; hosted here because US-009 has no runtime surface to host it |

### Technical Notes (ARC)
- Modify `JwtTokenService` (US-003) to inject `RoleResolutionService` at token issuance
- `RoleResolutionService`: queries `user_roles JOIN role_permissions JOIN permissions WHERE user_id = ? AND tenant_id = ? AND revoked_at IS NULL`
- Result cached in Redis: two keys sharing a TTL — `{nexus.redis.key-prefix}:rbac:roleset:{tenant_id}:{user_id}` and `{nexus.redis.key-prefix}:rbac:permset:{tenant_id}:{user_id}` (`nexus.redis.key-prefix` defaults to `nexus`) — TTL 15 min; warmed on login, invalidated via `PermissionCachePort.evict` on role change (US-012). **Redis is not currently a dependency anywhere in the backend** (no `spring-boot-starter-data-redis`, no client, only an unused config placeholder for rate-limiting) — this story must add the starter, client config, and a docker-compose service, not just a cache-key scheme. Size this as new infrastructure, not a config tweak.
- Permission strings in JWT: short form only (`tenant:read`) — no descriptions
- Token contract addition: `"permissions": ["tenant:read", "tenant:write"]` added to the frozen `JwtClaims` schema; **requires a `token_version` bump** (the record's existing doc comment explicitly requires this for any field addition) and an update to the existing contract test — not just appending a claim
- `RoleResolutionService` output is also used to add `permissions: string[]` to the `GET /api/v1/users/me` response (`MeApiResponse`), alongside the existing `roles: string[]` — this is what the Angular frontend actually reads (see US-013); it does not decode the JWT
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Login with `TENANT_ADMIN` role | Integration | JWT contains all 7 permissions |
| 2 | Login with `MEMBER` role | Integration | JWT contains `user:read` only |
| 3 | Login with no roles | Integration | `roles: []`, `permissions: []`; login succeeds |
| 4 | Login with revoked role | Integration | Revoked role absent from JWT claims |
| 5 | JWT size with 5 roles + 20 permissions | Performance | Token < 4KB |
| 6 | Role assigned → token refreshed | Integration | New access token includes new permission |

### Dependencies
- Blocked by: US-009 (RBAC schema + seeded roles), US-003 (JWT issuance)
- Blocks: US-011 (permission enforcement reads JWT)
- External: Redis (permission cache)

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| JWT bloat with large permission sets | Med | Med | Benchmark at 5 roles / 20 permissions; use short permission strings; strip descriptions |

### Out of Scope
- Real-time permission invalidation without re-login (future capability)
- Platform-wide permission claims

---

### US-011 — Enforce permission checks on API endpoints via Spring Security

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 5 | EPIC-002: RBAC Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a development team,
I want a standard `@RequiresPermission` annotation that enforces tenant-scoped permission checks on any API endpoint,
So that every future feature can be secured with a single annotation and no bespoke auth logic.

### Background / Context
The enforcement contract that all future epics consume. Reads permissions from the JWT (no DB call per request). Tenant boundary is enforced in the `PermissionEvaluator` — a permission granted in Tenant A never satisfies a check in Tenant B. This is the highest-consequence correctness requirement in EPIC-002.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | `@RequiresPermission` annotation works | Method annotated with `@RequiresPermission("tenant:write")` returns 403 if caller's JWT `permissions[]` does not contain `tenant:write`; returns expected response if it does | P0 | |
| 2 | Tenant boundary enforced | User with `tenant:write` in Tenant A receives 403 when calling an endpoint scoped to Tenant B, even if the permission name matches | P0 | Highest-consequence test |
| 3 | 403 response contract consistent | All permission failures return `403 + RBAC_001 + { "required_permission": "<name>", "message": "You do not have permission to perform this action" }` | P0 | |
| 4 | Unauthenticated request returns 401 not 403 | Missing or invalid JWT returns 401 (US-003 filter); permission check is only reached for authenticated requests | P0 | |
| 5 | Annotation usable on any controller method | `@RequiresPermission` applied to a new endpoint in any future controller compiles and enforces without additional configuration | P0 | Developer contract |
| 6 | Permission check latency | `@RequiresPermission` evaluation from JWT adds < 5ms to p95 endpoint response time (cache hit path) | P1 | |

### Technical Notes (ARC)
- `@RequiresPermission`: custom annotation + Spring `@PreAuthorize("@permissionEvaluator.hasPermission(authentication, #tenantId, '{permission}')")`
- `TenantAwarePermissionEvaluator` implements Spring `PermissionEvaluator`; extracts `tenant_id` from JWT; validates against `permissions[]` claim; cross-tenant check: JWT `tenant_id` must match the resource's `tenant_id`
- Enable method security: `@EnableMethodSecurity` on security config (not present anywhere in the codebase today — this story introduces it fresh, along with the first `PermissionEvaluator`/`@PreAuthorize` usage)
- 403 response: `GlobalExceptionHandler` **already** has a generic `AccessDeniedException` handler (returns `code=ACCESS_DENIED`) from EPIC-001's filter-chain security config. A method-security denial thrown by `@PreAuthorize` will hit that same generic handler unless it's a distinguishable type. Introduce `InsufficientPermissionException extends AccessDeniedException` (carrying the `requiredPermission` string) thrown by `TenantAwarePermissionEvaluator`, and register a handler for it in `GlobalExceptionHandler` that is more specific than (and takes precedence over) the existing generic one — returning `403 + RBAC_001 + { required_permission, message }` per the contract in AC3, while the generic `AccessDeniedException` handler remains the fallback for non-RBAC denials.
- Angular: no changes in this story (frontend guard is US-013)
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Caller has required permission | Integration | 200 / expected response |
| 2 | Caller lacks required permission | Integration | 403 + RBAC_001 |
| 3 | Caller has permission but wrong tenant | Security | 403 — cross-tenant boundary enforced |
| 4 | No JWT present | Integration | 401 (not 403) |
| 5 | JWT with manually injected permission claim (invalid signature) | Security | 401 — JWT filter rejects before permission check |
| 6 | 200 RPS on permission-guarded endpoint | Performance | p95 < 300ms; permission check < 5ms |
| 7 | New controller method annotated with `@RequiresPermission` | Unit | Compiles and enforces without extra configuration |

### Dependencies
- Blocked by: US-010 (JWT must contain `permissions[]` claim)
- Blocks: US-012, US-013; all future epics that protect endpoints
- External: none

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Cross-tenant boundary bug in `PermissionEvaluator` | Low | Critical | Dedicated security test suite; mandatory code review gate |

### Out of Scope
- Field-level or row-level permission filtering
- ABAC conditions on resource attributes

---

### US-012 — Enable role assignment and revocation API

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 5 | EPIC-002: RBAC Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a tenant administrator,
I want to assign and revoke roles for users within my tenant via an API,
So that I can control what each user is permitted to do on the platform.

### Background / Context
First admin capability on the platform. All endpoints are themselves protected by `@RequiresPermission` (US-011). Assignment is recorded in `user_roles` with `assigned_by`; revocation sets `revoked_at` (never hard-deleted). Cache is invalidated on every change so the next token refresh reflects the new state.

**Forward-tracked from US-009's Gate-2 threat model** (`docs/features/US-009/03b-threat-model.md`, found before this story reached its own Gate 1 — recorded now so it isn't discovered late): self-registered users and the seeded `TENANT_ADMIN` role share the same bootstrap tenant (pre-existing EPIC-001 design, not introduced by US-009), which means this story's assignment-authorization check is the *only* thing standing between an ordinary member and full tenant admin (T-E1). AC8 below makes that explicit. Two further findings (T-S2, T-R1) are folded into AC1/AC7's wording: `assigned_by` and the revocation actor must come from the authenticated principal, never request input.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | Assign role to user | POST /api/v1/users/{userId}/roles with `{ "roleId": "..." }` creates active `user_roles` row; `assigned_by` is set from the authenticated caller's principal, never from request input; returns 201; requires `user:write` permission | P0 | `assigned_by` sourcing per threat model T-S2 |
| 2 | Revoke role from user | DELETE /api/v1/users/{userId}/roles/{roleId} sets `revoked_at`; returns 204; requires `user:write` permission | P0 | Soft delete only |
| 3 | List roles for a user | GET /api/v1/users/{userId}/roles returns active role assignments; requires `user:read` permission | P0 | |
| 4 | Tenant isolation on assignment | Tenant Admin in Tenant A cannot assign roles to users in Tenant B; attempt returns 403 | P0 | |
| 5 | Revoking the tenant's last active TENANT_ADMIN role is blocked | If user is the only active `TENANT_ADMIN` in the tenant, revoking their admin role returns 409 + RBAC_002 | P0 | Actor-agnostic: fires for *any* caller revoking the tenant's last active `TENANT_ADMIN` assignment, not only self-revocation — prevents tenant lockout |
| 6 | Permission cache invalidated on change | The permission cache is invalidated via `PermissionCachePort.evict(tenantId, userId)` on assignment and revocation; next token refresh reflects change | P0 | |
| 7 | Assignment events audited | Every role assignment and revocation writes an event to the audit stream: `ROLE_ASSIGNED` / `ROLE_REVOKED` with user_id, role_id, assigned_by (assignment) or revoking principal (revocation), tenant_id | P0 | Revocation-actor attribution per threat model T-R1 |
| 8 | Only `TENANT_ADMIN` may grant `TENANT_ADMIN` | Assigning the `TENANT_ADMIN` role requires the caller to already hold an active `TENANT_ADMIN` assignment in that tenant (not just generic `user:write`); attempt by a non-admin returns 403, even if they somehow hold `user:write` | P0 | Hard AC per threat model T-E1 — the schema (US-009) places no backstop between a self-registered member and the all-permissions admin role; this check is the actual control |

### Technical Notes (ARC)
- Endpoints: POST + DELETE `/api/v1/users/{userId}/roles`, GET `/api/v1/users/{userId}/roles`, all protected by `@RequiresPermission`
- `RoleAssignmentService`: validates user and role both belong to caller's `tenant_id` before write
- Lockout guard: `SELECT COUNT(*) FROM user_roles WHERE role_id = :roleId AND tenant_id = ? AND revoked_at IS NULL` before any revocation of a `TENANT_ADMIN` role, where `:roleId` is resolved from `roles` by `(tenant_id, name = 'TENANT_ADMIN')` for the caller's own tenant, matched case-insensitively — there is no `TENANT_ADMIN` constant; `TENANT_ADMIN` is a per-tenant `roles` row
- Cache invalidation: `PermissionCachePort.evict(tenantId, userId)` in `RoleAssignmentService` after write
- Audit: publishes `ROLE_ASSIGNED` / `ROLE_REVOKED` events to existing audit event pipeline (US-008)
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Assign valid role to user in same tenant | Integration | 201; `user_roles` row active |
| 2 | Revoke role | Integration | 204; `revoked_at` set; row not deleted |
| 3 | Assign role to user in different tenant | Security | 403 |
| 4 | Revoke last `TENANT_ADMIN` role | Integration | 409 + RBAC_002 |
| 5 | Cache invalidated after assignment | Integration | Redis key absent; next login JWT reflects new role |
| 6 | Audit events emitted | Integration | `ROLE_ASSIGNED` and `ROLE_REVOKED` events in audit stream |
| 7 | DELETE on `user_roles` row directly | Security | Trigger blocks; `SQLSTATE '45000'` |
| 8 | Non-admin (holds `user:write` some other way) attempts to assign `TENANT_ADMIN` | Security | 403 — only an existing `TENANT_ADMIN` in that tenant may grant `TENANT_ADMIN` |

### Dependencies
- Blocked by: US-009 (schema), US-011 (permission enforcement)
- Blocks: US-013 (frontend reads assignments); Epic 3 (Tenant Admin surface)
- External: Redis (cache invalidation), audit event pipeline (US-008)

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Tenant lockout if last admin role removed | Med | High | Lockout guard in service layer + 409 response + integration test |
| Self-escalation to `TENANT_ADMIN` via a gap in assignment authorization (US-009 threat model T-E1 — the schema places all bootstrap users and the seeded admin role in one tenant with no backstop) | Med | Critical | AC8's "only `TENANT_ADMIN` can grant `TENANT_ADMIN`" check is the actual control; dedicated security test suite (Test Scenario 8) + mandatory code review gate, same rigor as the cross-tenant boundary test |

### Out of Scope
- Bulk role assignment
- Role assignment UI (Epic 3)
- Time-limited / expiring role assignments

---

### US-013 — Implement Angular permission guard and directive

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P1 | 3 | EPIC-002: RBAC Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a frontend developer,
I want a standard Angular route guard and permission directive that reads from the JWT,
So that every future feature can hide unauthorised UI elements and redirect unauthorised routes without bespoke logic.

### Background / Context
Frontend access control is UX only — the server-side `@RequiresPermission` (US-011) is the security boundary. The guard and directive make the frontend consistent and reduce boilerplate across all future feature modules. **Correction from the original draft:** the existing `AuthService`/`AuthStore` does not decode the JWT client-side at all — it fetches `roles[]` via `GET /v1/users/me` after login/refresh and stores it in signals. Both the guard and directive read from `AuthStore`'s signals (populated with the new `permissions[]` field added to `/users/me` in US-010), not a decoded token — no new JWT-decode dependency, no additional API call beyond what already runs today.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | `PermissionGuard` blocks unauthorised routes | Route configured with `{ canActivate: [PermissionGuard], data: { permission: 'tenant:write' } }` redirects to Access Denied page if `AuthStore`'s `permissions` signal does not contain `tenant:write` | P0 | |
| 2 | `PermissionGuard` does not redirect to login | Unauthorised but authenticated user sees Access Denied page, not login page | P0 | |
| 3 | `*appHasPermission` directive hides elements | `<button *appHasPermission="'tenant:write'">` is absent from DOM if permission missing; present if permission held | P0 | UX only — not a security boundary |
| 4 | Directive degrades gracefully | If the current-user signal has no `permissions`, directive treats as empty — element hidden, no console error thrown | P0 | |
| 5 | Access Denied page meets WCAG 2.1 AA | Heading hierarchy correct; keyboard-complete; "Contact your administrator" link has descriptive text; contrast ≥ 4.5:1 | P0 | |
| 6 | Guard and directive documented | Developer guide entry: usage example for both `PermissionGuard` and `*appHasPermission`; states explicitly that frontend guards are UX only | P1 | |

### Technical Notes (ARC)
- `PermissionGuard`: functional guard (`CanActivateFn`), matching the existing `authGuard` pattern (`src/app/core/guards/auth.guard.ts`) — `inject()` `AuthStore`/`Router`, check the `permissions` signal, return `true` or a `router.createUrlTree(['/access-denied'])`
- `HasPermissionDirective`: structural directive `*appHasPermission`; reads `AuthStore`'s current-user signal (via `effect()` or a computed signal, not an RxJS subscription — no `currentUser$` observable exists); uses `ViewContainerRef` to show/hide. This is the first structural directive in the codebase — place it under `src/app/shared/directives/` alongside the `shared/ui/*` and `shared/types/*` conventions
- `AuthStore` gains a `permissions` computed signal (or reuses `currentUser().permissions` once US-010 adds the field to `MeApiResponse`/`AuthUser`) — no JWT decoding, no new dependency
- `AccessDeniedComponent`: standalone routed page; reuse `NxErrorState` (`src/app/shared/ui/error-state/error-state.ts`), which already ships a documented "Access denied" usage example, rather than building a new presentational component
- `api-error.interceptor.ts` currently has no distinct 403 handling (it falls into the generic pass-through branch alongside 400/404/409) — add a 403 case so `AppError` surfaces the `RBAC_001` code/`required_permission` cleanly for any component that wants to show detail, while the guard/directive redirect on the boolean check alone
- No backend changes in this story
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Navigate to guarded route without permission | E2E | Redirect to Access Denied page |
| 2 | Navigate to guarded route with permission | E2E | Route activates normally |
| 3 | `*appHasPermission` with permission present | Unit | Element in DOM |
| 4 | `*appHasPermission` without permission | Unit | Element absent from DOM |
| 5 | JWT with no `permissions` claim | Unit | Element hidden; no error thrown |
| 6 | Access Denied page | Accessibility | Axe scan: zero critical issues |

### Dependencies
- Blocked by: US-010 (JWT must contain `permissions[]`), US-011 (403 response contract)
- Blocks: all future Angular feature modules that use guards or directives
- External: none

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Developers rely on frontend guard as security boundary | Med | High | Documented explicitly in developer guide; code review checklist item |

### Out of Scope
- Role management UI (Epic 3)
- Permission-based field hiding within a component (future, per-feature)

---

### US-014 — Audit role assignment and revocation events

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 3 | EPIC-002: RBAC Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a security and compliance team member,
I want every role assignment and revocation recorded immutably in the audit stream,
So that I can reconstruct who had access to what, and when, for any user in any tenant.

### Background / Context
Extends the US-008 audit pipeline with RBAC-specific events. No new audit infrastructure — events are appended to `auth_events` using the existing publisher. The event schema is extended with two new `event_type` values. Required before Epic 3 ships any admin surface.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | `ROLE_ASSIGNED` event emitted | Every successful role assignment writes a `ROLE_ASSIGNED` event within 1s: user_id, role_id, role_name, assigned_by, tenant_id, correlation_id | P0 | |
| 2 | `ROLE_REVOKED` event emitted | Every successful role revocation writes a `ROLE_REVOKED` event within 1s with same fields plus `revoked_by` | P0 | |
| 3 | Events are append-only | Existing `auth_events` trigger blocks UPDATE/DELETE; RBAC events inherit the same protection | P0 | No new mechanism needed |
| 4 | Failed assignments not audited as success | A 403 or 409 response from US-012 does not write a `ROLE_ASSIGNED` event; may write a `ROLE_ASSIGNMENT_DENIED` event | P1 | |
| 5 | Events queryable by tenant and user | `SELECT * FROM auth_events WHERE tenant_id = ? AND user_id = ? AND event_type IN ('ROLE_ASSIGNED','ROLE_REVOKED')` returns correct ordered history | P0 | |

### Technical Notes (ARC)
- No schema changes: two new `event_type` enum values added to `auth_events` (`ROLE_ASSIGNED`, `ROLE_REVOKED`)
- `RoleAssignmentService` (US-012) publishes events via existing `AuditEventPublisher` (US-008)
- Event payload stored in a `metadata` JSON column on `auth_events` (add column in `V3` migration or `V4` patch — ARC to decide)
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Assign role → query audit stream | Integration | `ROLE_ASSIGNED` event present with correct fields |
| 2 | Revoke role → query audit stream | Integration | `ROLE_REVOKED` event present |
| 3 | Failed assignment (403) → query audit stream | Integration | No `ROLE_ASSIGNED` event; optional `ROLE_ASSIGNMENT_DENIED` |
| 4 | UPDATE on `ROLE_ASSIGNED` event row | Security | Trigger blocks; `SQLSTATE '45000'` |
| 5 | Query by tenant + user + event type | Integration | Correct ordered history returned |

### Dependencies
- Blocked by: US-008 (audit pipeline), US-012 (role assignment service)
- Blocks: none — consumed by Epic 7 (Audit Log UI)
- External: none

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| ~~`metadata` JSON column absent from `auth_events`~~ | ~~Med~~ | ~~Med~~ | RESOLVED: column already exists (added in EPIC-001's `V2__identity_schema.sql`) — no schema change needed for this story |

### Out of Scope
- Audit log UI (Epic 7)
- Permission-level audit events (future granularity)
- SIEM export

---

### US-015 — Enable role and role-permission management API

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P1 | 9 | EPIC-002: RBAC Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a platform development team,
I want an API to create tenant-scoped roles and manage the permissions attached to them,
So that Epic 3 (and any future admin UI) has a ready-made, tenant-isolated API to let a Tenant Admin build custom roles beyond the two seeded system roles.

### Background / Context
US-009 seeds exactly two roles per tenant (`TENANT_ADMIN`, `MEMBER`) via migration, with no way to create or modify roles afterward. This story completes the RBAC data model's CRUD lifecycle within the `rbac` bounded context established by US-009–US-012, rather than leaving it for a not-yet-scoped Epic 3 to build against RBAC's own tables. It is explicitly **non-gating**: the Epic 3 kickoff gate remains US-009 (seed) + US-012 (assignment) only, per the epic Synthesis. System roles (`is_system_role = TRUE`) must be immutable through this API — `TENANT_ADMIN` and `MEMBER` can never be edited or have their permissions changed or removed via these endpoints, only via a future migration.

**Forward-tracked from US-009's Gate-2 threat model (T-E5):** `roles.is_system_role` is seeded `TRUE` for `TENANT_ADMIN`/`MEMBER` starting in US-009, but it is **inert** until this story's AC7 ships — nothing enforces it beforehand. No `role_permissions`-mutation endpoint may ship before this story's immutability check lands.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | Create role | `POST /api/v1/roles` with `{ "name": "...", "description": "..." }` creates a role scoped to the caller's tenant with `is_system_role = FALSE`; returns 201; requires `role:write` | P0 | |
| 2 | List roles in tenant | `GET /api/v1/roles` returns only roles belonging to the caller's tenant; requires `role:read` | P0 | |
| 3 | List permissions on a role | `GET /api/v1/roles/{roleId}/permissions` returns the role's assigned permissions; 404 if the role isn't in the caller's tenant; requires `role:read` | P0 | |
| 4 | Assign permission to role | `POST /api/v1/roles/{roleId}/permissions` with `{ "permissionId": "..." }` creates a `role_permissions` row; returns 201; requires `role:write` | P0 | |
| 5 | Remove permission from role | `DELETE /api/v1/roles/{roleId}/permissions/{permissionId}` removes the row; returns 204; requires `role:write` | P0 | |
| 6 | List all available permissions | `GET /api/v1/permissions` returns the 7 code-seeded permissions; requires `role:read` | P0 | |
| 7 | System roles are immutable | Any write (`POST`/`DELETE` on `/permissions`, or editing the role itself) targeting a role with `is_system_role = TRUE` returns 409 + `RBAC_003` | P0 | Protects `TENANT_ADMIN`/`MEMBER` from being altered via this API |
| 8 | Tenant isolation | A caller in Tenant A cannot read or write roles/role-permissions belonging to Tenant B — 403/404 | P0 | Mirrors US-012 AC4 |
| 9 | Role name uniqueness enforced | Creating a role with a name already used in the same tenant returns 409; the same name in a different tenant succeeds | P0 | Matches US-009's `UNIQUE (tenant_id, name)` |
| 10 | Assigned users see updated permissions | After a role's permissions change, users holding that role see the change reflected within the existing cache TTL / token refresh window (no new SLA introduced) | P1 | See Technical Notes on cache fan-out |

### Technical Notes (ARC)
- New `RoleManagementService` in the existing `com.example.nexus.rbac` bounded context, alongside `RoleAssignmentService` (US-012) — same package, same tenant-scoping style (explicit `tenantId` parameter, not a Hibernate filter)
- System-role protection: check `is_system_role` before any mutating operation on a role or its `role_permissions`; throw a dedicated `SystemRoleImmutableException` mapped to `409 + RBAC_003` in `GlobalExceptionHandler`
- **Cache fan-out (new relative to US-012):** revoking/assigning a *user's* role invalidates that user's cache entry via `PermissionCachePort.evict(tenantId, userId)` (US-012). Editing a *role's* permissions here affects every user currently holding that role. Options: (a) query all active `user_roles` for the `role_id` and bulk-delete their cache keys on every `role_permissions` write, or (b) accept the existing 15-min TTL / 7-day refresh lag as sufficient and document it identically to US-012's revocation lag. Pick (a) if role-permission edits are expected to be rare-but-security-sensitive; (b) is simpler and consistent with the epic's already-accepted cache lag elsewhere — default to (b) unless ADR-0013 says otherwise.
- Endpoints all protected by `@RequiresPermission` (US-011); no new enforcement mechanism needed
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Create role in own tenant | Integration | 201; role persisted with `is_system_role = FALSE` |
| 2 | Create role with duplicate name in same tenant | Integration | 409 |
| 3 | Assign permission to a custom role | Integration | 201; `role_permissions` row created |
| 4 | Remove permission from a custom role | Integration | 204; row removed |
| 5 | Attempt to modify `TENANT_ADMIN`'s permissions | Security | 409 + `RBAC_003` |
| 6 | Attempt to read/write a role in another tenant | Security | 403/404 |
| 7 | List permissions | Integration | Returns all 7 seeded permissions |
| 8 | User holding a role whose permissions just changed | Integration | Reflects new permissions within documented cache/refresh window |

### Dependencies
- Blocked by: US-009 (schema), US-011 (permission enforcement pattern)
- Blocks: none — Epic 3's future Tenant Admin UI is a consumer, not a dependency
- External: Redis (if cache fan-out option (a) is chosen)

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Cache fan-out on role-permission edits leaves stale permissions for many users at once | Med | Med | Default to documenting the existing TTL/refresh lag (option (b) above) unless a stricter SLA is required |
| System-role immutability check missed on one of the 3 write endpoints | Low | High | Single shared guard in `RoleManagementService`, not per-controller; covered by AC7's security test suite |

### Out of Scope
- Role deletion (only creation/read + permission attach/detach in this story)
- Bulk permission assignment
- Role templates / cloning
- The Epic 3 Tenant Admin UI itself

---

### US-016 — Gate role assignment/revocation by actual privileges, not role name

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | High — hard expiry at Epic 3 kickoff | _(unestimated — pending Gate 1)_ | EPIC-002: RBAC Foundation | _(unscheduled — must land before Epic 3 kickoff)_ | _(Tech lead assigns)_ |

### User Story
As a platform security owner,
I want role assignment and revocation (`RoleAssignmentService.assign()`/`revoke()`) to check the *privileges* a role actually confers, not just whether its name matches `TENANT_ADMIN`,
So that a custom role built via US-015 and later renamed, or any role a `TENANT_ADMIN` grants dangerous permissions to, is gated the same way the seeded `TENANT_ADMIN` role is.

### Background / Context
This story closes the "propagate" half of a privilege-escalation chain that US-015 deliberately left open as an accepted residual risk (RES-1 / R-3, D15 condition C3, `docs/features/US-015/03-design.md` §10, `03b-threat-model.md` §4.5). US-015 closed the "mint" side: attaching a dangerous permission (`role:write`, `user:write`, `tenant:write`) to *any* role now requires the caller to hold an active `TENANT_ADMIN` assignment (AC11).

What remains open, confirmed live in `RoleAssignmentService.java` (M-3 / T-E9 notes on `assign()`/`revoke()` respectively): both methods still gate the `TENANT_ADMIN` grant/revoke path by matching the target role's *name*, not by whether the role being assigned actually carries admin-equivalent privileges. A role named anything other than `TENANT_ADMIN` that has been granted `role:write`/`user:write`/`tenant:write` (a legitimate, admin-gated action per US-015 AC11) can then be assigned to — or have `TENANT_ADMIN` stripped by — any `user:write` holder through the ordinary, non-admin-gated path.

**Hard expiry:** Epic 3 makes attaching dangerous permissions to custom roles a routine, expected admin action, which invalidates the premise that exploitation is rare/detectable. Per D15's risk-acceptance record, this story becomes P0 the first time the `nexus.rbac.dangerous_permission_granted` compensating-control alert fires in any environment, and must in any case be re-reviewed by 2026-11-27 or at Epic 3 kickoff, whichever is earlier.

**Gate 1 note:** requirements analysis (`docs/features/US-016/01-requirements.md`) resolved the story's three self-flagged open questions: (1) the gate reuses `RbacDangerousPermissions.NAMES` unchanged; (2) `revoke()` gets the **identical** privilege-based gate as `assign()` — not a documentation-only "review" — per the threat model's own conclusion that fixing only `assign()` is worse than fixing neither; (3) the `nexus.rbac.self_role_assignment` counter/composed page-alert is retained but reinterpreted as a post-release canary on the gate itself, not a live-exploit signal. Gate 1 also found that this story requires **a new ADR** before/alongside design, per the explicit precedent set in US-015's own design document (§0) for expanding `assign()`/`revoke()`'s shipped authorization contract. Out of scope: any backfill/remediation of assignments made during the US-015→US-016 exposure window (forward-only fix; a one-off exposure audit is a tracked follow-up action, not story scope), and extending AC5's last-admin-lockout mechanism to custom admin-equivalent roles (a distinct mechanism — tracked as a follow-on risk, not built here).

### Acceptance Criteria — Gate 1 resolved (`docs/features/US-016/01-requirements.md`)
| # | Criterion | Notes |
|---|-----------|-------|
| 1 | `assign()` denies granting a role that carries any of `role:write`/`user:write`/`tenant:write` unless the caller holds an active `TENANT_ADMIN` assignment | Extends the existing name-match check to a privilege-check. Permission set resolved at Gate 1: reuse `RbacDangerousPermissions.NAMES` unchanged; reuse the same `hasActiveAdminAssignment` mechanism and a Q7-shaped dangerous-permission lookup per the design's own forward note |
| 2 | `revoke()` gets the **identical** privilege-based gate as `assign()` | Resolved at Gate 1 (no longer just a "review"): symmetric gate required — fixing only `assign()` would leave a worse, asymmetric admin-stripping hole per the threat model |
| 3 | The `nexus.rbac.self_role_assignment` counter (US-015 RC-7) is retained, reinterpreted as a post-release canary on this gate rather than a live-exploit signal | Resolved at Gate 1; exact alert-routing change is a design/Gate-2 detail |

### Dependencies
- Blocked by: US-015 (defines the dangerous-permission set and the `hasActiveAdminAssignment` mechanism this story extends) — **satisfied**, merged
- Should land before: Epic 3 kickoff (hard expiry on the R-3 risk acceptance this story resolves)
- New: requires a dedicated ADR alongside Phase 3 design (Gate 1 finding — see Gate 1 note above)

### Risks
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| **[US-016 shipped, 2026-09-16]** RES-1(b) (attach-after-assign propagate path, T-E21) survives this story — a `user:write` holder can still be silently escalated when an administrator later attaches a dangerous permission to their own self-assigned, then-benign custom role. `revoke()`/T-E17 admin-stripping and `assign()`/T-E16's *direct* propagate path are closed | Med | **Med** (down from Critical now D13's detective signal is live — no longer "not yet prioritized") | D13 ships in this story: holder-count WARN + `nexus.rbac.dangerous_permission_granted{holders}` counter on `attachPermission` (`docs/features/US-016/03-design.md` §4.7). Detective, not preventive. Owner (Md Nisar Ahmed, inherited from US-015 Gate 2) reviews by 2026-11-27 or at Epic 3 kickoff, whichever is earlier — expiry unchanged, transferred per design §12.3 |
| AC5-style last-admin-lockout protection does not extend to custom admin-equivalent roles (Gate 1 finding, explicitly out of scope here) | Low | Med | Tracked as a follow-on risk/backlog entry by the story owner, not built in this story |

### Out of Scope (Gate 1 resolved)
- Backfill/remediation of assignments made during the US-015→US-016 exposure window — forward-only fix; a one-off exposure audit is a tracked follow-up action outside story scope
- Extending AC5's last-admin-lockout mechanism to custom admin-equivalent roles — a distinct mechanism, tracked as a follow-on risk
- Exact `DenialReason` value(s) and self-assignment/AC8 precedence ordering — deferred to Phase 3 design with recommended defaults recorded in the requirements doc

### Validation note
Verified against current code (`nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`) and `docs/features/US-015/03-design.md` §10 / `03b-threat-model.md` §4.5 on 2026-09-09: the described gap is real and unresolved, the story is correctly scoped as US-015's D15/C3 successor, and its sole blocking dependency (US-015) has merged. Full requirements/impact scoping is deferred to this story's own Gate 1, per its explicit DRAFT status.

### Implementation Status (2026-09-16)
Gate 2 (`docs/features/US-016/03-design.md`, `03b-threat-model.md` — conditional pass, all required changes discharged per design §14) and Gate 3 (`docs/features/US-016/04-tasks.md`, 23 tasks) are both complete and approved. All 18 code tasks (T-001–T-018) and the four documentation tasks (T-019 ADR-0017, T-020 US-012 monitoring amendment, T-021 US-015 monitoring/threat-model correction, T-022 US-016 `monitoring.md`/`runbook.md`) are implemented, independently re-verified against the shipped code, and reported.

**Closure is partial, not full — recorded precisely so this entry is never misread as "R-3 resolved":**
- **T-E9 / T-E17 (revoke-side admin stripping): closed outright.** `revoke()` now carries the identical privilege-based gate as `assign()`.
- **T-E16 (propagate-side self-escalation via `assign()`): closed for the direct propagate path only.** The attach-after-assign sequence (self-assign a benign custom role, then have an administrator later attach a dangerous permission to it) is **not** covered by this gate — no race, no collusion, no gate evaluation applies to that sequence, by design — and survives as **US-016 RES-1(b) / T-E21**, mitigated (not closed) by D13's holder-count detective signal (`docs/features/US-016/03-design.md` §4.7, §12.3).
- RES-1(b) carries forward US-015's original owner (Md Nisar Ahmed), the 2026-11-27 review date, and the Epic-3-kickoff hard expiry, unchanged.

**Outstanding before this story is fully landed:** Phase 8 (`/test-validate`) has not yet run. The staging soak that produces the measured p50/p95/p99 lock-hold baseline (`docs/features/US-016/monitoring.md` §4, currently marked `⚠ PENDING`) and the staging execution of the exposure-audit SQL (`runbook.md` §6, currently validated only against a local Docker/Flyway MySQL instance, explicitly labeled as such) are both still pending. `/review`, `/security-review`, `/test-validate`, and `/pre-pr-check` have not yet been run.

---

### US-017 — Extend last-admin lockout protection to admin-equivalent custom roles

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | High — RES-3 backlog item, hard-linked to Epic 3's admin-boundary question | _(sized at Gate 3 — 8 consolidated implementation tasks, T-001–T-008)_ | EPIC-002: RBAC Foundation | _(in progress)_ | Md Nisar Ahmed |

### User Story
As a platform security owner,
I want the tenant-wide last-admin lockout guard and the zero-admin health indicator to protect/detect **every** admin-equivalent role — not only the literally-named `TENANT_ADMIN` — and I want a holder of such a role able to pass the same caller-side gate US-016 built,
So that a tenant cannot be silently locked out of administration via a custom dangerous-permission-carrying role, and a legitimate administrator-equivalent user is not permanently stuck unable to administer.

### Background / Context
Supersedes the US-016 stub filed under this epic's Open Decisions item 7. Closes **RES-3** (US-016 §12.3: the lockout guard and the health indicator cover only the literal `TENANT_ADMIN`) and, **partially**, **RES-9** (US-016 §12.3: the caller-side admin test remains name-based while the target-side test became privilege-based). Was paired with RES-9 as "one Epic-3 question" per the original stub; Gate 1 resolved that pairing by scoping this story to the assign/revoke caller test only, with the mint-side remainder (`attachPermission`/`detachPermission`'s caller test) carried forward as this story's own new residual, **RES-13** — not folded in silently.

### Implementation Status (2026-09-24)

**Gate 1** (`docs/features/US-017/01-requirements.md`, approved 2026-09-17) and **Gate 2** (`docs/features/US-017/03-design.md` Revision 2; `03b-threat-model.md`, **Gate 2 CLOSED 2026-09-18**) are both complete. The threat model's conditional pass required eight changes (RC-15…RC-22) plus five editorial corrections; all thirteen were folded into the design and independently re-verified line-by-line by the reviewer at closure (`03b-threat-model.md` §9.7) — no Blocker, no decision returned to the Architect, no new threat found. **Gate 3** (`docs/features/US-017/04-tasks.md`, consolidated to 8 implementation-sized tasks T-001–T-008) is complete. **T-001–T-008 are all implemented, 2026-09-24.** T-007's five-part integration test suite (`AdminEquivalentLockoutIT` new, `RbacZeroActiveAdminsHealthIndicatorIT` new, `RoleAssignmentSecurityIT` extended) is landed and green under a full Docker-backed `./mvnw verify` (1387 tests, 0 failures, 0 errors). T-008's seven documentation/governance edits ((a)–(g): `docs/features/US-012/monitoring.md`, `docs/features/US-012/runbook.md`, `docs/features/US-016/monitoring.md`, `docs/features/US-016/runbook.md`, `docs/features/US-015/monitoring.md`, `docs/features/US-016/03-design.md` §6.4/§9.6/§12.3, `docs/features/US-017/03-design.md` editorial fold-ins) are all landed and cross-checked against the shipped code; this entry (h) is the eighth. **T-008 is not fully closed, only because three of its sub-items have a hard, non-skippable dependency on live staging/Ops action this session cannot perform** — RC-21's forensic SQL executed once against real staging data (§9.5(b)), the Phase 8 soak's measured lock-hold/lock-set-size baseline (§9.5(c)), and RC-19's Ops sign-off (merge checklist item 4 below). All doc/code content that does not depend on those three items is complete.

**Phase 6 (`/review`, `06-code-review.md`) and Phase 7 (`/security-scan`, `07-security-review.md`) both ran, 2026-09-24.** Code review: **APPROVE WITH NITS** (1 Medium — the caller gate's two-sequential-query shape vs. the design's pinned single-call pseudocode, resolved via a design addendum, no code change; 2 Low). Security review: **initially BLOCKED** — found **H-1** (High, A01/A04): the lockout guard and `RbacZeroActiveAdminsHealthIndicator` both counted the ANY-admin-equivalent population, not the caller-qualifying (D2) population, so a tenant could retain an ANY-only holder while losing its last holder able to ever pass the caller gate again, with both controls still reporting healthy — a genuine regression of AC5's guarantee, not caught at Gate 2. Also found **M-1** (Medium, A09): the gate-bypass canary read the caller's state *after* the assign() INSERT committed, making `callerIsAdmin="false"` unreachable for a self-assignment of a fully-admin-equivalent role — the exact case the canary exists to catch. **Both fixed and verified same-day** (`ActiveAssignmentHolder` gained a `roleId` field; the lockout guard and FR-2's two queries re-scoped to the caller-qualifying predicate; the canary's M4/M12 read moved to before the INSERT) — full Docker-backed `./mvnw verify` green after both fixes. Recorded as threat-model **RES-24** (H-1) and **RES-25** (M-1), both closed same-day, no review-date carry-forward.

**Phase 8 (`/test-validate`, `08-test-audit.md`) ran, 2026-09-24.** Closed the security review's **L-3** finding (missing HTTP-level test for the D13 detach gate) with three new cases in `RolePermissionSecurityIT`, plus two more HTTP-level cases closing an authorization-matrix asymmetry on `revoke()`'s privileged-gate branches in `RoleAssignmentSecurityIT`. Corrected a stale comment in `role-change-privileged-denial-throttle.k6.js` (its assign-side scenarios already exercised D7's new pre-gate lock; the watch-list just didn't say so). **Full suite: 1437/1437 passing, 0 failures, 0 errors, 1 pre-existing skip** — independently reproduced twice. **L-1 and L-2 remain open**, correctly deferred to follow-up tasks (neither has a test-only fix). Frontend not applicable — this story touches zero frontend files.

**Closure is partial, not full — recorded precisely, mirroring US-016's own discipline above, so this entry is never misread as "RES-9 fully resolved":**
- **RES-3: closed end to end.** FR-1 (the tenant-wide, distinct-holder lockout guard) and FR-2 (the widened `RbacZeroActiveAdminsHealthIndicator`) both use the single `RbacAdminEquivalence.isAdminEquivalent` predicate (D1/D5/D10–D12), so the preventive and detective controls cover the same population by construction, not by two independently-maintained queries.
- **RES-9: closed for the `assign()`/`revoke()` caller test only.** A caller holding a role carrying all three dangerous permissions (or the literal `TENANT_ADMIN`) can now pass `requireActiveTenantAdmin` (D2's `isFullyAdminEquivalent` predicate) — the gap US-016 §12.3 RES-9 named.
- **Not closed on the mint side — carried forward as US-017 RES-13, not silently dropped.** `RoleManagementService.attachPermission`/`detachPermission`'s caller test stays name-based (D18). A fully admin-equivalent caller can reach the mint-side population in one self-assignment of the literal `TENANT_ADMIN`, so RES-13 is recorded as narrower **by construction** but **not a containment** (threat model T-E28/RC-16.1) — do not read the surviving asymmetry as a control.
- **US-016 RES-1(b) (the attach-after-assign pre-positioning primitive) is not closed by this story and is materially amplified by it** (threat model T-E27, High): FR-3 raises its payoff from admin-equivalent *permissions* (effective at next token mint) to caller-side *administrative capability* (effective on the next request), and, one self-assignment later, the literal `TENANT_ADMIN`. Mitigated by a new detective signal (D22, `RBAC_ROLE_BECAME_FULLY_ADMIN_EQUIVALENT` — see `docs/features/US-015/monitoring.md`), not closed. Owner, review date and Epic-3 hard expiry are unchanged (see merge checklist below).

**Outstanding before this story is fully landed (do not read any of these as resolved elsewhere in this document set):**
1. **Phase 8 staging soak has not run.** `docs/features/US-016/monitoring.md` §4's lock-hold baseline (re-derived for the widened region and for `assign()`) and `nexus.rbac.admin_equivalent_lock_set_size`'s p99 threshold are both marked `PENDING — Phase 8 staging soak measurement required`, matching the pre-existing PENDING convention rather than inventing numbers.
2. **RES-10's closure evidence: CLOSED, 2026-09-24.** D7 (the change intended to close US-016 RES-10 by making the tenant-wide union-lock acquisition order total across both verbs) required `LastAdminLockoutIT`'s reshaped harness C (the `assign(TENANT_ADMIN)` thread restored, plus a new benign thread, T-003(f)) green over ≥5 consecutive runs under Docker as its exit gate. **Root cause of the earlier failures was not a lock cycle:** MC-C's own fix (native `FORCE INDEX (fk_user_roles_role)` on M11) surfaced an unrelated, pre-existing resource-sizing artifact — Spring Boot's Hikari default (`maximum-pool-size=10`) is one short of harness C's 11 truly-concurrent threads, so one thread always queued for the full 30 s Hikari connection-acquisition timeout, alone exceeding the harness's 15 s `awaitTermination` budget regardless of locking correctness (confirmed by an isolated 90 s-budget diagnostic run, which completed cleanly in ~34 s and logged the exact `HikariPool-1 ... request timed out after 30003ms` condition). Fixed by raising `LastAdminLockoutIT`'s `@SpringBootTest` properties to `spring.datasource.hikari.maximum-pool-size=15` (test-scoped only); the original 15 s `awaitTermination` budget — the actual deadlock-detection sensitivity — was left unchanged. **Evidence: 5/5 consecutive green runs** against real Docker/Testcontainers MySQL 8.4 on 2026-09-24, zero exceptions and zero pool-timeout warnings in any run. See `docs/features/US-016/03-design.md` §12.3 RES-10 for the full account.
3. **Two further mechanical controls: both CONFIRMED GREEN, 2026-09-24.** MC-A's SQL-capture assertion (`should_neverEmitForShareOrForUpdate_when_capturingM7M8AndM9sSql`) was failing because its M7 matcher (`findStatementMatching(flowASql, List.of("role_permissions"), List.of())`) also matched M10's new tenant-scoped `role_permissions` read; fixed by adding `List.of("tenant_id")` as an exclusion term so the matcher disambiguates M7 from M10 — a test-assertion specificity fix, not a production change. MC-C's IN-list plan-stability assertion was failing for a real reason: M11's original JPQL `@Lock(PESSIMISTIC_WRITE)` form (no index hint) let MySQL's optimizer fall back to a full table scan (`key=null`) at IN-list cardinality 25, breaking D8's containment proof — an **Architect-level finding**, fixed (not relaxed) by converting M11 to a native query with `FORCE INDEX (fk_user_roles_role)`, matching the established M5/M5b pattern (`JpaUserRoleRepository.lockActiveAssignmentHoldersByRoles`; adapter and its unit test updated accordingly). Both assertions now pass.
4. **MC-I's equivalence IT (`AdminEquivalenceSqlJavaEquivalenceIT`): CONFIRMED GREEN, 2026-09-24 (2/2).** The fixture defect (`should_agreeWithJavaCombinator_acrossFixtureMatrix_MCI` violated `chk_user_roles_revoked_not_before_assigned`) was in the test's `seedRevokedAssignment` helper: it called `.revoke()` before the entity's initial INSERT had flushed, racing DB-generated `assigned_at` against Java-supplied `revoked_at`. Fixed with two separate `saveAndFlush()` calls (insert, then revoke). Production code was not at fault.
5. **RC-19's Ops sign-off has not been obtained.** The ≥1-year retention figure for `RBAC_LAST_ADMIN_REVOCATION_BLOCKED`, `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` and `RBAC_DANGEROUS_PERMISSION_DETACH_BLOCKED` is **named** in `03-design.md` §9.4, but Ops sign-off on it is an explicit, outstanding, blocking human action item — flagged since T-006, not fabricated as done here.
6. **RC-21's forensic sweep SQL is written and locally sanity-checked, but not yet executed against real staging data.** The attribution query and the detection query are in `docs/features/US-012/runbook.md` §2, cross-checked against the shipped schema and audit-adapter metadata shape, and additionally validated on 2026-09-24 against a disposable local MySQL fixture (two admin-equivalent revocations, one that zeroes the tenant and one that doesn't): the sweep returned exactly the one row expected, correctly attributed via `auth_events`. That confirms the SQL's logic, not staging reality — per RC-21's own four-part requirement, an unexecuted-in-staging runbook query is not yet a control. A human/CI step must still run it once against real staging data before this sub-item's Definition of Done is satisfied.
7. `/review`, `/security-review` (beyond Gate 2's own threat-model pass), `/test-validate`, and `/pre-pr-check` have not yet all been run to completion. With items 2–4 above now resolved, the remaining blockers are the Phase 8 staging soak (item 1), RC-19's Ops sign-off (item 5) and RC-21's staging execution (item 6).

**Merge checklist (per `03b-threat-model.md` §8, reconfirmed at §9.7 — non-code items, following the US-015 §4.5 / US-016 §8 precedent):**

| # | Item | Status |
|---|---|---|
| 1 | RES-1(b)'s amplification recorded with its inherited owner (Md Nisar Ahmed), 2026-11-27 review date and Epic-3 hard expiry | **Confirmed landed** in `docs/features/US-017/03-design.md` §12.3 (citation-only row, no competing entry) and ADR-0018's "what this ADR does not close" — per Gate 2 closure, not re-authored here |
| 2 | RES-10 closure evidence attached to the PR | **CLOSED, 2026-09-24 — 5/5 consecutive green runs** under Docker-backed execution (`LastAdminLockoutIT` harness C). Root cause of the earlier failures was a Hikari connection-pool sizing artifact (10 < 11 concurrent threads), not a lock cycle — see `03-design.md` §12.3 RES-10 and outstanding-items note 2 above for the full account |
| 3 | RES-17 / RES-18 / RES-13's re-ratings reflected in `03-design.md` §12.3 | **Confirmed landed** (RES-17 Low→Medium, RES-18 Low→Medium restated over three consumers, RES-13 Low-Med→Medium with the RC-16.1 wording correction) — per §9.7, not re-authored here |
| 4 | RC-19's retention figure named, **with Ops sign-off obtained** | Figure named (≥ 1 year, `docs/observability-standards.md`). **Ops sign-off: OUTSTANDING — a blocking, human action item, not obtained as of this entry** |
| 5 | RC-21's sweep output retained as dated evidence, with a remediation ticket or written acceptance per affected tenant, **before** the production deploy step | SQL written into `docs/features/US-012/runbook.md` §2 (RC-21's four-part requirement: attribution, executable SQL, all-environments scope, evidence retention + stated action). **Logic validated locally, 2026-09-24** (disposable fixture: one non-zeroing revocation correctly excluded, one zeroing revocation correctly returned with `auth_events` attribution). **Not yet executed against staging** — outstanding until a human/CI step runs it and the per-tenant tickets/acceptances (if any tenants are found) exist |
| 6 | `./mvnw dependency:tree` runs at Phase 7 | Confirmed at Gate 2: no dependency-manifest delta exists on this branch, so there is nothing to scan earlier. **Scheduled for Phase 7, not yet run** |

**Note, not created:** `docs/features/US-017/monitoring.md` and `docs/features/US-017/runbook.md` are **Phase 8** deliverables per this epic's established convention (they document what shipped, verified against code and the staging soak's measured figures) — explicitly out of scope for Gate 3/`/breakdown` and deliberately **not** drafted early from the design's intent.

---

## Recommended Sprint Order

| Sprint | Stories | Points | Notes |
|--------|---------|--------|-------|
| Sprint 3 | US-009, US-010 | 11 | Schema + JWT population; foundation before enforcement (US-009 revised 5→8 pts at Gate 1) |
| Sprint 4 | US-011, US-012, US-014 | 13 | Enforcement + assignment API + audit; Epic 3 gate met |
| Sprint 5 | US-013, US-015 | 12 | Frontend guards + role/permission management API; non-gating, can parallel-stream with Epic 3 start |
| Sprint 6 | US-016 | _(TBD at Gate 1)_ | Closes the D15/R-3 residual risk from US-015; hard deadline before Epic 3 kickoff, not just "recommended" |

## Open Decisions

_Resolved during feasibility review (see updates above), plus forward-tracked entry criteria surfaced during Gate 2 threat modeling; kept here for traceability._

1. **`metadata` column on `auth_events`** — ~~add in V3 migration (US-009) or a separate V4 patch?~~ **RESOLVED: no action needed.** The column already exists (added in EPIC-001's `V2__identity_schema.sql`, ahead of the `V4__auth_events_add_user_agent.sql` patch). US-014 uses it as-is.
2. **Role + permission management API** — ~~confirm these are in Epic 2 scope or deferred to Epic 3 UI~~ **RESOLVED (revised): kept in Epic 2, as new story US-015, non-gating.** `POST /roles`, `GET/POST/DELETE /roles/{id}/permissions`, and `GET /roles` / `GET /permissions` are `rbac`-bounded-context CRUD, not a Tenant Management concern — building them now reuses the context/controllers/services US-009–US-012 already establish, rather than requiring a context-switch back into `rbac` from a not-yet-scoped Epic 3. US-015 does **not** block the Epic 3 kickoff gate (still just US-009 + US-012) and is scheduled in Sprint 5. Epic point total corrected from the original 34 to 33 (24 core stories + 9 for US-015) accordingly (see ARC effort estimate).
3. **ADR-0013** (RBAC model + permission naming convention) — corrected from "ADR-003" in the original draft, which collides with the existing `0003-flyway-schema-migrations.md`; 0013 is the next free number in `docs/adr/`. **RESOLVED: Accepted.** `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` covers the permission naming convention, the `active_key` generated-column technique (US-009), the `InsufficientPermissionException` approach (US-011), and the cache-fan-out default (US-015). Sprint 3 gate cleared.
4. **Epic-3 entry criterion — controller-must-be-annotated ArchUnit rule (deferred from US-011)** — **OPEN — gates Epic 3 kickoff.** US-011 (`@RequiresPermission` enforcement) deliberately deferred the ArchUnit rule requiring every `@RestController` method to carry `@RequiresPermission` or an explicit `@PublicEndpoint` opt-out — there are no protected production controllers yet, and today's `identity` auth endpoints are legitimately `permitAll`/unguarded (design `docs/features/US-011/03-design.md` §B8; threat model `docs/features/US-011/03b-threat-model.md` finding T-03, verdict Condition 3). **The first protected controller in Epic 3 (Tenant Management) cannot merge until all three of the following exist:** (a) the ArchUnit rule itself — every `@RestController` method must carry `@RequiresPermission` or `@PublicEndpoint`; (b) the `@PublicEndpoint` opt-out annotation/convention; (c) a same-class self-invocation lint/ArchUnit check flagging direct calls to `@RequiresPermission` methods (folded in per threat-model Condition 4/T-05, so both deferred method-security gaps close together). Tracked here, not built in US-011 — see US-011 task `docs/features/US-011/04-tasks.md` T-011.
5. **Epic-3 entry criterion — `CrossTenantPermissionIT` as a merge-blocking CI gate (T-010, US-011)** — **RESOLVED — gate is live, confirmed in CI, not just documented intent.** `CrossTenantPermissionIT` (`com.example.nexus.rbac.security`, written under US-011 T-014) is the epic's only end-to-end proof of the Critical no-cross-tenant-privilege-escalation property — both its 403-denial and 200-positive-control tests are green. It runs automatically in the `backend-build` job's `mvn verify` (Failsafe's default `*IT`-suffix convention picks it up; no per-test CI configuration exists or is needed), and `backend-build` is already a required status check on `main` (branch protection: `strict: true`, `enforce_admins: true` — confirmed live via the GitHub API, not just `nexus-scripts/setup-branch-protection.sh`'s committed intent). No CI workflow or branch-protection changes were needed for T-010 — both already satisfied the "hard gate" requirement before this task started; the workflow file now carries an inline comment naming this test so a future `-DskipITs` or test-exclusion change can't silently weaken it. **Distinct from item 4 above** (the deferred ArchUnit `@RequiresPermission`-coverage rule, still **OPEN**): both are Epic-3 entry criteria, but this one is closed.
6. **US-016 successor story (D15 condition C3, US-015 Gate 2)** — **RESOLVED: filed and now formally tracked in this epic.** `docs/story/2-rbac/US-016.md` was filed pre-merge per US-015's threat model requirement that a named successor exist before that story merged; US-015 has since merged (`76470e2`). US-016 is added above as a full epic entry and to the sprint order (Sprint 6). It remains a **DRAFT stub pending its own Gate 1** — deliberately not pre-scoped, per D15/C3's own reasoning — and is a **hard, date-bound entry criterion for Epic 3 kickoff** (review by 2026-11-27 or Epic 3 kickoff, whichever is earlier), distinct from item 4's ArchUnit gate. Epic point total remains unrevised pending US-016's Gate-1 estimate.
7. **RES-3 successor story (US-016 Gate 1 #8, merge-checklist item)** — **RESOLVED: filed and now formally tracked in this epic.** `docs/story/2-rbac/US-017.md` — "Extend last-admin lockout protection to admin-equivalent custom roles" — is filed pre-merge per US-016's own threat-model/design merge checklist (`docs/features/US-016/03-design.md` §12.2 item 14, §12.3 RES-3, §14), following the US-016 stub precedent in item 6 above. It is a **DRAFT stub pending its own Gate 1**, deliberately not pre-scoped, and is paired with RES-9 (US-016 §12.3) as one Epic-3 question — see US-017's Background section. Not a hard date-bound gate the way item 6 is; US-016's design records RES-3 as Med severity, accepted out of scope, with the backlog story's existence (not its completion) being the merge blocker for US-016 itself. **[US-017, 2026-09-24] Superseded by the full story entry above.** Gate 1 (2026-09-17), Gate 2 (threat model closed 2026-09-18) and Gate 3 (8-task breakdown) are complete; the stub's "paired with RES-9 as one Epic-3 question" framing is resolved as RES-3 closed end to end and RES-9 closed for the assign/revoke caller test only, with RES-13 carrying the mint-side remainder forward — see the "US-017" section above for current implementation status and the merge checklist, which is not yet fully satisfied.
8. **RES-10 backlog observation (US-016 §12.3, T-D12)** — **RESOLVED: filed as an observation, not a story.** `RoleAssignmentService.assign(TENANT_ADMIN)` (S-lock on the caller's row, then an insert-intention lock in the `role_id = adminRoleId` gap) and `revoke(TENANT_ADMIN)` (M1's next-key range lock) can cycle under a mixed concurrent workload — pre-existing, **unrelated to and unchanged by US-016**. Recorded so that a future harness-C or production lock-wait failure under mixed `assign`/`revoke(TENANT_ADMIN)` traffic is not misattributed to this story. No successor story is filed for this item — it is deliberately **not a fix commitment**, per US-016 design §12.3 RES-10 ("Accepted as inherited... Filed as a separate backlog observation, not a US-016 fix"). Named in US-016's own `03-design.md` §7.2 property 3 and in `LastAdminLockoutIT`'s harness-C Javadoc. **[US-017, 2026-09-24] Closed at the root.** US-017 D7 closes this by making the tenant-wide union-lock acquisition order total across both verbs; the empirical exit gate for that fix (`LastAdminLockoutIT` harness C, ≥5 green runs under Docker, T-003(f)) is now satisfied (5/5 green, 2026-09-24). The harness's earlier failures traced to an unrelated Hikari connection-pool sizing artifact, not a surviving lock cycle — see `docs/features/US-016/03-design.md` §12.3 RES-10 for the full diagnosis. This backlog observation is now discharged, not merely status-updated.
9. **Dependency-hygiene backlog item for `npm audit`'s 27 pre-existing frontend toolchain findings (US-017 §12.1/Editorial 5)** — **NEW, filed here as instructed by the design's own editorial note, since no dependency-hygiene backlog item existed for it prior to this entry.** `npm audit` on the frontend reports 27 pre-existing findings (1 critical, 7 high, 16 moderate, 3 low), all in the Angular build/toolchain dependency graph (`tar`, `undici`, `qs`, …) — re-verified independently by both US-017's requirements/impact pass and its Gate 2 threat model (`03b-threat-model.md` §0.1 item 19). **Not attributable to US-017**, which touches zero files under `nexus-frontend/`. Warranted **independently of any RBAC story** — whoever picks this up must respect the known npm-Windows lockfile-prune trap (`npm install` on Windows strips `@emnapi` entries from the frontend lockfile, breaking Linux CI) when working it. No story id assigned yet; tracked here as an open item, not a hard gate for any story in this epic.