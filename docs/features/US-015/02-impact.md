# US-015 — Impact Analysis

**Feature:** Enable role and role-permission management API
**Epic:** EPIC-002 (RBAC Foundation)
**Phase:** 2 (Impact Analysis) — inputs: `docs/features/US-015/01-requirements.md` (Gate 1 approved, §11 Resolutions binding), `docs/story/2-rbac/US-015.md` (authoritative per §11 OQ3)
**Author:** Principal Architect
**Status:** Draft for Gate 2 entry

> This document is *read-only analysis*. Every §11 Gate 1 Resolution — including the new AC11 (dangerous-permission admin gating) and AC12 (role/role-permission audit events) — is treated as settled and applied, never re-litigated. Where this analysis contradicts or sharpens a claim in the requirements doc, the story, or the epic, the contradiction is called out with the verified code evidence.

---

## 0. Executive summary

US-015 is **additive-only**: **no Flyway migration, no schema change, no new `nexus_app` grant, no new dependency, no breaking change, zero frontend files touched.** `V5__rbac_schema.sql` already carries every table, column, constraint and index the story needs, and the ADR-0014 D6 / ADR-0015 D7 grant set already permits every DML statement all six endpoints plus AC11 and AC12 issue (§2.4).

The risk is concentrated entirely in the two ACs added at Gate 1. Both were specified by reference to existing US-012 mechanisms, and **neither mechanism composes as-is**:

| # | Finding | Severity |
|---|---|---|
| **F1** | **AC11's named mechanism cannot be called as-is.** `UserRoleAssignmentPort#hasActiveAdminAssignment(userId, roleId, tenantId)` requires *the tenant's `TENANT_ADMIN` role id* as an input. In US-012 that id fell out for free (`role.getId()` — the role being granted *was* `TENANT_ADMIN`); in US-015 the target role is an arbitrary custom role, so the admin role id must be resolved separately by `(tenant_id, name)`. **No port or repository method in the codebase performs that lookup** — `RoleAssignmentService.callerHoldsActiveTenantAdmin`'s own Javadoc states this explicitly ("the port exposes no 'find role by (tenant, name)' lookup") and works around it with a **non-locking projection read** that Gate 1 forbids for AC11. Copying that workaround is the single most likely way to ship AC11 looking correct while silently violating its stated locking semantics. | **High** |
| **F2** | **`RbacAuditEvent` cannot express any of AC12's three payloads.** The record is `(tenantId, targetUserId, roleId, roleName, actorUserId, requestContext)` — no `permissionId`/`permissionName` field for grant/revoke, and no meaningful `targetUserId` for role creation (which has no subject user at all). `RbacAuthEventAdapter#record` hard-wires `withUserId(event.targetUserId())` and a metadata key set (`assignedBy`/`revokedBy`/`attemptedBy`) built for assignment semantics. AC12 therefore needs a **new carrier type plus three new port methods**, not a reuse. `/design` must pick the shape; this analysis recommends one (§1.4). | **High** |
| **F3** | **AC11 closes the mint side of the M-3 escalation chain, not the propagate side.** Verified against `RoleAssignmentService.assign()` (lines 79–91, 107–124): AC8's guard still matches on the role **name** `TENANT_ADMIN`. Once a legitimate `TENANT_ADMIN` attaches `user:write` to `CustomRole` (which AC11 permits by design — Epic 3 needs it), **any** holder of `user:write` may grant `CustomRole` to anyone, including themselves, with AC8 never firing. `revoke()`'s T-E9 note documents the symmetric hole on the revoke path. Unreachable today (only `TENANT_ADMIN` carries `user:write`), reachable the moment US-015 ships and is used for its intended purpose. **This is in-scope to *record*, not to fix, but it must not be recorded as "closed."** | **High** |

Everything else is routine but not trivial: 1 new application service, 1 new outbound persistence port + adapter, 2 new controllers + ~6 DTOs, 3 new domain exceptions (**one of which has no error code assigned by Gate 1 — F4**), 4 genuinely new repository query methods, 3 new `AuthEventType` constants with a PRIORITY-lane decision to make, 3 new `RbacAuditPort` methods, 1 feature flag in 3 YAML files.

**Estimate note (requirements §11 hands this to `/impact-analysis`):** the original 9 points assumed 10 ACs with no admin gating and no audit surface. AC11 adds a new role-by-name lookup, a locking-read path and two dedicated security ITs; AC12 adds a carrier type, three port methods, three adapter methods, three enum constants and four audit ITs. **Recommend re-estimating to 13 points.**

---

## 1. Modules / classes affected

### 1.1 Backend — `rbac` bounded context (`nexus-backend/src/main/java/com/example/nexus/rbac/`)

**Existing inventory (verified by read, post-US-012/US-014):**

| Layer | Existing classes |
|---|---|
| `domain/` | `Permission`, `Role`, `RolePermission`, `RolePermissionId`, `UserRole`, `ResolvedPermissions`, `ActiveAssignmentRef`, `ActiveRoleAssignment`, `RoleChangeActor`, `RbacRoleNames`, `IdGenerator`, `LastAdminRoleException`, `DuplicateRoleAssignmentException` |
| `application/` | `RoleResolutionService`, `RoleAssignmentService` |
| `application/port/out/` | `UserRoleQueryPort`, `UserRoleAssignmentPort`, `PermissionCachePort`, `UserDirectoryPort`, `RbacAuditPort`, `RbacAuditEvent` |
| `infrastructure/persistence/` | `JpaPermissionRepository`, `JpaRoleRepository`, `JpaRolePermissionRepository`, `JpaUserRoleRepository`, `JpaUserRoleQueryAdapter`, `JpaUserRoleAssignmentAdapter` |
| `infrastructure/cache/` | `RedisPermissionCacheAdapter` |
| `infrastructure/crypto/` | `UuidV7IdGenerator` |
| `infrastructure/health/` | `RbacDbPrivilegeHealthIndicator`, `RbacZeroActiveAdminsHealthIndicator` |
| `interfaces/rest/` | `UserRoleController` |
| `interfaces/rest/dto/` | `AssignRoleRequest`, `RoleAssignmentResponse`, `RoleAssignmentListResponse` |

**NEW files — `rbac`:**

| Path | Kind | Notes |
|---|---|---|
| `rbac/application/RoleManagementService.java` | `@Service` | Orchestrates AC1–AC12. `@Transactional` on the three writes, `@Transactional(readOnly = true)` on the three reads. Sits beside `RoleAssignmentService`, same tenant-scoping style (explicit `tenantId`, no Hibernate filter). **Reuse `RoleChangeActor`** — do not introduce a second actor record; its `(userId, tenantId)` shape is exactly what is needed and it is already ArchUnit-covered. Must reuse `RoleAssignmentService`'s `verifySameTenant`-free / `resolveRoleInTenant`-equivalent 403-vs-404 shape (§3.2); note US-015 has **no** target *user*, so `UserDirectoryPort` is **not** a collaborator. |
| `rbac/application/port/out/RoleManagementPort.java` | interface | Read+write port over `roles`/`role_permissions`/`permissions`. **Must be a new port, not a widening of `UserRoleAssignmentPort`** — that port's Javadoc scopes itself to the assignment aggregate, and `RoleAssignmentService`/`JpaUserRoleAssignmentAdapterTest`/`RoleAssignmentServiceTest` all depend on its current surface (requirements R7 confirmed by read). Methods enumerated in §1.2. |
| `rbac/application/port/out/RoleAuditEvent.java` *(or `RolePermissionAuditEvent`)* | record | **F2.** New typed carrier(s) for AC12. Recommended single record: `(UUID tenantId, UUID roleId, String roleName, UUID permissionId, String permissionName, UUID actorUserId, RequestContext requestContext)`, with `permissionId`/`permissionName` null for `ROLE_CREATED` — matching `RbacAuthEventAdapter#buildMetadataJson`'s existing "omit null keys entirely, never emit JSON null" contract. Sits beside `RbacAuditPort`, as `RbacAuditEvent` does. |
| `rbac/domain/SystemRoleImmutableException.java` | exception | `extends common.domain.ConflictException`, code `RBAC_003`. Fixed static message, no DB text — copy `LastAdminRoleException`'s documented discipline verbatim. Closes requirements Gap 5 (`RBAC_003` had no committed message text). |
| `rbac/domain/DuplicateRolePermissionException.java` | exception | `RBAC_005` (§11 OQ5b). Same pattern. **Message must not echo the `pk_role_permissions` violation text** — MySQL's message would leak the constraint name and hex-encoded role/permission UUIDs, exactly the leak `DuplicateRoleAssignmentException`'s Javadoc documents. |
| `rbac/domain/DuplicateRoleNameException.java` | exception | AC9's 409. **F4 — Gate 1 registered no code for this.** Recommend `RBAC_006`; verified unused anywhere in `src/main` or `docs/`. |
| `rbac/domain/RbacDangerousPermissions.java` | constants | AC11's fixed set `{role:write, user:write, tenant:write}`, single-sourced with a case-insensitivity note, mirroring `RbacRoleNames`' own Javadoc rationale (`permissions.name` also lives under `utf8mb4_0900_ai_ci`). A private `Set` inside the service would work but hides a security-load-bearing constant from targeted unit testing — recommend the domain class. |
| `rbac/domain/RolePermissionView.java` | record | Projection for `GET /roles/{roleId}/permissions` — `(UUID permissionId, String name, String description)`. Avoids the N+1 in §7 and avoids returning managed `Permission` entities across the layer boundary (the same rationale `ActiveAssignmentRef`/`ActiveRoleAssignment` already document). |
| `rbac/infrastructure/persistence/JpaRoleManagementAdapter.java` | `@Component` | Implements `RoleManagementPort` over `JpaRoleRepository` + `JpaRolePermissionRepository` + `JpaPermissionRepository`. Translates `DataIntegrityViolationException` → `DuplicateRoleNameException` / `DuplicateRolePermissionException`, mirroring `JpaUserRoleAssignmentAdapter`'s existing translation (that adapter's own comment warns a mistranslation surfaces as a 500 instead of a clean 409). |
| `rbac/interfaces/rest/RoleController.java` | `@RestController` | `@RequestMapping("/api/v1/roles")`. 4 handlers (AC1, AC2, AC3, AC4, AC5 — five, see §3.1). |
| `rbac/interfaces/rest/PermissionController.java` | `@RestController` | `@RequestMapping("/api/v1/permissions")`. 1 handler (AC6). **Two controllers, not one**, because the two path roots differ; a single controller would need method-level absolute paths, which no existing controller does. Both gated on the *same* flag. |
| `rbac/interfaces/rest/dto/CreateRoleRequest.java` | record | `{ "name", "description" }`. `name` `@NotBlank @Size(max = 64)` (matches `roles.name VARCHAR(64)`); `description` optional (§11 OQ6), `@Size(max = 255)`. Closes requirements Gap 4. |
| `rbac/interfaces/rest/dto/AttachPermissionRequest.java` | record | `{ "permissionId" }`, `@NotNull` **as `String`**, parsed via the `parsePathUuid` pattern — never a `UUID`-typed field (§1.5). |
| `rbac/interfaces/rest/dto/RoleResponse.java` | record | 201 body + `GET /roles` element. Field set is `/design`'s call (Gap 2); recommend `id, name, description, isSystemRole, createdAt` — `isSystemRole` is needed by any Epic 3 UI to grey out the AC7-protected roles client-side, and is not sensitive (tenant-scoped, and AC7 already reveals it via 409). |
| `rbac/interfaces/rest/dto/RoleListResponse.java` | record | `{"data": [...]}` envelope, matching `RoleAssignmentListResponse`. |
| `rbac/interfaces/rest/dto/PermissionResponse.java` / `PermissionListResponse.java` | records | Same envelope for AC3 and AC6. |

**MODIFIED files — `rbac`:**

| Path | Change |
|---|---|
| `rbac/application/port/out/RbacAuditPort.java` | **+3 methods** (`recordRoleCreated`, `recordRolePermissionGranted`, `recordRolePermissionRevoked`). Interface Javadoc must be extended: its current text enumerates "the three" methods and their call-site semantics explicitly. See §1.4 for the never-throw/never-block carry-over and the denial-method question. |
| `rbac/infrastructure/persistence/JpaRoleRepository.java` | **+2** query methods (Q1, Q3 — §1.2). Currently a bare marker interface. |
| `rbac/infrastructure/persistence/JpaRolePermissionRepository.java` | **+2** query methods (Q7, Q9). Currently a bare marker interface. |
| `rbac/infrastructure/persistence/JpaPermissionRepository.java` | **Probably unchanged** — AC6 and the AC11/404 permission lookup are both served by inherited `findAll(Sort)` / `findById`. |

**UNCHANGED — explicitly verified, reused as-is:**

- `RoleAssignmentService` — **not modified by this story.** Its M-3 Javadoc forward-tracks AC11, but AC11 lives on the *attach* path in a different service. See **F3**: the Javadoc's claim ("a custom-roles story must close this") is only *partly* discharged, and `/design` should amend that Javadoc to say so rather than delete it.
- `UserRoleAssignmentPort` / `JpaUserRoleAssignmentAdapter` / `JpaUserRoleRepository` — **no signature change.** `hasActiveAdminAssignment` is reused verbatim (see F1 for the *missing input* problem, which is solved on the new port, not here).
- `PermissionCachePort` / `RedisPermissionCacheAdapter` — **not called at all.** AC10 + ADR-0013 D4 ratify option (b): no bulk fan-out invalidation. `RoleManagementService` therefore does **not** inject `PermissionCachePort`. This is a deliberate non-dependency, not an omission (§7, F6).
- `UserDirectoryPort` — not a collaborator; US-015 has no target user.
- `RbacDbPrivilegeHealthIndicator` — unchanged, but see F7: it covers **only** `user_roles`, leaving `roles`/`role_permissions` grant drift undetected now that this story makes them write targets.
- `RbacZeroActiveAdminsHealthIndicator`, `RoleResolutionService`, `UserRoleQueryPort`, `Role`, `Permission`, `RolePermission`, `RolePermissionId`, `RbacRoleNames`, `IdGenerator`/`UuidV7IdGenerator`, `RoleChangeActor`.

> **Role entity — do not mutate.** `Role` maps `tenantId`, `name`, `description`, `systemRole` as plain updatable columns (only `createdAt`/`updatedAt` are `insertable=false, updatable=false`). `nexus_app` holds **`SELECT, INSERT` on `roles` and no `UPDATE` at all**. Any code path that loads a `Role` and mutates it — even accidentally, even a "harmless" `setDescription` — flushes an `UPDATE` that MySQL rejects **in production only**, since every `*IT` connects as the Testcontainers `test` user with full DML. This is the identical failure class as US-012's F1/R-1, arriving through a different door. `RoleManagementService` must treat every loaded `Role` as read-only (F7).

### 1.2 New repository / port query methods

The three RBAC repositories relevant here are **confirmed bare marker interfaces** (`extends JpaRepository<X, …>`, zero custom methods). Exact JPQL is `/design`'s job; this is the *requirement* list, and the AC each one exists for.

| # | Repository | Purpose | AC | Index / notes |
|---|---|---|---|---|
| **Q1** | `JpaRoleRepository` | List roles by tenant | AC2 | Served by `uq_roles_tenant_name (tenant_id, name)` **leftmost prefix** — no new index. **Add a deterministic `ORDER BY name`**: without it MySQL's order is unspecified, and Gap 3 (no pagination) makes a stable order the only thing a client can rely on. |
| **Q2** | *(inherited `findById`)* | Role by id, for the exists/tenant/system-role checks | AC3, AC4, AC5, AC7, AC8 | PK lookup. Exposed on the **new** port, not by reusing `UserRoleAssignmentPort#findRole` (§1.1 rationale). One read serves the 404, the 403, and the `is_system_role` boolean — **`role.isSystemRole()` needs no extra query**, confirming requirements §3's architectural claim. |
| **Q3** | `JpaRoleRepository` | **Find the tenant's `TENANT_ADMIN` role by `(tenantId, name)`** | **AC11** | **F1 — this is the method that does not exist.** Use a plain `r.name = :name` predicate and rely on `roles`' `utf8mb4_0900_ai_ci` collation for case-insensitivity, so `uq_roles_tenant_name` is used as an index. Do **not** copy `JpaUserRoleRepository#findTenantsWithZeroActiveAssignmentsForRole`'s `UPPER(r.name) = UPPER(:roleName)` shape — that query is explicitly documented as a health-check-cadence, non-hot-path query, and the `UPPER()` wrapper makes the indexed column non-sargable. AC11 sits on a write hot path. Returns `Optional<UUID>` (the role id) — never the entity, per the "don't hand mutable `Role` instances to callers" constraint above. |
| **Q4** | *(inherited `findById`)* | Permission by id | AC4 (404 on unknown `permissionId`, §11 OQ5a) **and AC11** (the permission's *name*, to test dangerous-set membership) | PK lookup. **One read serves both** — and this fixes the check ordering: the permission must be loaded before the AC11 gate can run, so unknown-`permissionId` → 404 necessarily precedes AC11's 403. Record that ordering explicitly in `/design` §8 alongside §11 OQ4's tenant-before-system-role ordering. |
| **Q5** | *(inherited `findAll(Sort)`)* | All 7 seeded permissions | AC6 | 7-row table. Sort by `name` for determinism. |
| **Q7** | `JpaRolePermissionRepository` | Permissions attached to a role, as a **single projection join** `RolePermission → Permission` | AC3 | PK `(role_id, permission_id)` leftmost prefix gives the range scan; join to `permissions` by PK. **Must be one query** — the naive `findAll` + per-row `permissionRepository.findById` is the §7 N+1. Bounded at 7 rows today by `|permissions|`. |
| **Q8** | *(inherited `existsById`)* | Is this permission already attached? | AC4 / `RBAC_005` | PK probe. Keep it **and** the adapter-level constraint translation — the pre-check gives the clean 409 on the common path, the translation covers the concurrent-attach race (§11 edge case 10). This is exactly the dual pattern `hasActiveAssignment` + `JpaUserRoleAssignmentAdapter`'s catch already implement for `RBAC_004`. |
| **Q9** | `JpaRolePermissionRepository` | **Detach returning an affected-row count** | AC5 + §11 OQ5c | **F9 — `deleteById` returns `void`** and issues a SELECT-then-DELETE, so it cannot distinguish "was attached" from "was never attached", which is exactly the distinction Gate 1's 404-not-204 resolution requires. Needs `@Modifying @Query("DELETE FROM RolePermission …") int`, with the int count as the concurrency guard — the direct analog of `JpaUserRoleRepository#revokeById`'s documented "this int IS the concurrency guard" pattern (`RolePermission` has no `@Version` either, and the schema has no version column). |
| **Q10** | *(inherited `save`)* | Insert role / insert role-permission | AC1, AC4 | Ids from the existing `rbac.domain.IdGenerator` (`UuidV7IdGenerator`). `role_permissions` PK is client-supplied via `RolePermissionId`, `roles.id` via `IdGenerator`. `created_at`/`updated_at` are DB defaults (`insertable=false`). Round-trip already proven by `RbacRepositoryRoundTripIT`. |
| **Q11** | *(existing)* `UserRoleAssignmentPort#hasActiveAdminAssignment(userId, roleId, tenantId)` | AC11's locking admin check | **AC11** | **Reusable verbatim once Q3 supplies the roleId.** Backed by `JpaUserRoleRepository#lockActiveAdminAssignment` with `@Lock(PESSIMISTIC_READ)` → `FOR SHARE`. Drives off `ur.userId` → served by the implicit FK index on `user_roles.user_id`, so the lock set is *one user's* rows. **This is not US-012's F3 hazard** (that one drove off the unindexed `tenant_id`). Locking-read privilege under the column-scoped `UPDATE (revoked_at)` grant is already empirically settled — `UserRolesPrivilegeIT` executes a `… FOR UPDATE` as `nexus_app` (line ~141); `FOR SHARE` is no stricter. |

> **F1, restated as the design constraint:** AC11 is `Q3 → Q11`, in that order, inside the write transaction. `RoleAssignmentService.callerHoldsActiveTenantAdmin` (lines 298–303) looks like a ready-made helper, and it is **not**: its own Javadoc says it deliberately uses a **plain, non-locking** projection read because it only decides whether to redact one response field. Gate 1 requires AC11 to be a *fresh, locking* read. **Copying that helper satisfies the AC's letter and violates its point.** `/design` must state this in one sentence, and `/tasks` must carry a test that revokes the caller's admin assignment in a concurrent transaction.

### 1.3 Backend — `identity` bounded context

**MODIFIED:**

| Path | Change |
|---|---|
| `identity/domain/AuthEventType.java` | **+3 constants** — `ROLE_CREATED`, `ROLE_PERMISSION_GRANTED`, `ROLE_PERMISSION_REVOKED` (confirmed absent). `auth_events.event_type` is `VARCHAR(64)`, not a DB `ENUM`, so **no migration**; the longest new wire name is 25 chars. PRIORITY-lane recommendation below. |
| `identity/infrastructure/audit/RbacAuthEventAdapter.java` | **+3 method implementations** and a second `record(...)`/`buildMetadataJson(...)` overload keyed to the new carrier. See §1.4. |

**PRIORITY-lane recommendation — reasoned against the enum's own stated criterion, not by analogy.**

The comment block on `PRIORITY` states the admission test explicitly: *"Membership in the priority lane turns on **cost-and-uniqueness per row**, not mere triggerability by an authenticated caller"* — because the lane is capacity-200 with drop-newest overflow (ADR 0011 §1) and a depth-critical ≥180 pager, so a cheap-to-generate type lets a probing loop crowd out `LOCKOUT`/`TOKEN_REFRESH_REUSE`. That is precisely why `ROLE_ASSIGNMENT_DENIED` was excluded while `ROLE_ASSIGNED`/`ROLE_REVOKED` were admitted. Applying it:

- **`ROLE_PERMISSION_GRANTED` / `ROLE_PERMISSION_REVOKED` → admit to PRIORITY.** Cost per row is at least that of `ROLE_ASSIGNED`: a real mutation of `role_permissions`, past the AC7 system-role guard, the Q4 permission-existence read, the Q8 duplicate check, and — for the three dangerous permissions — a locking read (Q11). Uniqueness is bounded by `|permissions| = 7` per role. And the forensic value is *strictly greater* than a single `ROLE_ASSIGNED`: one row changes the effective privileges of every current **and future** holder of that role, which is the exact rationale §11 OQ2 gave for mandating AC12 at all. Losing one of these to a drop-newest overflow is a worse repudiation outcome than losing a `ROLE_ASSIGNED`.
- **`ROLE_CREATED` → do NOT admit; STANDARD lane.** It is the cheapest of the three: a single `INSERT` with no locking read, no existence check, and no privilege consequence — a freshly created role carries **zero permissions** and confers nothing until a separate, individually-audited grant. Its uniqueness is *caller-controlled and unbounded*: `name` is caller-supplied free text, so a `role:write` holder can loop with distinct names and mint unbounded distinct `ROLE_CREATED` rows at one cheap `INSERT` each — amplified by requirements R4 (this story is the one that removes the per-tenant role bound, and there is no pagination or ceiling). That is the `ROLE_ASSIGNMENT_DENIED` hazard profile, not the `ROLE_ASSIGNED` one.

**Consequence to record in `/design`:** the priority lane grows from 6 to 8 admitted types sharing the same capacity-200 buffer and the same depth-critical ≥180 pager. That is an operability change, not just an enum edit — call it out in §9 rather than letting it land silently. If `/design` disagrees with admitting the two grant/revoke types, the fallback (all three STANDARD) is defensible and must be justified against the same criterion, not against convenience.

**UNCHANGED (verified):** `AuthEventPort` (no signature change), `SecureEventService#recordEvent(AuthEvent)` (reused verbatim), `JpaAuthEventAdapter`, `AuthEventRetryBuffer`, `AuthEvent` (its `withUserId`/`withTenantId`/`withIpAddress`/`withUserAgent`/`withMetadata` builders are sufficient), `AuthEventDbPrivilegeHealthIndicator`, `JpaUserDirectoryAdapter`.

### 1.4 F2 in detail — the audit-carrier and port-extension decision

**Verified facts.** `RbacAuditEvent` is `(UUID tenantId, UUID targetUserId, UUID roleId, String roleName, UUID actorUserId, RequestContext requestContext)`. `RbacAuthEventAdapter#record(...)` sets `AuthEvent.withUserId(event.targetUserId())` and takes an `actorFieldName` parameter whose only three values are `"assignedBy"`, `"revokedBy"`, `"attemptedBy"`. `buildMetadataJson` emits, in order and omitting nulls: `traceId`, `roleId`, `roleName`, `reason`, `<actorFieldName>`. There is **no** permission field anywhere in the chain.

**Why reuse fails:**
1. `ROLE_PERMISSION_GRANTED`/`_REVOKED` must carry `permission_id` and `permission_name` (AC12's stated minimum). `RbacAuditEvent` has nowhere to put them. Smuggling `permissionId` through `roleId` or `permissionName` through `roleName` would corrupt the existing US-012/US-014 field semantics that `RoleAssignmentAuditIT` asserts on.
2. `ROLE_CREATED` has **no target user**. Passing `targetUserId = null` is *technically* survivable — `auth_events.user_id` has no FK (verified, `V2__identity_schema.sql`) and is nullable — but it makes the `AuthEvent.user_id` column mean "the subject" for five event types and "nothing" for a sixth, silently, with no compile-time signal. The `LOCKOUT`-style "user_id is the subject" convention the adapter documents would be quietly broken.

**Recommendation (for `/design` to ratify or reject with reasons):**
- **One new carrier record** in `rbac.application.port.out`, beside `RbacAuditEvent`: `RoleAuditEvent(tenantId, roleId, roleName, permissionId, permissionName, actorUserId, requestContext)` — no `targetUserId` field at all, so the "no subject user" fact is structural rather than a null convention. `permissionId`/`permissionName` null ⇒ role-creation event, which the existing omit-nulls metadata builder already handles correctly.
- **Three new methods on the existing `RbacAuditPort`**, not a sibling port: `recordRoleCreated(RoleAuditEvent)`, `recordRolePermissionGranted(RoleAuditEvent)`, `recordRolePermissionRevoked(RoleAuditEvent)`. The port is already named for "RBAC authorization changes" generally, already implemented by exactly one adapter in the correct context, and already ArchUnit-covered by `rbac_must_not_depend_on_identity`. A sibling port would duplicate the never-throw contract prose and add a second `@Component` for no boundary gain.
- **In the adapter:** map `AuthEvent.withUserId(null)` (i.e. simply do not call `withUserId`) and add `permissionId`/`permissionName` to the metadata map. Use `"createdBy"` / `"grantedBy"` / `"revokedBy"` as the `actorFieldName`, consistent with the existing naming.
- **Contract carry-over: yes, cleanly, with one amendment.** The "MUST NEVER throw and MUST NOT block" guarantee applies unchanged, and all three new call sites are post-commit successes routed through the `registerPostCommitSideEffects` pattern — the *easier* case. The existing `recordRoleAssignmentDenied` Javadoc's special pleading (inline, pre-throw, `REQUIRES_NEW` is the sole reason the row survives a doomed transaction) does **not** apply to any of the three. The `nexus.rbac.audit_write_failed{operation}` counter gains three new tag values.

**On the "denied attempt writes no success event" clause — this analysis reads it as literally "write nothing", and recommends *not* adding a parallel denied-event method in this story.** AC12's wording is a negative constraint on the success path, not a positive requirement for a denial event; the story's Test Scenario 14 asserts *absence* ("No success event written"), never presence of a denial row. `recordRoleAssignmentDenied` exists because **US-014 AC4** created it as a first-class requirement, and its own Javadoc scopes it deliberately narrowly ("Scoped to the two 403 authorization denials … never called for the 409 conflicts or the 404s, and never from a read path"). US-015 has no equivalent AC. Adding `recordRolePermissionDenied` speculatively would (a) exceed the AC, (b) create a fourth cheap-to-generate event type with an unresolved lane question, and (c) hand a `role:write` holder a probing loop that writes audit rows. **Concrete note for `/design`:** the correct, cheap substitute is already free — an AC11 denial throws `InsufficientPermissionException(role:write, NOT_TENANT_ADMIN)`, which inherits `GlobalExceptionHandler`'s WARN log **and** the `nexus.rbac.permission_denied{permission, reason}` counter, with the `permission` tag (`role:write`) distinguishing it from US-012's AC8 denial (`user:write`) on the same `reason`. That gives full alertability on self-escalation attempts with zero new code. If Security later wants a durable denial row, that is a clean follow-up story, not a Gate 2 improvisation.

> **Escaping discipline (T-T1/T-E13 class).** `permissionName` is code-seeded today, but it flows through the same `buildMetadataJson` → native `JSON` column path as the tenant-controlled `roleName` that US-015 itself makes writable. The adapter's Javadoc is unambiguous about the mechanism: escaping is Jackson's, via the **injected `tools.jackson.databind.ObjectMapper` (Jackson 3, the Spring-Boot-4-managed bean)** — never `com.fasterxml.jackson.databind.ObjectMapper`, never hand-instantiated. The new overload must reuse the same injected mapper and must be unit-tested with adversarial `roleName` values (quotes, control characters, `\u2028`). Do **not** hand-roll an escaper, and do not reach for `RequestContext#toMetadataJson` (it emits exactly `{traceId, ip, userAgent}`).

### 1.5 Backend — `interfaces.rest` conventions to follow

Verified against `UserRoleController` (the correct in-repo template — **not** `UserProfileController`):

- **Feature flag:** `@ConditionalOnProperty(name = "feature.nexus-us015-rbac-role-management.enabled", havingValue = "true")` on **both** new controllers. Absent the property, `havingValue="true"` means the bean is not registered — i.e. default-off is achieved by the annotation itself, and the `application.yml` entry is documentation plus an explicit kill-switch target.
- **Path/body UUIDs:** `String` `@PathVariable` / body field, validated against the `CANONICAL_UUID` pattern, then `UUID.fromString`. `parsePathUuid` currently lives **private** in `UserRoleController`. Two new controllers need it → `/design` must choose: duplicate it (3 copies), or extract it. **Recommend extracting to a package-private helper in `rbac.interfaces.rest`** — not to `common.web`, because `HexagonalArchitectureTest#rbac_must_not_depend_on_identity`'s own `because(...)` clause warns that a shared helper in a neutral `common.*` package is exactly the class of coupling ArchUnit cannot see. The reason this matters: a `UUID`-typed `@PathVariable` yields `MethodArgumentTypeMismatchException`, which `GlobalExceptionHandler` (a plain `@RestControllerAdvice`, not `ResponseEntityExceptionHandler`) does not handle → **500 instead of 400**.
- **Principal unwrapping:** `resolveActor(...)`-equivalent, in the **controller only**, producing a `RoleChangeActor`. Fail closed on a non-`String`/non-UUID principal (`MALFORMED_AUTHENTICATION`) and on an unparseable tenant (`MISSING_TENANT`). Same duplication question as above.
- **Annotations:** `@RestController`, `@RequestMapping("/api/v1/…")`, springdoc `@Tag`/`@Operation`/`@ApiResponse`, `@Valid @RequestBody`, `@ResponseStatus`. `POST` returns `ResponseEntity.created(locationUri)`.
- **Response envelope:** `{"data": [...]}` for all three list endpoints, matching `RoleAssignmentListResponse` (§5 assumption, now settled).

> **F5 — `@RequiresPermission` visibility trap, still mechanically unguarded (Medium).** `@RequiresPermission`'s Javadoc and `SECURITY.md` §3.1 both state that Spring AOP cannot proxy `final` or non-`public` methods, so the annotation is *silently never enforced* on such a handler — no error, no log, no failing test. **Verified: no ArchUnit rule anywhere catches this.** The suite is exactly two classes (`HexagonalArchitectureTest`, `LoggingStandardsTest`); neither inspects method visibility. US-012 mitigated this with a Javadoc warning and per-endpoint negative tests only. US-015 **triples** the annotated-handler count (2 → 8 across the context) and its handlers guard the platform's role-definition surface. **Recommendation for `/design`:** add one ArchUnit rule — `methods().that().areAnnotatedWith(RequiresPermission.class).should().bePublic()` plus a non-`final` companion. Near-zero cost, retroactively covers `UserRoleController`, and converts a convention into a build failure. **Not an ADR** — it encodes an already-accepted rule from `SECURITY.md`, it does not create one. Per-endpoint negative-control 403 tests remain mandatory regardless (§11.2).

### 1.6 Backend — `common` and `config`

**No changes required.** Verified line by line:

- `common.web.GlobalExceptionHandler` — `@ExceptionHandler(ConflictException.class)` → `409` using `e.code()` plus a `nexus.domain.conflict{code}` counter (lines 71–76); `@ExceptionHandler(ResourceNotFoundException.class)` → `404` using `e.code()` (65–69); `@ExceptionHandler(InsufficientPermissionException.class)` → `403 RBAC_001` + WARN + `nexus.rbac.permission_denied{permission, reason}` (159–176); `@ExceptionHandler(FieldValidationException.class)` and `MethodArgumentNotValidException` → `400` with `details[]`. **`RBAC_003`, `RBAC_005` and (recommended) `RBAC_006` all dispatch by base type → zero new handler code**, exactly as `RBAC_002`/`RBAC_004` did for US-012. Confirmed as requested.
- `config.SecurityConfig` — `.anyRequest().authenticated()`; the `permitAll` list contains only actuator/swagger/JWKS/`/api/v1/auth/*` paths. `/api/v1/roles/**` and `/api/v1/permissions` fall through to `authenticated()`. **No change.**
- `config.MethodSecurityConfig` — `AnnotationTemplateExpressionDefaults` already registered, so `@RequiresPermission`'s `{value}` substitution works. **No change.**
- `common.security.*` — `@RequiresPermission`, `TenantAwarePermissionEvaluator`, `AuthenticatedRequestDetails`, `AuthenticationDetailKeys`, `InsufficientPermissionException` all reused unchanged. **`DenialReason` needs no new constant** — AC11's denial reuses `NOT_TENANT_ADMIN`, which already exists and whose comment reads "US-012 AC8: caller lacks an active TENANT_ADMIN assignment". US-015's story text says "reuse, don't duplicate"; verified as correct.
- `common.domain.RequestContext` — reused as the audit-enrichment carrier, unchanged.

### 1.7 Configuration files

| Path | Change |
|---|---|
| `nexus-backend/src/main/resources/application.yml` (line ~205, `feature:` block) | **+`nexus-us015-rbac-role-management: enabled: false`.** Insertion point confirmed: the block currently holds `nexus-us002-auth-registration`, `nexus-us003-auth-login`, `nexus-us012-rbac-role-assignment`. Follow the `us012` entry's pattern exactly, including the inline comment explaining *why* it defaults off (here: AC11 is the platform's only control against the F3 escalation chain's mint side, so a config flip is the fastest kill switch). |
| `nexus-backend/src/main/resources/application-dev.yml` (line ~48) | +`enabled: true` |
| `nexus-backend/src/main/resources/application-test.yml` (line ~6) | +`enabled: true` — **mandatory, or every US-015 `*IT` gets a 404 from an unregistered bean**, which looks exactly like a routing bug. |

### 1.8 Frontend — **zero impact (explicitly verified, not assumed)**

- `docs/story/2-rbac/US-015.md` → Out of Scope: "The Epic 3 Tenant Admin UI itself".
- Grepped `nexus-frontend/src` for `/roles`, `/permissions`, `role:read`, `role:write`. **The only hits are in `src/app/core/http/api-error.interceptor.spec.ts` (lines 80–117)**, where `'/api/v1/roles'` is used purely as an arbitrary URL string for the interceptor's own unit tests. There is **no production call site** — no service, no component, no route, no guard.
- `core/http/api-error.interceptor.ts` maps RFC 7807 problem documents generically by `status`/`code`; there is no exhaustive error-code enum requiring `RBAC_003`/`RBAC_005`/`RBAC_006`.
- `shared/types/auth.ts`'s `roles: readonly string[]` is sourced from `/users/me` (`MeResponse`), which this story does not touch.

**Conclusion: no file under `nexus-frontend/` changes. No Vitest, no Playwright, no `package-lock.json` touch** — which also sidesteps the known npm-Windows `@emnapi` lockfile-prune trap entirely.

---

## 2. Database changes

### 2.1 Migration assumption — **CONFIRMED: no new migration**

Read `V5__rbac_schema.sql` in full. Existing migration set: `V1__baseline`, `V2__identity_schema`, `V3__add_password_hash_to_users`, `V4__auth_events_add_user_agent`, `V5__rbac_schema`.

| Table | US-015 needs | Already present in V5? |
|---|---|---|
| `roles` | `id`, `tenant_id`, `name`, `description` (NULL-able), `is_system_role` (BOOLEAN NOT NULL DEFAULT FALSE), `created_at`, `updated_at`; `uq_roles_tenant_name UNIQUE (tenant_id, name)` | **Yes, all** (V5:30–40) |
| `permissions` | `id`, `name`, `description` (NOT NULL), `created_at`; `uq_permissions_name` | **Yes** (V5:18–25) |
| `role_permissions` | `role_id`, `permission_id`, `created_at`; `pk_role_permissions PRIMARY KEY (role_id, permission_id)`; FKs to both parents | **Yes** (V5:45–52) |
| `auth_events` | `metadata JSON`, `event_type VARCHAR(64)` (not a DB `ENUM`) | **Yes** (V2:76–90) |

`description` on `roles` is `VARCHAR(255) NULL` while `permissions.description` is `NOT NULL` — confirming §11 OQ6's "description is optional" resolution against the actual DDL, not just the entity mapping.

**⇒ No new migration is required for table shape, column shape, constraint, trigger, or index.** ADR 0003's append-only rule is therefore not even engaged. If `/design` disagrees on any point, it must be a new `V6__*.sql` — never an edit to V5.

### 2.2 Index analysis — no new index required

| Query | Driving predicate | Index used | Verdict |
|---|---|---|---|
| Q1 `GET /roles` | `roles.tenant_id = ?` | `uq_roles_tenant_name` **leftmost prefix** | Index range scan over one tenant's roles. Sufficient. |
| Q3 AC11 admin-role lookup | `roles.tenant_id = ? AND roles.name = 'TENANT_ADMIN'` | `uq_roles_tenant_name` **full key** | Unique lookup, one row. Optimal — provided the predicate stays sargable (no `UPPER()`; §1.2 Q3). |
| Q2/Q4 `findById` | PK | `pk_roles` / `pk_permissions` | Optimal. |
| Q5 `GET /permissions` | none | full scan of 7 rows | Trivially fine. |
| Q7 role's permissions | `role_permissions.role_id = ?` | `pk_role_permissions` **leftmost prefix**, then PK join into `permissions` | Optimal. V5:53–57's own note confirms the reverse lookup (`permission_id`) is *also* indexed via the FK auto-index, though US-015 never needs it. |
| Q8/Q9/Q10 | full composite PK | `pk_role_permissions` | Optimal. |
| Q11 AC11 locking read | `user_roles.user_id = ?` (+ `role_id`, `tenant_id`, `revoked_at` residuals) | implicit FK auto-index on `user_id` | **Lock set is one user's handful of rows.** Materially unlike US-012's F3 hazard, which came from driving off the unindexed `user_roles.tenant_id`. Safe. |

`RbacSchemaMigrationIT#should_createExpectedIndexes_…` uses `contains(...)` (would survive an added index); `should_createExpectedColumns_…` uses `containsExactly(...)` (would break on an added column). Neither is triggered, since nothing is added.

### 2.3 Constraint semantics — one sharpening of AC9

`roles` is `COLLATE=utf8mb4_0900_ai_ci`. `uq_roles_tenant_name` therefore enforces uniqueness **case-insensitively *and* accent-insensitively** (`ai` = accent-insensitive). AC9 and `RbacRoleNames`' Javadoc both say "case-insensitive", which is true but narrower than reality: `Rôle` collides with `role` and `ROLE`.

**F10 (Low).** No behaviour change is needed — the DB constraint is the enforcement mechanism per §11 edge case 9, and it does the right thing. But `/design` should state the real semantics so that (a) `DuplicateRoleNameException`'s message doesn't promise something narrower, and (b) the AC9 test suite includes an accent case, otherwise the true contract is untested and a future collation change goes unnoticed.

Per §11 edge case 9 and 10, **both** uniqueness rules are enforced by *constraint-violation translation*, not check-then-insert: `uq_roles_tenant_name` → `DuplicateRoleNameException`, `pk_role_permissions` → `DuplicateRolePermissionException`. This is atomic under concurrency and matches ADR-0013 D2's rationale and `JpaUserRoleAssignmentAdapter`'s shipped precedent.

### 2.4 `nexus_app` grants — **CONFIRMED sufficient; no new grant**

Verified **identical** in all three provisioning artifacts — `nexus-database/mysql/init/02-grants-post-schema.sql:30-35`, `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java:156-165` (the `AFTER_MIGRATE` Flyway callback), and `docs/runbooks/nexus-app-provisioning.md`:

```
GRANT SELECT                 ON nexus.permissions      TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON nexus.roles            TO 'nexus_app'@'%';
GRANT SELECT, INSERT, DELETE ON nexus.role_permissions TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON nexus.user_roles       TO 'nexus_app'@'%';
GRANT UPDATE (revoked_at)    ON nexus.user_roles       TO 'nexus_app'@'%';
GRANT INSERT, SELECT         ON nexus.auth_events      TO 'nexus_app'@'%';
```

Endpoint-by-endpoint, statement-by-statement:

| Statement | Needs | Granted? |
|---|---|---|
| AC1 `INSERT INTO roles` | `INSERT` on `roles` | ✅ |
| AC2 `SELECT … FROM roles WHERE tenant_id = ?` | `SELECT` on `roles` | ✅ |
| AC3 `SELECT … role_permissions JOIN permissions` | `SELECT` on both | ✅ |
| AC4 `INSERT INTO role_permissions` | `INSERT` on `role_permissions` | ✅ |
| AC5 `DELETE FROM role_permissions` | `DELETE` on `role_permissions` | ✅ (this is the one intentionally-granted `DELETE` in the RBAC set — `role_permissions` has no soft-delete column and no `no_delete` trigger, unlike `user_roles`) |
| AC6 `SELECT … FROM permissions` | `SELECT` on `permissions` | ✅ |
| AC7 `is_system_role` read | `SELECT` on `roles` (same row already loaded) | ✅ — **no extra query** |
| **AC11** role-by-`(tenant,name)` lookup + permission-name lookup | `SELECT` on `roles`, `SELECT` on `permissions` | ✅ |
| **AC11** locking read `SELECT … FOR SHARE` on `user_roles` | `SELECT` + one of `DELETE`/`LOCK TABLES`/`UPDATE` | ✅ — satisfied by the column-scoped `UPDATE (revoked_at)`; **already empirically proven** by `UserRolesPrivilegeIT`, which executes a `… FOR UPDATE` as `nexus_app`. US-012's open R-4 is therefore closed, not inherited. |
| **AC12** `INSERT INTO auth_events` | `INSERT` on `auth_events` | ✅ |

**⇒ Zero grant changes. No update to `02-grants-post-schema.sql`, `TestcontainersConfiguration`, or the provisioning runbook.** Confirmed explicitly, as requested.

**Two grant-adjacent notes that are *not* blockers but must be recorded:**

> **F7 (Medium) — the absent `UPDATE` on `roles` is load-bearing, and untested.** The story's own AC7 note observes that `roles` has no `UPDATE` grant, so "editing the role itself" is not merely descoped but unexecutable. That is correct and is genuine defence-in-depth for AC7. The flip side: it means **any accidental Hibernate dirty-flush on a loaded `Role` fails in production only** — every `*IT` connects as the Testcontainers `test` user with full DML (this is exactly US-012's F1 class, arriving via `roles` instead of `user_roles`). Mitigation is cheap and belongs in `/tasks`: extend the `UserRolesPrivilegeIT` pattern with a `RolePermissionsPrivilegeIT` that connects as `nexus_app` and asserts (a) `INSERT INTO roles` succeeds, (b) `UPDATE roles SET name=…` is **denied**, (c) `INSERT`/`DELETE` on `role_permissions` succeed. That single test converts an invisible production-only failure mode into a build signal *and* proves AC7's DB-level backstop.

> **F7b (Medium) — privilege-drift detection has a blind spot this story creates.** `RbacDbPrivilegeHealthIndicator` inspects **only `user_roles`** (`USER_ROLES_TABLE` constant; three queries, all table-scoped to it). US-015 promotes `roles` and `role_permissions` from read-only-at-runtime to active write targets. A drifted `GRANT UPDATE ON nexus.roles` would silently re-permit role renames and `is_system_role` flips — a direct AC7 bypass below the application layer — and **no health check, metric, or test would notice**. Recommend `/design` either extend the indicator to cover `roles` (no `UPDATE`/`DELETE` expected) and `role_permissions` (no `UPDATE` expected), or explicitly accept and document the gap. The existing indicator's structure makes the extension mechanical.

### 2.5 Data migration

**None.** No existing row is reshaped, backfilled, re-interpreted, or re-keyed. No expand/contract phase is needed. All schema interaction is DML against an unchanged schema. The two seeded system roles are untouched by construction (AC7).

---

## 3. API changes

### 3.1 New endpoints (6) — all additive

Paths verified character-for-character against `EPIC-002.md`'s API table (lines 147–152) and `US-015.md` AC1–AC6.

| Method | Path | `@RequiresPermission` | Success | Controller | AC |
|---|---|---|---|---|---|
| `POST` | `/api/v1/roles` | `role:write` | `201` + `RoleResponse` + `Location` | `RoleController` | AC1, AC9, AC12 |
| `GET` | `/api/v1/roles` | `role:read` | `200` + `{"data":[RoleResponse]}` | `RoleController` | AC2 |
| `GET` | `/api/v1/roles/{roleId}/permissions` | `role:read` | `200` + `{"data":[PermissionResponse]}` | `RoleController` | AC3, AC8 |
| `POST` | `/api/v1/roles/{roleId}/permissions` | `role:write` | `201` + `Location` | `RoleController` | AC4, AC7, AC8, **AC11**, AC12 |
| `DELETE` | `/api/v1/roles/{roleId}/permissions/{permissionId}` | `role:write` | `204` no body | `RoleController` | AC5, AC7, AC8, AC12 |
| `GET` | `/api/v1/permissions` | `role:read` | `200` + `{"data":[PermissionResponse]}` | `PermissionController` | AC6 |

**No versioning strategy change** — `/api/v1` is new surface, not a modification of existing surface. Both new roots are covered by `SecurityConfig`'s `.anyRequest().authenticated()` with no config edit (§1.6).

Two contract facts this analysis fixes (both by direct analogy to US-012 FR2, which is cited by US-015 FR2):
- The role's `tenant_id` comes **exclusively** from the caller's authenticated tenant. `CreateRoleRequest` must **not** model a tenant field — enforce by omission, not by validation.
- `is_system_role` is **always** `FALSE` on creation (AC1). `CreateRoleRequest` must not model it either; a client-settable `isSystemRole` would let a caller mint an AC7-immune role.

**Empty-collection semantics (settled from §5, now verified against precedent):** `GET /roles/{roleId}/permissions` on a role with zero attachments returns `200 {"data": []}`, not `404` — the role's existence is already resolved by Q2, and the `{"data": …}` envelope makes the empty case unambiguous.

### 3.2 Error contract — **zero new handler code**

| Condition | Status | Code | Mechanism | Verdict |
|---|---|---|---|---|
| Missing `role:read`/`role:write` | 403 | `RBAC_001` | `@RequiresPermission` → `InsufficientPermissionException` → existing handler (WARN + `nexus.rbac.permission_denied`) | Existing |
| Target role in another tenant (AC3, AC8 — all three role-scoped verbs) | 403 | `RBAC_001` | `InsufficientPermissionException(perm, CROSS_TENANT_TARGET)` from the service, mirroring `resolveRoleInTenant` | Existing |
| **AC11**: caller lacks an active `TENANT_ADMIN` assignment while attaching a dangerous permission | 403 | `RBAC_001` | `InsufficientPermissionException("role:write", NOT_TENANT_ADMIN)` — **reuses the existing `DenialReason`**; the `permission` tag (`role:write`) distinguishes it from US-012 AC8 (`user:write`) on the same metric | Existing |
| Role id not found anywhere | 404 | `ROLE_NOT_FOUND` | `ResourceNotFoundException` → existing `handleNotFound`. Same code string as `RoleAssignmentService`, for cross-story consistency | Existing |
| `permissionId` not found (§11 OQ5a) | 404 | `PERMISSION_NOT_FOUND` *(new code string, existing handler)* | `ResourceNotFoundException`. No cross-tenant dimension — `permissions` has no `tenant_id` column (verified V5:18–25) | Existing |
| `DELETE` on a never-attached / already-detached pairing (§11 OQ5c) | 404 | `ROLE_PERMISSION_NOT_FOUND` | `ResourceNotFoundException`, driven by Q9's affected-row count. **Explicitly not an idempotent `204`** | Existing |
| **AC7** write against `is_system_role = TRUE` | 409 | **`RBAC_003`** | New `SystemRoleImmutableException extends ConflictException` → existing `handleConflict` + `nexus.domain.conflict{code="RBAC_003"}` | **Zero new handler code** |
| Duplicate role-permission attachment (§11 OQ5b) | 409 | **`RBAC_005`** | New `DuplicateRolePermissionException extends ConflictException` → same existing handler | **Zero new handler code** |
| **AC9** duplicate role name in tenant | 409 | **unassigned — F4** | New `DuplicateRoleNameException extends ConflictException` → same existing handler. **Recommend `RBAC_006`** | **Zero new handler code**, once the code is assigned |
| Malformed/missing `name`, or missing `permissionId` | 400 | `VALIDATION_FAILED` | Existing `handleBodyValidation` via `@Valid` + `@NotBlank`/`@NotNull`/`@Size` | Existing |
| Malformed `{roleId}`/`{permissionId}` path or body UUID | 400 | `VALIDATION_FAILED` + `details[].field` | `FieldValidationException` via the `parsePathUuid` pattern → existing `handleFieldValidation`. **Never a `UUID`-typed binding**, which would 500 | Existing |

**Confirmed as requested: `RBAC_003` and `RBAC_005` both route through the existing generic `ConflictException` → 409 handler with zero new handler code, exactly as `RBAC_002`/`RBAC_004` did for US-012.** Both codes are verified unused anywhere in `src/main`.

> **F4 (Medium) — one error code is missing from the Gate 1 register.** §11 states: *"New error code registered by this story: `RBAC_003` … and `RBAC_005` …"*. But **AC9's 409 (duplicate role name in tenant) has no code assigned** — it is not `RBAC_003` (system-role-immutable), not `RBAC_005` (duplicate role-permission), and not `RBAC_004` (US-012's duplicate *user-role* assignment; reusing it would be a semantic collision that breaks any consumer switching on `code`). Verified: `RBAC_006` appears nowhere in `src/main` or `docs/`. This is a contract hole, not a Gate 1 re-litigation — the *behaviour* (409) is settled; only the machine-readable identifier is unassigned. **`/design` must assign it (recommend `RBAC_006`) before writing the §5 API contracts**, or AC9 ships with an inconsistent or duplicated code.

**Check ordering (must be pinned in `/design` §8, three constraints, two from Gate 1 and one derived):**
1. Tenant-ownership resolution (404 / 403) **first**, always — §11 OQ4, mirroring `RoleAssignmentService.assign()`'s `resolveRoleInTenant`-before-AC8 ordering, and avoiding leaking system-role status of an inaccessible role.
2. AC7 `is_system_role` (409 `RBAC_003`) **after** tenant resolution.
3. **Derived (new):** `permissionId` existence (404) **before** AC11's admin gate (403) — unavoidable, because AC11's dangerous-set test needs the permission's *name*, which requires the row. Worth stating so it isn't "fixed" later into an information-leak-motivated reorder; leaking "this permission id exists" is not a leak, since `GET /api/v1/permissions` publishes all 7 to every `role:read` holder.

### 3.3 Breaking changes

**None. Purely additive.**
- No existing endpoint's path, method, request shape, or response shape changes.
- `MeResponse` and the `JwtClaims` contract are untouched → **no `token_version` bump**, no `JwtClaimsContractTest` change.
- `AuthEventType` gains 3 constants; every existing wire name is unchanged; `auth_events.event_type` is `VARCHAR(64)` so existing rows and any downstream query are unaffected.
- `RbacAuditPort` **gains** 3 methods. Its only implementation (`RbacAuthEventAdapter`) is updated in the same change; there is no external implementor. Interface-widening is source-compatible here because Java requires the single implementor to be updated together — and it is in the same module.
- `UserRoleAssignmentPort`, `UserRoleQueryPort`, `PermissionCachePort`, `UserDirectoryPort`, `AuthEventPort`, `SecureEventService` all keep their exact current signatures.
- No frontend contract touched (§1.8).

---

## 4. UI changes

**None.** See §1.8 for the verification, which was performed by grep rather than assumed. Downstream consumers — the Epic 3 Tenant Admin UI, per the epic's own release-readiness bar ("at least one Epic 3 admin surface built on this API with no contract changes required") — inherit this contract but require no work in this story.

Two forward notes for the eventual UI, worth one line in `/design` so the API doesn't have to change later:
- Returning `isSystemRole` on `RoleResponse` lets the UI disable the AC7-protected roles client-side instead of discovering immutability through a 409.
- `GET /roles` is unbounded and unpaginated (Gap 3 / R4). If `/design` wants to keep the door open, the `{"data": …}` envelope already permits adding a sibling `page` object later without breaking clients — which is the strongest practical argument for keeping the envelope on all three list endpoints.

---

## 5. Cross-context, dependency direction, and ArchUnit conformance

### 5.1 Edge direction — unchanged and still acyclic

- `identity → rbac`: exists (`JwtRs256Service` → `RoleResolutionService`); `RbacAuthEventAdapter` → `rbac.application.port.out.*`. US-015 *reinforces* this edge (the adapter now implements 6 port methods instead of 3) without adding a new one.
- `rbac → identity`: **zero imports**, and must stay zero. `RoleManagementService` depends only on its own `RoleManagementPort` + the extended `RbacAuditPort` + `UserRoleAssignmentPort` (all in `rbac.application.port.out`). AC12's audit durability arrives entirely through the port.

**No new cross-context edge, no cycle.**

### 5.2 ArchUnit conformance — rule by rule against the verified suite

The suite is exactly two classes: `architecture/HexagonalArchitectureTest.java` and `architecture/LoggingStandardsTest.java`.

| Rule | US-015 verdict |
|---|---|
| `domain_must_not_depend_on_outer_layers` | ✅ The 3 new exceptions depend only on `common.domain.ConflictException`; `RbacDangerousPermissions` and `RolePermissionView` depend on nothing. |
| `application_must_not_depend_on_adapters` | ✅ `RoleManagementService` depends on `..port.out..` interfaces only. |
| `domain_must_not_use_spring_web` | ✅ |
| `domain_and_application_must_not_depend_on_redis` | ✅ — trivially, since AC10/ADR-0013 D4 means **no cache call at all**. |
| **`domain_and_application_must_not_depend_on_spring_security`** | ⚠️ **Constrains the design, same as US-012.** `RoleManagementService` must not accept an `Authentication` and must not call `AuthenticatedRequestDetails.fromAuthentication(Authentication, String)` — the parameter type alone is a direct dependency on `org.springframework.security.core.Authentication`. The controllers unwrap into `RoleChangeActor` and pass plain `UUID`/`String`/`RequestContext`. *Throwing* `InsufficientPermissionException` from the service is fine (ArchUnit records the direct reference, not the supertype). Validate by running `./mvnw verify -DskipITs` immediately after the first service skeleton lands, not by reasoning. |
| **`rbac_application_methods_must_not_accept_principal_or_map`** | ⚠️ **New relevance.** This rule (added by US-012 for T-E10) bans `java.security.Principal` and `java.util.Map` as parameter types on **any** method in `..rbac.application..`. Two US-015-specific traps: (a) a convenience `Map<String,Object>` audit-payload parameter — precisely why F2's typed carrier record is the right answer; (b) `RbacDangerousPermissions` must be modelled as a `Set`/`List`, never a `Map`. A `Set<String>` parameter is fine. |
| **`rbac_must_not_depend_on_identity`** | ✅ — provided AC12 goes through the port. Note the rule's own `because(...)` caveat: it cannot catch a shared helper placed in a neutral `common.*` package. Relevant to the `parsePathUuid`/`resolveActor` extraction question (§1.5) — extract within `rbac.interfaces.rest`, not into `common.web`. |
| `only_jwtAuthenticationFilter_sets_authentication_details` | ✅ US-015 never calls `setDetails`. |
| `no_field_injection` / `no_standard_streams` / `no_java_util_logging` | ✅ Constructor injection + SLF4J throughout. |
| `LoggingStandardsTest` | ✅ Structured `log.atInfo().addKeyValue(...)` per the `RoleAssignmentService` precedent. |

**No ArchUnit rule is *tripped* by any new port, adapter, entity use, or controller.** Two rules *constrain* the design and are called out above.

**Recommended addition (not an ADR — encodes an existing `SECURITY.md` §3.1 rule):** the `@RequiresPermission`-must-be-public rule from F5/§1.5. It is the only gap in the suite that can cause a *silently unguarded privileged endpoint*, and US-015 is the story that most increases that exposure.

### 5.3 Tenant-ID type boundary

Unchanged from US-012 and equally load-bearing: `AuthenticatedRequestDetails.tenantId()` is a **`String`**, documented as opaque ("no trimming, case-folding, or comparison"); `Role.tenantId` is a **`UUID`**. The controllers must `UUID.fromString(...)` and **fail closed** — `InsufficientPermissionException(perm, MISSING_TENANT)`, never an unhandled 500 via `handleUnexpected`. Provenance is safe in practice (`JwtRs256Service` mints from `User.getTenantId().toString()`, canonical lowercase), but the parse must remain defensive, matching `UserRoleController.resolveActor`'s shipped shape exactly.

---

## 6. Security impact

**New attack surface:** six authenticated endpoints, of which three are writes against the platform's *role definitions* — a strictly more privileged surface than US-012's, which only wrote *assignments* of pre-existing roles. This story is the sole control for the epic's T-E5 note ("`is_system_role` is inert until this story's AC7 ships") and the mint-side half of T-E1.

| Concern | Analysis |
|---|---|
| **Authn** | Unchanged. `SecurityConfig.anyRequest().authenticated()` already covers both new roots; `JwtAuthenticationFilter` untouched. |
| **Authz — coarse** | `@RequiresPermission("role:read"/"role:write")`. **`TenantAwarePermissionEvaluator` performs no tenant or resource comparison** — it checks flat JWT `permissions[]` membership only. AC7, AC8, AC9 and AC11 are therefore **entirely** service-layer logic, in `RoleManagementService` and nowhere else. Restated because it is the single most load-bearing fact in the design. |
| **Authz — tenant isolation (AC8)** | Uniform across `GET`/`POST`/`DELETE` on `/roles/{roleId}/permissions`; `GET /roles` satisfies it by result-filtering (FR3), not a 403/404 branch. Caller tenant sourced **exclusively** from the JWT; target tenant read **fresh from the DB** (`Role.tenantId`), never from request input. |
| **Authz — AC7 system-role immutability** | `role.isSystemRole()` is a plain boolean on the already-loaded row — **no name matching, no extra query, no casing hazard** (materially safer than AC8's `TENANT_ADMIN` name match). Single shared guard in the service, not per-controller (story R9's own mitigation). Backed at the DB level by the absent `UPDATE` grant on `roles`, though note that grant does **not** protect `role_permissions`, which has `INSERT`/`DELETE` — so for the two write endpoints AC7 is a **pure application-layer control** with no DB backstop. That is exactly why F5 (silently unenforced `@RequiresPermission`) and the per-endpoint negative tests matter here more than in US-012. |
| **Authz — AC11 dangerous-permission gating** | **The story's most security-critical control.** Must be `Q3 → Q11`: resolve the tenant's `TENANT_ADMIN` role by `(tenant_id, name)`, then a **fresh locking** (`PESSIMISTIC_READ` / `FOR SHARE`) read on the caller's own active assignment. **Never** the JWT `roles[]`/`permissions[]` claim (up to ~15 min stale — a caller whose admin assignment was revoked out-of-band still carries it), and **never** the non-locking `callerHoldsActiveTenantAdmin` shortcut (F1). Denial → 403 `RBAC_001` + `NOT_TENANT_ADMIN`. |
| **Residual escalation — F3 (High)** | AC11 closes the **mint** side: a non-admin `role:write` holder cannot build a dangerous role. It does **not** close the **propagate** side. `RoleAssignmentService.assign()`'s AC8 guard still matches the role *name* (line 107), so once a legitimate `TENANT_ADMIN` attaches `user:write` to `CustomRole` — which AC11 explicitly permits, and which §11's rationale says Epic 3 *needs* — **any** `user:write` holder can grant `CustomRole` to anyone, including themselves (nothing restricts `targetUserId == actor.userId()`), with AC8 never firing. `revoke()`'s T-E9 Javadoc documents the symmetric hole: there is no "only an active `TENANT_ADMIN` may revoke `TENANT_ADMIN`" check at all. **Unreachable today** (only `TENANT_ADMIN` carries `user:write`), reachable the first time US-015 is used as intended. **In scope to record, not to fix.** The cheap future fix is one query — "does role X grant any of the 3 dangerous permissions?", a near-clone of Q7 — feeding the same `hasActiveAdminAssignment` gate in `assign()`/`revoke()`. `/design` must (a) amend `RoleAssignmentService`'s M-3 Javadoc from "a custom-roles story must close this" to "US-015 AC11 closed the attach path; the assign/revoke paths remain open, tracked as X", and (b) add this to `03b-threat-model.md` as an explicit accepted-risk-with-owner, not delete the note as discharged. |
| **IDOR** | `{roleId}`, `{permissionId}` are client-supplied. `{roleId}` is mitigated by AC8's tenant check on all three verbs. `{permissionId}` needs no tenant check — `permissions` is global and fully published by AC6. |
| **Privilege-surface widening via `POST /roles`** | A caller with `role:write` but no active admin assignment can still *create* unlimited empty roles (AC1 has no AC11-style gate, correctly — an empty role confers nothing). The consequences are availability/noise (R4, unbounded growth; F3 on the audit lane), not escalation. Worth one threat-model line. |
| **Audit integrity (T-R1/T-S2)** | Actor is `actor.userId()`, sourced from `authentication.getPrincipal()` only — never from the path or body. `auth_events` is append-only at both the trigger and the privilege level (`GRANT INSERT, SELECT`); the 3 new event types inherit both protections with no new mechanism. |
| **JSON injection into `auth_events.metadata` (T-T1/T-E13)** | **Vector widens.** `roleName` becomes genuinely tenant-controlled free text *for the first time* in this story (US-012 could only echo seeded names), and `permissionName` joins it on the same path. Escaping is Jackson-3-via-the-injected-`ObjectMapper`, per `RbacAuthEventAdapter`'s explicit contract. Mandatory adversarial unit test. |
| **Anti-enumeration** | Not applicable in the `/forgot`-class timing-equalisation sense — these are authenticated admin endpoints. The 403-vs-404 split does distinguish "role exists in another tenant" from "no such role", a deliberate §11 OQ4 trade accepted for consistency with US-012; `roles.id` is a UUIDv7 with no useful guessability. One threat-model line, not a change. |
| **Rate limiting** | No requirement stated (consistent with the epic). No cross-cutting limiter exists beyond `LoginRateLimitFilter`. Accepted gap — but note R4 + F3's `ROLE_CREATED` spam interact: an unthrottled `POST /roles` loop is the cheapest way to generate audit rows in this story. This is the concrete reason `ROLE_CREATED` should stay out of the priority lane (§1.3). |

**Threat-model refresh required at Gate 2** (`03b-threat-model.md`): F3's residual propagate-side escalation (with owner and accepted-risk status), the F1 non-locking-read trap, the widened `roleName` JSON-injection vector, AC7's lack of a DB backstop on `role_permissions`, the F7b privilege-drift blind spot on `roles`/`role_permissions`, and the AC10 staleness sharpening in F6.

---

## 7. Performance impact

| Path | Analysis |
|---|---|
| **`POST /roles`** (AC1) | Zero reads (no pre-check — uniqueness is the constraint). 1 `INSERT` + one unique-index probe. Cheapest endpoint in the story. Comfortably inside the epic's generic 200 RPS / p95 < 300 ms figure. |
| **`GET /roles`** (AC2) | 1 index range scan on `uq_roles_tenant_name`'s `tenant_id` prefix. **Unbounded result set** — Gap 3 / R4, and *this story is the mechanism that removes the previous ≤2-roles-per-tenant bound*. Not a today problem; is a contract problem. `/design` must either document the unbounded contract explicitly or add pagination. Recommend documenting now + the `{"data":…}` envelope's forward-compatibility (§4) rather than building unrequested pagination. |
| **`GET /roles/{id}/permissions`** (AC3) | Q2 (PK) + Q7 (1 projection join). **N+1 risk (Medium):** the naive implementation loops `role_permissions` rows calling `permissionRepository.findById` per row. Must be a single JPQL projection join, exactly like the shipped `findActiveAssignmentViews`. Result set is bounded at `|permissions| = 7` — so unlike `GET /roles`, this one has a real ceiling and needs no pagination discussion. |
| **`POST /roles/{id}/permissions`** (AC4) | Reads: Q2 (PK), Q4 (PK), Q8 (PK probe), plus — **only when the permission is one of the 3 dangerous ones** — Q3 (unique index) + Q11 (locking read on `user_roles`, one user's rows). Write: 1 `INSERT`. Worst case ~5 index lookups + 1 insert. **Q11 is the only lock in the story**, and its scope is one user's assignment rows — not US-012's platform-wide F3 hazard. |
| **`DELETE /roles/{id}/permissions/{permId}`** (AC5) | Q2 (PK) + Q9 (PK-targeted `DELETE` returning a count). No lock, no AC11 gate (revoking a dangerous permission *reduces* privilege). Cheapest write. |
| **`GET /permissions`** (AC6) | Full scan of a 7-row table. A caching candidate on paper; **do not cache it.** Nexus has Redis wired, but adding a cache here would need an invalidation story for a table that is migration-only-writable, to save a 7-row scan. Boring tech wins. |
| **Cache touches** | **None.** AC10 + ADR-0013 D4 ratify option (b) — no bulk fan-out invalidation. `PermissionCachePort` is not a collaborator. |
| **Audit write** | One extra `INSERT` into `auth_events` per successful write, in a `REQUIRES_NEW` transaction — a second DB round-trip and a **second pooled connection held concurrently** with the first. Pre-existing, benchmarked cost (`AuthEventLoadIT`/`AuthEventLoadSmokeIT`). Note this now overlaps Q11's `FOR SHARE` lock window on the dangerous-permission path, the same connection-pool + lock interaction US-012's §7 flagged; the window here is shorter (a PK-scoped share lock, not a range write lock). |
| **AC11 marginal cost** | Two extra index lookups on ≤3 of 7 possible permission values. Negligible. There is **no** justification for caching the tenant's admin role id to avoid Q3 — that cache would reintroduce exactly the staleness AC11 exists to defeat. |

> **F6 (Medium) — AC10's staleness window is worse than the story text implies, and the story's own Test Scenario 8 will not detect it.** AC10 says users "see the change reflected within the existing cache TTL / token refresh window". Verified against `PermissionCachePort`'s Javadoc: `RoleResolutionService` uses the cached **role set** as a freshness fingerprint — role *names* are re-read live at login/refresh, and a cache hit whose `roles` no longer match is treated as stale and recomputed. **A role-permission edit does not change any role name.** So the fingerprint matches, the cache hit is treated as fresh, and the stale *permission* set is served for the full 15-minute TTL **even on an explicit token refresh** — the very mechanism that saved US-012 from needing cache eviction for correctness does not help here. This is not a defect (D4 accepted the lag) and not a Gate 1 reopening (the decision stands), but the *documented window* is wrong: it is "up to the cache TTL, and a token refresh does not shorten it", not "cache TTL or next refresh". `/design` must state the accurate window, and the security runbook + Test Scenario 8 must assert it accurately — otherwise an operator responding to an incident will refresh a token expecting a fix that does not come.

---

## 8. Integration impact

| Integration | Impact |
|---|---|
| **MySQL** | DML only, on existing unchanged tables. No schema change, no grant change. See §2.4's F7/F7b usage constraints. |
| **Redis** | **Untouched.** No `evict`, no `get`, no `put`. Wired and available, deliberately not used (ADR-0013 D4). `/design` should say this in one sentence so a reviewer does not read the absence as an oversight. **No new Redis dependency is proposed.** |
| **Audit pipeline (US-008/US-014)** | Reused end-to-end and structurally unchanged: `RbacAuditPort` → `RbacAuthEventAdapter` → `SecureEventService` (`REQUIRES_NEW`) → `AuthEventPort` → `JpaAuthEventAdapter` → `AuthEventRetryBuffer`. **One real change: 2 of the 3 new types are recommended into the capacity-200 drop-newest PRIORITY lane** (§1.3), raising admitted priority types from 6 to 8 and sharing the depth-critical ≥180 pager. That is an operability change to record, not just an enum edit. |
| **JWT / token issuance (US-010)** | Unaffected in contract. Affected in *effect*: see F6 — a permission-set change is not visible to `RoleResolutionService`'s role-set fingerprint. |
| **US-012 `RoleAssignmentService`** | No source change. But see **F3**: its M-3 Javadoc's forward-tracking is only partly discharged and must be amended, not deleted. |
| **US-013** | Sprint-5 sibling. No shared surface identified; both are `rbac`-context stories, so watch for merge contention in `application.yml`'s `feature:` block and `AuthEventType`. |
| **US-014** | Its audit pipeline is reused. Its `ROLE_ASSIGNMENT_DENIED` design decision 5 (cost-and-uniqueness lane criterion) is the reasoning framework applied in §1.3 — and its `AuthEventTypeTest` hard-coded counts are broken by this story (§11.2). |
| **Epic 3** | This API is the future Tenant Admin UI's backend. Explicitly **non-gating** for Epic 3 kickoff (US-009 + US-012 only), but the contract should be treated as stable at ship, per the epic's release-readiness bar. Epic 3 also inherits F3 unless it is fixed first. |
| **Epic-3 per-tenant seeding** | Requirements Gap 9: per-tenant system-role seeding is bootstrap-tenant-only today (ADR-0014 D5 / ADR-0015 D8). **Direct consequence for AC11:** in any tenant with no seeded `TENANT_ADMIN` role, Q3 returns empty and AC11 must **fail closed** (403), never fall through to "allow". `/design` must specify that branch explicitly — it is the difference between a safe default and a silent bypass for every tenant Epic 3 creates. |
| **Upstream/downstream services** | None. Nexus is a modular monolith; no external service boundary is crossed. |

---

## 9. Observability impact

Not a formal Phase 2 deliverable, but the gaps must be recorded so `/design` §9 can close them (requirements §3 "Observability" and Gap 5).

**Free, no new instrumentation:**
- `RBAC_003` / `RBAC_005` / `RBAC_006` all route through `handleConflict` → `nexus.domain.conflict{code}` counter. Trend lines for free. Confirms the requirements doc's positive-precedent claim.
- AC11 denials → `handleInsufficientPermission` → WARN log **plus** `nexus.rbac.permission_denied{permission="role:write", reason="NOT_TENANT_ADMIN"}`. **The story's most security-critical control is fully alertable with zero new metric plumbing**, and the `permission` tag separates it from US-012 AC8's `user:write` denials on the same `reason`. `/design` should name this as the AC11 alert.
- `traceId`/`correlationId` propagation via `CorrelationIdFilter` + MDC, landing in `auth_events.metadata.traceId`.
- `nexus.rbac.audit_write_failed{operation}` gains 3 tag values (`createRole`, `grantPermission`, `revokePermission`) with the existing ERROR + `RBAC_AUDIT_WRITE_LOST` log marker.

**Gaps `/design` must close:**
1. **AC7 attempts are invisible at production log levels.** `handleConflict` logs at **DEBUG** and emits no dedicated signal. A burst of `RBAC_003` is a plausible probing signature (someone testing whether system roles are really immutable). `RoleAssignmentService` already sets the precedent for the fix: a service-level `log.atWarn().addKeyValue("event", "RBAC_SYSTEM_ROLE_MUTATION_BLOCKED")…`, mirroring `RBAC_LAST_ADMIN_REVOCATION_BLOCKED`. Recommended. Requirements §3 flagged this as unaddressed; this is the concrete close.
2. **Three new INFO structured log events** on the success paths — `ROLE_CREATED`, `ROLE_PERMISSION_GRANTED`, `ROLE_PERMISSION_REVOKED` — emitted from the post-commit block alongside the audit call, with `tenantId`/`roleId`/`roleName`/`permissionId`/`actorUserId`. `RoleAssignmentService`'s own comment gives the rationale verbatim: "Operator-visible confirmation independent of the audit table's own availability", since the audit write is best-effort. Without these, an audit-pipeline outage means a role-permission change leaves *no* durable trace.
3. **Priority-lane depth.** Admitting 2 new types raises pressure on the capacity-200 buffer that drives the depth-critical ≥180 pager. Recommend `/design` state the expected event rate for grant/revoke (very low — admin-initiated configuration changes) as the justification, and confirm the existing lane-depth dashboard/alert needs no threshold change.
4. **AC9/AC5 404-vs-409 distinction** is already visible via the `code` tag on `nexus.domain.conflict` and the `errorCode` log field — no work needed, worth one line so it isn't re-litigated.
5. **F6's corrected staleness window** belongs in the security runbook, not just the design doc — it is the fact an operator needs during an incident.

---

## 10. Dependency changes

**None.** No new libraries, no version bumps, no license review, no `pom.xml` change.

Everything required is already on the classpath: Spring Data JPA (incl. `@Lock`, `@Modifying`, `@Query`), Spring Security (`@PreAuthorize` machinery + `AnnotationTemplateExpressionDefaults`), springdoc (`@Tag`/`@Operation`/`@ApiResponse`), Jakarta Bean Validation, Jackson 3 (`tools.jackson.databind`), Micrometer, Lombok, ArchUnit, Testcontainers (MySQL 8.4 + Redis 7.4), AssertJ, Mockito, JUnit 5.

**Explicitly not proposed:** Redis for `GET /permissions` (§7), any caching library, any policy-engine library for AC11's 3-element dangerous set. A `Set.of(...)` in a domain constants class is the right size of solution.

---

## 11. Test impact

### 11.1 Existing infrastructure to reuse

There is **no shared `*IT` base class**; the codebase uses a *copied configuration convention*. Both established shapes apply, and — unlike US-012, which was inventing them — US-015 has direct in-package templates for every test it needs.

| Need | Reuse this template |
|---|---|
| Persistence/DB-level IT | `rbac/RbacRepositoryRoundTripIT` — **already round-trips `Role` and `RolePermission` saves and a `RolePermissionId` composite-key `findById`** (lines 85–121), proving the entity mappings US-015 depends on. Also `rbac/RoleUniquenessIT` for `uq_roles_tenant_name`. |
| End-to-end HTTP + security IT | `rbac/security/RoleAssignmentSecurityIT` and `rbac/security/CrossTenantPermissionIT` — the latter already seeds a user in the bootstrap tenant plus a custom role in a *second* tenant, which is exactly the AC8 fixture shape. |
| Audit IT | `rbac/RoleAssignmentAuditIT` — asserts `auth_events` rows and metadata for `ROLE_ASSIGNED`/`ROLE_REVOKED`. Direct template for AC12's Scenarios 11–14. |
| **`nexus_app` privilege IT** | `rbac/UserRolesPrivilegeIT` — connects as `nexus_app` on a separate JDBC connection (credentials `nexus_app` / `nexus_app_test_only`), and already executes a `… FOR UPDATE` and a `SHOW GRANTS`. **The template for F7's mandatory `RolePermissionsPrivilegeIT`.** |
| Controller slice | `rbac/interfaces/rest/UserRoleControllerTest` (MockMvc); plus `common/security/RequiresPermissionWebTest`, `config/SecurityConfigWebTest`. |
| Service unit test | `rbac/application/RoleAssignmentServiceTest` (Mockito, all ACs + error branches). |
| Concurrency harness | `rbac/ActiveAssignmentIT#should_allowExactlyOneWinner…` and `RefreshTokenRotationIT#concurrent_rotation_single_winner` (8-thread `ExecutorService` + `CyclicBarrier`, 5 s barrier / 15 s termination). The pattern for AC9's and AC4's concurrent-duplicate tests. Note `ActiveAssignmentIT`'s own Javadoc warning that `SecureEventServiceConcurrencyTest` is *not* a real concurrency harness. |
| Container/config | `TestcontainersConfiguration` — MySQL 8.4 + Redis 7.4, Flyway pinned on, `ddl-auto=validate`, `nexus_app` grants via an `AFTER_MIGRATE` Flyway callback, stub `MailSenderPort`. |
| `@RequiresPermission` harness | `support/web/GuardedTestController` + `GuardedTestControllerConfig`. |

**Two shared-fixture caveats, both verified and both specific to this story:**
- **Shared context, shared schema.** All `*IT` using the identical `@SpringBootTest` + `@Import(TestcontainersConfiguration.class)` combination share one cached Spring context and therefore one MySQL schema for the whole run. `RbacSchemaMigrationIT`'s Javadoc (lines 21–30) documents this and states its counter-measure: its `roles` count is scoped to `is_system_role = TRUE` and its `role_permissions` count to the two known seeded role ids. **US-015 fixtures are therefore safe if and only if every fixture role is created with `is_system_role = false` and every fixture `role_permissions` row hangs off a fixture role.** An AC7 test that *attempts* to attach a permission to `TENANT_ADMIN` is safe by definition (it must 409 and write nothing) — but that also means an AC7 test that accidentally *passes through* would corrupt `RbacSchemaMigrationIT`'s seed count, which is a useful second-order tripwire worth noting rather than engineering away.
- **Randomised role names.** With `uq_roles_tenant_name` shared across the whole IT run, fixture role names must be randomised or AC9's own tests will collide with other suites' fixtures non-deterministically.
- **Seeded literals** (V5 header): bootstrap tenant `00000000-0000-7000-8000-000000000001`; `TENANT_ADMIN` role `019f6839-1810-…-00000000000a`; `MEMBER` `019f6839-1811-…-00000000000b`; `role:read` `019f6839-1804-…-000000000005`; `role:write` `019f6839-1805-…-000000000006`. **Per US-012's R-9: resolve `TENANT_ADMIN` by `(tenant_id, name)`, never by that literal** — the literal is the bootstrap tenant's admin role only, and AC11's second-tenant tests must not be written against it.

### 11.2 New tests required

**Unit:**
- `RoleManagementServiceTest` — all 12 ACs and every error branch. This will be the largest application-layer test in the codebase: 6 operations × (403 cross-tenant, 404 not-found, 409 conflict, happy path) + AC7 × 2 endpoints + AC11 × (dangerous permission × admin / non-admin) + AC12 × 3 post-commit assertions.
- `RoleControllerTest`, `PermissionControllerTest` — MockMvc slices, **including a negative-control 403 per endpoint** (the only mechanism that catches F5).
- `SystemRoleImmutableExceptionTest`, `DuplicateRolePermissionExceptionTest`, `DuplicateRoleNameExceptionTest` — required by the 0.90 `*.domain.*` gate, and note the known JaCoCo trap on `toString()`/record-accessor coverage for small domain types.
- `RbacDangerousPermissionsTest`, `RolePermissionViewTest`.
- `RbacAuthEventAdapterTest` — extend for the 3 new methods, including the **adversarial `roleName`/`permissionName` JSON test** (quotes, control chars, `\u2028`) and a null-`permissionId` (role-creation) case asserting the key is *omitted*, not emitted as JSON `null`.
- `JpaRoleManagementAdapterTest` — constraint-violation → domain-exception translation for both uniqueness rules.

**Integration (`*IT`, Testcontainers MySQL):**
- `RoleManagementIT` — Scenarios 1–4, 7 (201 with `is_system_role = FALSE`; 409 duplicate name; 201 attach; 204 detach; all 7 permissions listed); plus 404 branches for unknown role and unknown permission, and the Gate-1 404-on-never-attached `DELETE`.
- `RolePermissionSecurityIT` — Scenarios 5, 6, **9, 10**. Modelled on `RoleAssignmentSecurityIT`/`CrossTenantPermissionIT`. Must include a **second, non-bootstrap tenant** and a **tenant with no seeded `TENANT_ADMIN` role** (the §8 Epic-3-seeding fail-closed branch).
- **`RoleManagementAdminGateIT` (AC11's dedicated test — the one that catches F1)** — a caller who holds `role:write` via a custom role but has **no** active `TENANT_ADMIN` assignment attempts to attach `role:write`/`user:write`/`tenant:write` → 403 `NOT_TENANT_ADMIN` for each; plus an active-admin positive case; plus a **revoke-the-caller's-admin-assignment-in-a-concurrent-transaction** case, which is the only test that distinguishes the mandated locking read from the forbidden non-locking shortcut.
- `RoleManagementAuditIT` — Scenarios 11–14: `ROLE_CREATED`/`ROLE_PERMISSION_GRANTED`/`ROLE_PERMISSION_REVOKED` rows with the AC12 minimum field set, **and** Scenario 14's negative assertion (a 403 from AC11 and a 409 from AC7 each write **no** success row).
- `RoleNameUniquenessConcurrencyIT` — Scenario 2's concurrent variant (two threads, same name, same tenant → exactly one 201, one 409) plus the cross-tenant-same-name positive case, and the F10 accent case.
- **`RolePermissionsPrivilegeIT` (NEW, mandatory — F7)** — connects as `nexus_app` (pattern: `UserRolesPrivilegeIT`): `INSERT INTO roles` succeeds; **`UPDATE roles SET name=…` is denied**; `INSERT`/`DELETE` on `role_permissions` succeed; `UPDATE role_permissions` denied. **This is the only test that can catch an accidental `Role` dirty-flush, which otherwise fails in production only.**
- Optionally, an `EXPLAIN`-asserting test pinning Q3's plan to `uq_roles_tenant_name` (guards against a future `UPPER()` wrapper silently de-sargonising AC11's hot path).

**Modified tests:**
- **`identity/domain/AuthEventTypeTest`** — three concrete breakages, all currently hard-coded: `should_defineAll…` asserts `hasSize(23)` → **26**, plus its exhaustive name list; the priority test asserts `hasSize(6)` and an `EXPECTED_PRIORITY` set → **8** and two added members (if §1.3's recommendation is taken); and a new `should_returnFalse…` assertion for `ROLE_CREATED` mirroring the existing `ROLE_ASSIGNMENT_DENIED` one — that existing test's own comment says its purpose is to make a drive-by "add it for consistency" edit fail a test that states why it shouldn't, and `ROLE_CREATED` deserves the same guard.
- `RbacAuthEventAdapterTest` — as above.
- `rbac/RbacSchemaMigrationIT` — **no change expected.** No column, index, or table is added; its `contains(...)` index assertions and `containsExactly(...)` column assertions all still hold.

### 11.3 Coverage gates (`nexus-backend/pom.xml`, verified)

| Element | Gate | US-015 exposure |
|---|---|---|
| BUNDLE | LINE ≥ **0.80** | Comfortable. |
| `*.domain` / `*.domain.*` | LINE ≥ **0.90** | 3 new exceptions + 2 new records. Small classes with high gates — budget the companion tests explicitly (this is the known JaCoCo trap on small domain types). |
| `*.application` / `*.application.*` | LINE ≥ **0.85** | **The binding constraint.** `RoleManagementService` will be the largest application class in the codebase, dominated by error branches. Every AC's failure path needs a unit test, not just the happy paths. Budget for it in `/tasks`. |
| `*.interfaces.rest` / `*.interfaces.rest.*` | LINE ≥ **0.80** | 2 controllers + 6 DTOs. Records are cheap; the `resolveActor`/`parsePathUuid` fail-closed branches are not — they need explicit tests (which also happen to be security tests). |
| `*.infrastructure` / `*.infrastructure.*` | LINE ≥ **0.70**, **`*.rbac.infrastructure.persistence` EXCLUDED** | **F8 (Low) — the exclusion is stale.** Its `pom.xml` comment (lines 405–412) justifies it as "4 bare `JpaRepository` marker interfaces with zero instrumentable lines", which was true at US-009. The package now also contains `JpaUserRoleQueryAdapter` and `JpaUserRoleAssignmentAdapter`, and US-015 adds `JpaRoleManagementAdapter` — **including its constraint-violation-translation branches, the code that turns a 500 into a clean 409.** Those lines are currently exempt from any coverage gate. Recommend `/design` remove the exclusion (the stated zero-line condition no longer holds) and let the 0.70 gate apply; if it fails, that failure is information. |

---

## 12. Backward compatibility assessment

| Dimension | Verdict |
|---|---|
| HTTP API | ✅ Purely additive. Six new paths; no existing endpoint's path, method, request, or response changes. |
| JWT / `JwtClaims` | ✅ Unchanged → **no `token_version` bump**, no `JwtClaimsContractTest` change. |
| `MeResponse` / `/users/me` | ✅ Unchanged → frontend unaffected. |
| `/api/v1/users/{userId}/roles` (US-012) | ✅ Unchanged. `RoleAssignmentService` and `UserRoleController` are not modified. |
| Database schema | ✅ **No DDL at all.** No table, column, index, constraint, or trigger added or altered. Existing rows untouched. ADR 0003 not engaged. |
| `nexus_app` grants | ✅ No change required (§2.4) — but see F7/F7b for the *usage* constraints those grants impose. |
| `auth_events` data | ✅ 3 new `event_type` string values into a `VARCHAR(64)` column (longest new name: 25 chars). Existing rows and any consumer query are unaffected. |
| `auth_events` retry lanes | ⚠️ **Behavioural, not contractual.** If §1.3's recommendation is taken, the priority lane admits 2 more types, changing overflow characteristics under load. Not a compatibility break; is an operability change to record in §9. |
| Java port interfaces | ✅ `UserRoleAssignmentPort`, `UserRoleQueryPort`, `PermissionCachePort`, `UserDirectoryPort`, `AuthEventPort`, `SecureEventService` all keep current signatures. `RbacAuditPort` **widens** by 3 methods — source-compatible, since its single implementor is updated in the same change and there is no external implementor. |
| Error-code namespace | ✅ `RBAC_003`, `RBAC_005`, and (recommended) `RBAC_006` are all verified unused. `RBAC_001`/`RBAC_002`/`RBAC_004` keep their existing meanings. |
| Feature flag | ✅ Default-off in `application.yml` **and** structurally default-off via `@ConditionalOnProperty(havingValue="true")`. The entire story is dark until a per-env flip. |
| Rollback | ✅ Trivially reversible: no migration, no data reshaping. Flip the flag to disable instantly; revert the code to remove. `roles`/`role_permissions` rows written while live remain valid data and are consumed correctly by `RoleResolutionService` even with the feature off. |

**Overall: non-breaking, and unusually cleanly reversible — the flag is a genuine kill switch, not just a deployment gate.**

---

## 13. Top risks

| # | Risk | Sev | Owner / mitigation |
|---|---|---|---|
| **R-1** | **AC11's stated mechanism does not compose as-is.** `hasActiveAdminAssignment` needs the tenant's `TENANT_ADMIN` role id, which no port or repository can produce; the one existing helper that looks reusable (`callerHoldsActiveTenantAdmin`) is a **non-locking** read its own Javadoc says is only fit for response redaction. Copying it satisfies AC11's letter and destroys its point, with no failing test. | **High** | `/design`: pin AC11 as `Q3 → Q11`; add `findAdminRoleId(tenantId, roleName)` to the new port with a plain (collation-driven, sargable) name predicate; state in one sentence that `callerHoldsActiveTenantAdmin` must not be reused. `/tasks`: `RoleManagementAdminGateIT` with a concurrent admin-revocation case. |
| **R-2** | **`RbacAuditEvent` cannot carry AC12's payloads** — no `permissionId`/`permissionName`, and no meaningful `targetUserId` for role creation. Forcing reuse either corrupts US-012/US-014's field semantics (asserted by `RoleAssignmentAuditIT`) or silently redefines what `auth_events.user_id` means. | **High** | `/design`: new `RoleAuditEvent` record with no `targetUserId` field; 3 new methods on the existing `RbacAuditPort`; a second `record`/`buildMetadataJson` overload in `RbacAuthEventAdapter` reusing the injected Jackson-3 `ObjectMapper`. **No denial-recording method** — AC12 requires absence of a success row, not presence of a denial row (§1.4). |
| **R-3** | **Residual self-escalation: AC11 closes the mint side, not the propagate side.** `RoleAssignmentService.assign()`'s AC8 guard still name-matches `TENANT_ADMIN`, so once an admin legitimately attaches `user:write` to a custom role, any `user:write` holder can grant that role to themselves. `revoke()`'s T-E9 hole is symmetric. Unreachable today; reachable the first time US-015 is used as designed. | **High** | **Record, do not silently fix or silently close.** `/design`: amend `RoleAssignmentService`'s M-3 Javadoc to say AC11 discharged the attach path only; add both paths to `03b-threat-model.md` as accepted-risk-with-owner; note the cheap future fix (one Q7-like "does role X grant a dangerous permission?" query feeding the same admin gate in `assign()`/`revoke()`). |
| **R-4** | **AC9's 409 has no registered error code.** Gate 1 registered `RBAC_003` and `RBAC_005`; the duplicate-role-name conflict is unassigned, and reusing `RBAC_004` would collide with US-012's semantics. | **Medium** | `/design`: assign `RBAC_006` (verified unused) and complete the §5 error-contract table before any code is written. |
| **R-5** | **`@RequiresPermission` silently unenforced** on a non-`public` or `final` handler — no error, no log, no failing test. **No ArchUnit rule catches it** (suite verified: 2 classes, neither checks visibility). US-015 triples the annotated-handler count in this context, and AC7 has no DB backstop on `role_permissions`, so the application layer *is* the control. | **Medium** | `/design`: "all handlers `public`, non-`final`" as an explicit statement, **plus** a new ArchUnit rule (`@RequiresPermission` methods must be public and non-final) — near-zero cost, retroactively covers `UserRoleController`, encodes an existing `SECURITY.md` §3.1 rule so no ADR is needed. `/tasks`: a negative-control 403 test **per endpoint**. |
| **R-6** | **Accidental `Role` dirty-flush fails in production only.** `nexus_app` has no `UPDATE` on `roles`; `Role` maps `name`/`description`/`tenantId`/`systemRole` as updatable; every `*IT` runs as the full-DML `test` user. Same failure class as US-012's R-1, via a different table. | **Medium** | `/design`: `RoleManagementService` treats every loaded `Role` as read-only; the port returns ids/projections, not entities, wherever mutation isn't needed. `/tasks`: `RolePermissionsPrivilegeIT` as `nexus_app`, asserting `UPDATE roles` is denied. |
| **R-7** | **AC10's documented staleness window is wrong.** `RoleResolutionService`'s role-set fingerprint does **not** detect role-permission changes, so a token refresh does *not* shorten the lag — the full cache TTL applies. An operator following the current wording will refresh a token expecting a fix that never comes. | **Medium** | `/design`: state the accurate window (cache TTL; refresh does not help). Security runbook + Test Scenario 8 must assert the accurate behaviour. **Not** a reopening of ADR-0013 D4 — the decision stands; only its documentation is wrong. |
| **R-8** | **Privilege-drift detection blind spot.** `RbacDbPrivilegeHealthIndicator` covers only `user_roles`. A drifted `GRANT UPDATE ON nexus.roles` would silently re-permit role renames and `is_system_role` flips — a sub-application AC7 bypass — with zero operational signal. | **Medium** | `/design`: extend the indicator to `roles` (no `UPDATE`/`DELETE`) and `role_permissions` (no `UPDATE`), or explicitly accept and document the gap. Extension is mechanical against the existing structure. |
| **R-9** | **`GET /roles` is unbounded and unpaginated**, and this story is precisely the mechanism that removes the previous ≤2-roles-per-tenant bound. `POST /roles` is unthrottled, which also makes `ROLE_CREATED` the cheapest audit-row generator in the story. | **Medium** | `/design`: document the unbounded-list contract and the `{"data":…}` envelope's forward-compatibility; keep `ROLE_CREATED` out of the priority lane (§1.3); do **not** build unrequested pagination. |
| **R-10** | **Fail-open on a tenant with no seeded `TENANT_ADMIN` role.** Per-tenant seeding is bootstrap-only today (Gap 9). If Q3 returns empty and AC11 treats that as "no gate applies", every Epic-3-created tenant bypasses the story's key control. | **Medium** | `/design`: specify fail-closed (403) explicitly. `/tasks`: an IT with a tenant that has roles but no `TENANT_ADMIN`. |
| **R-11** | **`AuthEventTypeTest`'s hard-coded counts break** (`hasSize(23)`, priority `hasSize(6)` + `EXPECTED_PRIORITY`). Easy to "fix" by loosening the assertion, which would delete a deliberate tripwire. | **Low** | `/tasks`: update counts to 26 / 8 and extend the name lists; add a `should_returnFalse…isPriority` assertion for `ROLE_CREATED` mirroring the `ROLE_ASSIGNMENT_DENIED` one. Never weaken to `hasSizeGreaterThan`. |
| **R-12** | **`deleteById` cannot satisfy Gate 1's 404-on-never-attached** — it returns `void`. A `void` detach silently degrades to an idempotent 204, exactly the client-double-remove masking §11 OQ5c rejected. | **Low** | `/design`: `@Modifying @Query("DELETE FROM RolePermission …") int`, count-as-guard, mirroring `revokeById`. |
| **R-13** | **JaCoCo excludes `*.rbac.infrastructure.persistence`** on a rationale ("bare marker interfaces, zero instrumentable lines") that stopped being true two stories ago. The new adapter's 409-translation branches would ship ungated. | **Low** | `/design`: remove the exclusion; if the 0.70 gate then fails, that is information, not an obstacle. |
| **R-14** | **`uq_roles_tenant_name` is accent-insensitive as well as case-insensitive** (`utf8mb4_0900_ai_ci`), broader than AC9's wording. Untested today. | **Low** | `/design`: document the real semantics; keep `DuplicateRoleNameException`'s message from over-promising. `/tasks`: one accent test case. |

---

## 14. Open items handed to `/design` (Gate 2)

Not Gate 1 re-litigation — genuine design-level choices this analysis surfaced and deliberately did not decide:

1. The new port's exact name and surface (`RoleManagementPort` vs. splitting role CRUD from role-permission CRUD). Constrained by R7's "don't widen `UserRoleAssignmentPort`".
2. AC12's carrier shape: one `RoleAuditEvent` (recommended) vs. two records vs. widening `RbacAuditEvent`. Constrained by R-2.
3. `RBAC_006` (or another code) for AC9. Constrained by R-4 — **must be closed before the §5 API contracts are written.**
4. `parsePathUuid`/`resolveActor` duplication vs. extraction, and where (`rbac.interfaces.rest`, **not** `common.web`). Constrained by §5.2's ArchUnit caveat.
5. Response DTO field sets for `RoleResponse`/`PermissionResponse`, and whether `isSystemRole` is exposed (recommended: yes).
6. `name`/`description` validation constants (`@Size(max = 64)` / `255` from the DDL; allowed-character policy is genuinely open).
7. `AuthEventType.PRIORITY` membership for the 3 new types — this analysis gives a reasoned recommendation (grant/revoke in, `ROLE_CREATED` out) and the criterion it was derived from; `/design` ratifies or rebuts against the same criterion.
8. Whether to add the `@RequiresPermission`-must-be-public ArchUnit rule (recommended; not an ADR).
9. Whether to extend `RbacDbPrivilegeHealthIndicator` to `roles`/`role_permissions` (recommended) or accept and document the gap.
10. Whether to remove the stale `*.rbac.infrastructure.persistence` JaCoCo exclusion (recommended).
11. `GET /roles` unbounded-list contract: document (recommended) vs. paginate.
12. Observability: WARN + dedicated event name on AC7 blocks; the 3 new INFO success-log events; priority-lane depth-alert review.
13. The exact wording of the amended `RoleAssignmentService` M-3 Javadoc and the corresponding `03b-threat-model.md` entries for R-3.
14. Story re-estimation: this analysis recommends 9 → **13** points.

---

## 15. Files touched — quick index (all absolute)

**New — backend only:**
```
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\RoleManagementService.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\RoleManagementPort.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\RoleAuditEvent.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\SystemRoleImmutableException.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\DuplicateRolePermissionException.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\DuplicateRoleNameException.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\RbacDangerousPermissions.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\RolePermissionView.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\infrastructure\persistence\JpaRoleManagementAdapter.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\RoleController.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\PermissionController.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\dto\CreateRoleRequest.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\dto\AttachPermissionRequest.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\dto\RoleResponse.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\dto\RoleListResponse.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\dto\PermissionResponse.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\dto\PermissionListResponse.java
```

**Modified:**
```
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\RbacAuditPort.java                 (+3 methods)
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\infrastructure\persistence\JpaRoleRepository.java        (+Q1, Q3)
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\infrastructure\persistence\JpaRolePermissionRepository.java (+Q7, Q9)
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\identity\domain\AuthEventType.java                            (+3 constants, PRIORITY set)
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\identity\infrastructure\audit\RbacAuthEventAdapter.java        (+3 methods, +overload)
C:\entomo\AI\nexus\nexus-backend\src\main\resources\application.yml                                                            (+feature flag, ~line 214)
C:\entomo\AI\nexus\nexus-backend\src\main\resources\application-dev.yml                                                        (+flag true, ~line 54)
C:\entomo\AI\nexus\nexus-backend\src\main\resources\application-test.yml                                                       (+flag true, ~line 12)
C:\entomo\AI\nexus\nexus-backend\src\test\java\com\example\nexus\identity\domain\AuthEventTypeTest.java                        (23→26; priority 6→8)
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\RoleAssignmentService.java                    (Javadoc only — R-3; optional)
C:\entomo\AI\nexus\nexus-backend\pom.xml                                                                                       (remove stale JaCoCo exclusion — R-13; optional)
C:\entomo\AI\nexus\nexus-backend\src\test\java\com\example\nexus\architecture\HexagonalArchitectureTest.java                   (+@RequiresPermission visibility rule — R-5; recommended)
```

**Read but unchanged (key evidence):**
```
C:\entomo\AI\nexus\nexus-backend\src\main\resources\db\migration\V5__rbac_schema.sql
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\common\web\GlobalExceptionHandler.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\common\security\DenialReason.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\config\SecurityConfig.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\RoleAssignmentService.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\UserRoleAssignmentPort.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\PermissionCachePort.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\RbacAuditEvent.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\UserRoleController.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\Role.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\Permission.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\RolePermission.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\RolePermissionId.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\RbacRoleNames.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\infrastructure\persistence\JpaUserRoleRepository.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\infrastructure\persistence\JpaUserRoleAssignmentAdapter.java
C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\infrastructure\health\RbacDbPrivilegeHealthIndicator.java
C:\entomo\AI\nexus\nexus-backend\src\test\java\com\example\nexus\TestcontainersConfiguration.java
C:\entomo\AI\nexus\nexus-backend\src\test\java\com\example\nexus\rbac\UserRolesPrivilegeIT.java
C:\entomo\AI\nexus\nexus-backend\src\test\java\com\example\nexus\rbac\RbacSchemaMigrationIT.java
C:\entomo\AI\nexus\nexus-backend\src\test\java\com\example\nexus\rbac\RbacRepositoryRoundTripIT.java
C:\entomo\AI\nexus\nexus-database\mysql\init\02-grants-post-schema.sql
```

**Frontend:** no files.

---

### Cross-references
- `docs/features/US-015/01-requirements.md` — Gate 1 approved; §11 Resolutions (OQ1→AC11, OQ2→AC12, OQ3–OQ6) applied throughout, never re-opened
- `docs/story/2-rbac/US-015.md` — authoritative source ACs 1–12 (per §11 OQ3)
- `docs/story/2-rbac/EPIC-002.md` — API table (lines 147–152, verified to match); its inline US-015 AC copy (lines 702–708) is stale on AC3/AC7 wording and must not be implemented against
- `docs/features/US-012/02-impact.md` — structural/rigor template; source of the resolved US-012 findings this story inherits or closes (F1/R-1 → this story's R-6; F2/R-2 → R-5; F3/R-3 → not applicable, verified; R-4 locking-read privilege → closed by `UserRolesPrivilegeIT`)
- `docs/adr/0003` (Flyway append-only — not engaged), `0013` (RBAC data model; D1 permissions read-only, D2 uniqueness technique, D3 handler pattern, **D4 cache fan-out — ratified, not reopened**), `0014` (bootstrap tenant, D5 seeding scope, D6 grants), `0015` (threat-model hardening, D7 grants, D8 seeding), `0016` (Redis cache — deliberately not used here), `0011` (§1 audit retry-buffer lanes)
- `docs/features/US-009/03b-threat-model.md` — T-E1, T-E5, T-T1, T-S2, T-R1
- `SECURITY.md` §3.1 — `RBAC_001` response shape and the `@RequiresPermission` visibility/self-invocation pitfalls (R-5)
- `docs/TESTING.md` — Testcontainers-MySQL-only policy for `*IT`
