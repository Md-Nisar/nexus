# US-012 — Task Breakdown: Enable role assignment and revocation API

**Epic:** EPIC-002 (RBAC Foundation)
**Phase:** 4 (Task Breakdown) — Gate 3
**Inputs:** `03-design.md` (revised post-threat-model, all 8 required changes applied), `03b-threat-model.md` (Approve With Conditions)
**Status:** Draft for Gate 3 approval

> Every task cites the design section and/or threat ID it implements. Task IDs are sequenced by dependency, not by group — read top-to-bottom for implementation order; read the grouped index below for the reporting view the skill requires.

---

## One decision made during breakdown, not left implicit

**O-10 (threat model T-I5) — resolved as option (b).** `GET`'s response omits `assignedBy` unless the caller holds an active `TENANT_ADMIN` assignment in the tenant (checked via the same `hasActiveAdminAssignment` port method AC8 uses). This was left as a PM/architect decision in the design; adopting (b) now because it removes the admin-roster-enumeration surface T-I5 flagged for the cost of one conditional in the DTO mapper, with zero impact to AC3 or the Epic-3 contract (Epic 3's own admin UI caller will hold `TENANT_ADMIN` and see the field regardless). If this call is wrong, it is a one-line revert in T-011 and its test.

---

## Grouped index

```
Epic: US-012
├─ Database (migrations / schema)
│   └─ T-001  nexus_app privilege regression test (no migration — verified in 03-design.md §5.1)
├─ Backend
│   ├─ Domain
│   │   ├─ T-002  Core domain value types (RoleChangeActor, ActiveRoleAssignment, ActiveAssignmentRef, RbacRoleNames)
│   │   ├─ T-003  IdGenerator port
│   │   └─ T-004  Domain exceptions (LastAdminRoleException, DuplicateRoleAssignmentException)
│   ├─ Application
│   │   ├─ T-005  Outbound ports (UserRoleAssignmentPort, UserDirectoryPort, RbacAuditPort, RbacAuditEvent)
│   │   └─ T-010  RoleAssignmentService
│   ├─ Infrastructure
│   │   ├─ T-006  M1–M6 repository queries + JpaUserRoleAssignmentAdapter
│   │   ├─ T-007  UuidV7IdGenerator adapter
│   │   ├─ T-008  JpaUserDirectoryAdapter (identity)
│   │   └─ T-009  RbacAuthEventAdapter + AuthEventType constants (identity)
│   └─ Interfaces
│       └─ T-011  UserRoleController + DTOs
├─ Frontend
│   └─ (none — 02-impact.md §1.6 verified zero frontend impact; no tasks)
├─ Cross-cutting (security mitigations, feature flag, observability)
│   ├─ T-012  DenialReason additions (D5)
│   ├─ T-013  Feature flag wiring (D11)
│   ├─ T-014  ArchUnit rules (D9, T-E10)
│   └─ T-015  Observability: counters, alerts, dashboard config (D12, T-R3, T-R4)
├─ Tests
│   ├─ T-016  Unit test suite
│   ├─ T-017  RoleAssignmentIT
│   ├─ T-018  LastAdminLockoutIT
│   ├─ T-019  RoleAssignmentSecurityIT
│   ├─ T-020  RoleAssignmentCacheIT
│   ├─ T-021  RoleAssignmentAuditIT
│   └─ T-022  AuthEventTypeTest update
└─ Documentation
    ├─ T-023  monitoring.md + runbook.md
    └─ T-024  Story/epic text corrections (O-6)
```

24 tasks. Sizes: 15 S, 7 M, 2 L (T-010 `RoleAssignmentService`, T-019 `RoleAssignmentSecurityIT`) — both large because they carry the story's actual security substance (AC4/AC5/AC8 and their adversarial tests) and should not be split smaller than "one service" / "one security-focused IT class".

---

## Database

### T-001 — `nexus_app` DB-privilege regression test

**Description.** New Testcontainers-MySQL IT connecting **as `nexus_app`**, not the default `test` superuser, proving the privilege boundary the whole design depends on. This was originally scoped as a blocking discovery task (R-4/O-1); threat-model review already resolved the question empirically against a throwaway container, so this task now codifies that result as a permanent regression assertion rather than re-discovering it. Pattern: `identity/infrastructure/persistence/AuthEventsPrivilegeAppendOnlyIT.java` — raw `DriverManager.getConnection(mysqlContainer.getJdbcUrl(), "nexus_app", "nexus_app_test_only")` against the shared Testcontainers MySQL bean; do **not** use the autowired `DataSource` (that connects as `test`).

**Assertions (all four, per `03-design.md` §5.3):**
1. `UPDATE user_roles SET revoked_at = NOW(6) WHERE id = ?` succeeds (1 row) — proves D2 defeats R-1.
2. `UPDATE user_roles SET tenant_id = ? WHERE id = ?` (and at least one other non-`revoked_at` column) fails with `ERROR 1143`, SQLState `42000`.
3. `SELECT id FROM user_roles WHERE role_id = ? AND tenant_id = ? AND revoked_at IS NULL FOR UPDATE` succeeds.
4. `SHOW GRANTS FOR 'nexus_app'@'%'` matches the expected set **and explicitly asserts the `UPDATE` grant is column-scoped to `revoked_at`**, not table-scoped — this is the assertion that would catch a silent grant-widening regression (threat T-E12) that assertions 1 and 3 alone would not.

**Dependencies:** none — no application code required, pure DB/JDBC.

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/UserRolesPrivilegeIT.java`

**Files impacted:** none.

**Complexity:** S.

**Risks:** none residual — this is verification, not new production logic. If assertion 3 unexpectedly fails in CI (contradicting the threat-model's manual verification), stop and re-open O-1/§5.3's decision tree rather than silently adjusting the test.

**Testing requirements:** this task *is* the test. No further test needed on top of it.

**Definition of Done:** all 4 assertions pass against Testcontainers MySQL 8.4; test is tagged `@Tag("IT")` per `docs/TESTING.md`; CI green.

---

## Backend — Domain

### T-002 — Core domain value types

**Description.** Four small, dependency-free value types per `03-design.md` §4.6:
- `RoleChangeActor(UUID userId, UUID tenantId)` — the authenticated caller, Spring-Security-free (enforces R-10/ArchUnit).
- `ActiveRoleAssignment(UUID userId, UUID roleId, String roleName, Instant assignedAt, UUID assignedBy)` — read model for M4/M4a.
- `ActiveAssignmentRef(UUID id)` — id-only projection for the revocation write path (T-T6 fix; deliberately not a managed entity).
- `RbacRoleNames` — `public static final String TENANT_ADMIN = "TENANT_ADMIN";` single-sourced constant.

**Dependencies:** none.

**Files created:**
```
rbac/domain/RoleChangeActor.java
rbac/domain/ActiveRoleAssignment.java
rbac/domain/ActiveAssignmentRef.java
rbac/domain/RbacRoleNames.java
```

**Complexity:** S.

**Risks:** none — plain records/constants.

**Testing requirements:** unit tests only where there's behavior to test (records with no logic need no dedicated test beyond what JaCoCo's `*.domain.*` 0.90 gate requires — a trivial construction/accessor test satisfies it if the gate flags them).

**Definition of Done:** all four types compile, `HexagonalArchitectureTest`'s domain-layer rules pass (no outer-layer, no Spring Security, no Redis imports).

---

### T-003 — `IdGenerator` port

**Description.** `@FunctionalInterface IdGenerator { UUID newId(); }` in `rbac.domain`. Per `03-design.md` §4.7/D13: `rbac` cannot import `identity.domain.UuidGenerator` once T-014's ArchUnit rule lands, so this is a small rbac-local port rather than reuse across the context boundary. Consolidation into a `common.domain.UuidGenerator` is explicitly deferred to a US-015 prerequisite (O-9), not done here.

**Dependencies:** none.

**Files created:** `rbac/domain/IdGenerator.java`

**Complexity:** S.

**Risks:** none.

**Testing requirements:** none beyond the interface compiling (implementation tested in T-007).

**Definition of Done:** interface exists; `HexagonalArchitectureTest` passes.

---

### T-004 — Domain exceptions

**Description.** Per `03-design.md` §4.6 and threat T-T7:
- `LastAdminRoleException extends com.example.nexus.common.domain.ConflictException`, code `RBAC_002`.
- `DuplicateRoleAssignmentException extends ConflictException`, code `RBAC_004`.

**Both messages MUST be static literals baked into the exception class — never constructed from a caught `DataIntegrityViolationException`'s message or any other DB-supplied text.** This is the threat-model fix for T-T7: the natural implementation (`new DuplicateRoleAssignmentException(e.getMessage())`) would echo MySQL's constraint text — the constraint name, index name, and a hex fragment of `active_key` (`CONCAT(user_id, role_id)`, i.e. the raw target user/role ids) — straight into the client-visible RFC 7807 `detail` field via `GlobalExceptionHandler#handleConflict`. Give `DuplicateRoleAssignmentException` a no-arg (or ids-only, formatting nothing from any cause) constructor.

**Dependencies:** none.

**Files created:**
```
rbac/domain/LastAdminRoleException.java
rbac/domain/DuplicateRoleAssignmentException.java
```

**Complexity:** S.

**Risks:** T-T7 (Low) — mitigated by the static-literal constraint above; verified by the test below.

**Testing requirements:** `LastAdminRoleExceptionTest`, `DuplicateRoleAssignmentExceptionTest` — assert `code()` and `getMessage()` equal fixed literals regardless of constructor arguments (contributes to the `*.domain.*` 0.90 JaCoCo gate — note this is the known JaCoCo trap where trivial domain classes need explicit tests to hit the line-coverage floor).

**Definition of Done:** both classes exist, extend `ConflictException`, carry immutable static messages; unit tests green; `GlobalExceptionHandler`'s existing generic `ConflictException`/409 handler requires **zero** new code (verify by inspection, not by adding a handler).

---

## Backend — Application (ports)

### T-005 — Outbound ports

**Description.** Four port artifacts in `rbac.application.port.out`, per `03-design.md` §4.3–§4.5:

- `UserRoleAssignmentPort` — `findRole`, `hasActiveAssignment(userId, roleId)` [M2], `hasActiveAdminAssignment(userId, roleId, tenantId)` [M5, **locking**, T-E7 fix], `lockActiveAssignmentIds(tenantId, roleId)` [M1], `findActiveAssignmentRef(userId, roleId, tenantId)` [M3, **projection**, T-T6 fix], `findActiveAssignmentView(userId, roleId, tenantId)` [M4a], `findActiveAssignmentViews(userId, tenantId)` [M4], `assign(...)`, `revoke(userRoleId)` [M6].
- `UserDirectoryPort` — `Optional<UUID> findTenantId(UUID userId)`.
- `RbacAuditPort` — `recordRoleAssigned(RbacAuditEvent)`, `recordRoleRevoked(RbacAuditEvent)`; Javadoc must restate the "never throws, never blocks" contract (Res. 9).
- `RbacAuditEvent` record — `(tenantId, targetUserId, roleId, roleName, actorUserId, requestContext)`.

**A separate `UserRoleAssignmentPort`, not a widened `UserRoleQueryPort` (D3)** — the existing `UserRoleQueryPort` is documented read-only and consumed by `RoleResolutionService`/`RoleResolutionServiceTest`; widening it would leak a write capability to a read-only collaborator.

**Dependencies:** T-002 (domain types used in signatures), T-004 (not a compile dependency, but logically paired since the port's Javadoc references the exceptions its adapter will throw).

**Files created:**
```
rbac/application/port/out/UserRoleAssignmentPort.java
rbac/application/port/out/UserDirectoryPort.java
rbac/application/port/out/RbacAuditPort.java
rbac/application/port/out/RbacAuditEvent.java
```

**Files impacted:** none (`UserRoleQueryPort.java` is explicitly *not* touched).

**Complexity:** S — interfaces only, no logic.

**Risks:** getting the port surface wrong forces churn in three adapters and the service later; this is why the exact method list is pinned here rather than left to the implementer.

**Testing requirements:** none directly (interfaces); exercised by adapter tests (T-016) and the service test (T-016).

**Definition of Done:** all four files compile; `HexagonalArchitectureTest`'s `application_must_not_depend_on_adapters` rule passes; no method signature includes any `org.springframework.security` type (pre-empting T-E10/R-10 before the service is even written).

---

## Backend — Infrastructure

### T-006 — M1–M6 repository queries + `JpaUserRoleAssignmentAdapter`

**Description.** The core persistence work, per `03-design.md` §5.2 (all six queries specified exactly — copy them, do not re-derive):

- **M1** `lockActiveAssignmentsByRole(tenantId, roleId)` — `@Lock(PESSIMISTIC_WRITE)`, single-table JPQL driven by `ur.roleId` (never `ur.tenantId` as the driving predicate — this is the R-3/T-D3 fix; `tenant_id` stays only as a residual defense-in-depth filter). No join with `roles` — this is what keeps the lock scope to one tenant's admin rows and avoids locking a `roles` row.
- **M2** `countActiveByUserAndRole(userId, roleId)` — **no tenant predicate**, must mirror `uq_user_role_active (user_id, role_id)` exactly.
- **M3** `findActiveAssignmentRef(userId, roleId, tenantId)` — returns `Optional<ActiveAssignmentRef>` via a constructor-expression projection (**T-T6 fix** — this was originally specified as returning a managed `UserRole` entity; the corrected version in `03-design.md` §5.2 is authoritative).
- **M4/M4a** `findActiveAssignmentViews(userId, tenantId)` / `findActiveAssignmentView(userId, roleId, tenantId)` — single comma-join projection into `ActiveRoleAssignment`, `ORDER BY r.name`, cross-checking `r.tenantId = :tenantId` (mirrors the existing `findActiveRoleNames` defense-in-depth pattern).
- **M5** `lockActiveAdminAssignment(userId, roleId, tenantId)` — `@Lock(PESSIMISTIC_READ)` (renders `FOR SHARE`), returns `List<UserRole>` (**T-E7 fix** — originally a plain non-locking `COUNT`; the corrected locking version in `03-design.md` §5.2 M5 is authoritative). Service only inspects `size()`.
- **M6** `revokeById(id)` — `@Modifying(clearAutomatically = true)`, `UPDATE UserRole ur SET ur.revokedAt = FUNCTION('now', 6) WHERE ur.id = :id AND ur.revokedAt IS NULL`, returns `int`. **Must use `FUNCTION('now', 6)`, never plain HQL `current_timestamp`** — the latter renders MySQL's second-precision `CURRENT_TIMESTAMP` and would *cause* the R-8 CHECK-constraint violation it exists to avoid (verified empirically in the threat model).

`JpaUserRoleAssignmentAdapter` implements `UserRoleAssignmentPort`, delegating to these plus a plain `save()`-based insert wrapped in `catch (DataIntegrityViolationException) → throw new DuplicateRoleAssignmentException()` (the TOCTOU backstop behind M2's pre-check).

**R-9 discipline, applying to every query touching `roleId`:** never resolve `TENANT_ADMIN` by the seeded bootstrap-tenant literal. Always resolve the role the request names via `findRole(roleId)`, verify `role.tenantId == actor.tenantId` **and** `RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())` (case-insensitive — `roles.name`'s collation makes `uq_roles_tenant_name` case-insensitive, so a case-sensitive Java compare could silently disable both AC5 and AC8), then bind that resolved `role.getId()` into M1/M5.

**Dependencies:** T-002, T-003, T-004, T-005.

**Files impacted:** `rbac/infrastructure/persistence/JpaUserRoleRepository.java` (+6 methods)

**Files created:** `rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`

**Complexity:** L is tempting given the density, but the queries are fully specified in the design with no open decisions left — sizing as **M**.

**Risks:** R-1 (mitigated by M6's single-column UPDATE — do not regress to load-mutate-save), R-3/T-D3 (mitigated by M1's join-free, role_id-driven shape — verified empirically to produce `type=ref key=fk_user_roles_role`), T-E7 (mitigated by M5's locking read), T-T6 (mitigated by M3's projection return), R-9 (mitigated by resolve-by-name-and-tenant, never by literal).

**Testing requirements:**
- Unit: none beyond what Spring Data derives (query correctness is proven by IT, not mockable).
- Integration (T-017, T-018): `EXPLAIN`-asserting test pinning M1 to `key = fk_user_roles_role`, `type = ref`, and confirming the emitted SQL contains `for update`; the assign-then-immediately-revoke microsecond-precision assertion for M6 (`revoked_at >= assigned_at` AND `MICROSECOND(revoked_at) <> 0`); the mixed-case `TENANT_ADMIN`/`Tenant_Admin` R-9 regression case.

**Definition of Done:** all 6 methods implemented exactly per the (corrected) `03-design.md` §5.2 signatures; `RbacSchemaMigrationIT`'s existing `containsExactly` column assertions still pass unchanged (no entity/schema change); `JpaUserRoleAssignmentAdapter` implements `UserRoleAssignmentPort` fully.

---

### T-007 — `UuidV7IdGenerator` adapter

**Description.** `rbac.infrastructure.crypto.UuidV7IdGenerator implements IdGenerator`, one line: `UuidCreator.getTimeOrderedEpoch()` (same call as the existing `identity.infrastructure.crypto.UuidV7Generator`, per ADR-0005 — this is intentional, reviewed duplication, not a new pattern; see O-9 for the future consolidation).

**Dependencies:** T-003.

**Files created:** `rbac/infrastructure/crypto/UuidV7IdGenerator.java`

**Complexity:** S.

**Risks:** none (crypto/randomness already reviewed clean in the threat model — `SecureRandom`-backed, no enumeration surface since `user_roles.id` is never exposed in any DTO).

**Testing requirements:** trivial unit test asserting the returned UUID is version 7 (or simply non-null/unique across calls) — satisfies the `*.infrastructure.*` coverage expectation without over-testing a one-line delegate.

**Definition of Done:** `@Component`, implements `IdGenerator`, `HexagonalArchitectureTest` passes (crypto import stays in infrastructure, not domain).

---

### T-008 — `JpaUserDirectoryAdapter` (identity)

**Description.** `identity.infrastructure.persistence.JpaUserDirectoryAdapter implements rbac.application.port.out.UserDirectoryPort` — `userRepository.findById(userId).map(User::getTenantId)`. No `JpaUserRepository` change needed (`findById` already inherited; `User.tenantId` already `UUID`).

This is the concrete instance of the `identity.infrastructure → rbac.application.port.out` dependency direction the design insists on (§5.1/§7.4) — confirm this file imports `rbac.application.port.out.UserDirectoryPort` and nothing else from `rbac`.

**Dependencies:** T-005.

**Files created:** `identity/infrastructure/persistence/JpaUserDirectoryAdapter.java`

**Complexity:** S.

**Risks:** none — one-line delegation.

**Testing requirements:** `JpaUserDirectoryAdapterTest` — present-user and absent-user cases → `Optional` present/empty.

**Definition of Done:** `@Component`; implements the port; unit test green.

---

### T-009 — `RbacAuthEventAdapter` + `AuthEventType` constants (identity)

**Description.**

1. **`AuthEventType`**: add `ROLE_ASSIGNED("ROLE_ASSIGNED")`, `ROLE_REVOKED("ROLE_REVOKED")`. **Add both to the `PRIORITY` `EnumSet`** — this is the T-R4 reversal of the design's original D10: role-change audit events must not share the drop-newest STANDARD lane with `LOGIN_FAILURE` floods, since the STANDARD lane can silently drop the newest arrival under correlated load and a lost `ROLE_ASSIGNED` record is exactly the repudiation risk AC7 exists to prevent.

2. **`RbacAuthEventAdapter implements RbacAuditPort`** in `identity.infrastructure.audit`, beside `AuthEventRetryBuffer`/`LoggingAuditAlertAdapter`. Constructor: `(SecureEventService, UuidGenerator, tools.jackson.databind.ObjectMapper)` — **the Jackson 3 type, injected as the Spring Boot 4.1 auto-configured bean, never `new ObjectMapper()`** (T-E13 fix: the only other in-repo `ObjectMapper` usage, `LoginRateLimitFilter`, uses the unrelated Jackson **2** type self-instantiated — do not copy that pattern here, it either fails context startup or puts the T-T5 security-critical escaping on an unmanaged, unconfigured object).

3. **Field mapping** (per `03-design.md` §4.8 table): `id` = `uuidGenerator.newId()`; `eventType` via `wireName()`; `outcome = "SUCCESS"`; `userId` = the **target** user (matching identity's `LOCKOUT` convention — the subject, not the actor); `tenantId` = JWT-sourced from the event, never request input; `ipAddress`/`userAgent` from `RequestContext`; `metadata` = Jackson-serialized JSON built **in this adapter** (not by widening `common.domain.RequestContext#toMetadataJson`) containing `traceId`, `roleId`, `roleName`, `assignedBy` (assign) or `revokedBy` (revoke) — keys omitted when null, never null-valued.

4. **T-R3 fix — audit-write-loss handling, mandatory, not optional:**
   - Serialize the metadata JSON (`objectMapper.writeValueAsString(...)`) **before** calling `secureEventService.recordEvent(...)` — i.e. outside the `REQUIRES_NEW` transaction boundary — so a `JsonProcessingException` is caught before any transaction opens.
   - Wrap the whole call in `try/catch (Exception)`. On catch: log at **ERROR** (not WARN) with structured event `event=RBAC_AUDIT_WRITE_LOST`, carrying `tenantId`, `targetUserId`, `roleId`, `actorUserId`, `traceId`; increment `nexus.rbac.audit_write_failed{operation}` (T-015 defines the counter registration; this task increments it).
   - This is necessary because `JpaAuthEventAdapter`'s own retry-buffer `catch` is on the `save()` call inside its own transaction — but `AuthEvent` has an assigned `@Id`, so the actual `INSERT` (and any DB-level rejection) happens at `REQUIRES_NEW` **commit** time, inside `SecureEventService`'s proxy, after `record()` has already returned. `JpaAuthEventAdapter`'s catch never fires for this failure mode; without this task's ERROR log + counter, a committed role change can lose its audit record with zero signal.

**Dependencies:** T-005.

**Files impacted:** `identity/domain/AuthEventType.java` (+2 constants, added to `PRIORITY`)

**Files created:** `identity/infrastructure/audit/RbacAuthEventAdapter.java`

**Complexity:** M — the field mapping is simple; the T-R3 failure-handling and T-T5 escaping correctness are where the care goes.

**Risks:** T-T5 (JSON injection — mitigated by Jackson serialization, verified to close the vector), T-R3 (audit loss — mitigated by the ERROR log + counter above), T-E13 (Jackson-major ambiguity — mitigated by pinning the FQN), T-R4 (drop-newest lane — mitigated by the `PRIORITY` addition in step 1).

**Testing requirements:** `RbacAuthEventAdapterTest` — field-mapping table assertions; **adversarial `roleName` set** (`"`, `\`, `\n`, raw `U+0000`–`U+001F` control character, a lone high surrogate, a `{"a":1}`-shaped payload, and a `","traceId":"forged` duplicate-key attempt asserting the *real* `traceId` survives — this last case is the one that actually distinguishes a working escaper from a broken one, since MySQL keeps the **last** duplicate JSON key); never-throws behavior when `SecureEventService` raises; the test must use the same `tools.jackson.databind.ObjectMapper` type as production. `AuthEventTypeTest` update is T-022.

**Definition of Done:** both constants added and in `PRIORITY`; adapter implements `RbacAuditPort`; ERROR-log + counter path verified by a forced-failure unit test; `RoleAssignmentAuditIT` (T-021) proves the end-to-end JSON round-trips through `JSON_VALID()`/`JSON_EXTRACT` against real MySQL.

---

## Backend — Application (service)

### T-010 — `RoleAssignmentService`

**Description.** The story's actual substance: `assign`, `revoke`, `listActive` in `rbac.application`, per `03-design.md` §4.2 and the corrected §3.1–§3.3 sequences. This is the **only** place AC4 (tenant isolation), AC5 (lockout guard), and AC8 (self-escalation guard) are enforced — `@RequiresPermission` cannot express any of them.

**`assign(RoleChangeActor actor, UUID targetUserId, UUID roleId, RequestContext ctx)`:**
1. `userDirectoryPort.findTenantId(targetUserId)` → empty ⇒ `ResourceNotFoundException` (404 `USER_NOT_FOUND`); mismatch vs `actor.tenantId()` ⇒ `InsufficientPermissionException(perm, CROSS_TENANT_TARGET)`.
2. `userRoleAssignmentPort.findRole(roleId)` → empty ⇒ 404 `ROLE_NOT_FOUND`; `role.tenantId` mismatch ⇒ 403 `CROSS_TENANT_TARGET`.
3. If `RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())` (AC8): `userRoleAssignmentPort.hasActiveAdminAssignment(actor.userId(), role.getId(), actor.tenantId())` — **this MUST be the M5 locking-read port method, never `authentication.getAuthorities()` or any JWT claim** (closes R-5/T-E1's live half; the ~15-min-stale-JWT window is exactly what this design element exists to prevent) — false ⇒ 403 `NOT_TENANT_ADMIN`.
4. `userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)` [M2, no tenant predicate] → true ⇒ `DuplicateRoleAssignmentException` (409 `RBAC_004`).
5. `userRoleAssignmentPort.assign(...)` [insert; `DataIntegrityViolationException` → `DuplicateRoleAssignmentException`, the TOCTOU backstop behind step 4].
6. `userRoleAssignmentPort.findActiveAssignmentView(...)` [M4a projection — reads the DB-generated `assignedAt`; **never** re-read via the entity path, which would return the just-persisted session instance with a null `assignedAt`].
7. Register a `TransactionSynchronization` whose `afterCommit` calls `permissionCachePort.evict(actor.tenantId(), targetUserId)` then `rbacAuditPort.recordRoleAssigned(...)`. **If no transaction synchronization is active** (`TransactionSynchronizationManager.isSynchronizationActive() == false` — the normal case in a plain unit test), run both side effects **inline** rather than dropping them; document this fallback in the method's Javadoc.

**`revoke(RoleChangeActor actor, UUID targetUserId, UUID roleId, RequestContext ctx)`:**
1–2. Same tenant/role resolution as `assign`.
3. If admin role: `userRoleAssignmentPort.lockActiveAssignmentIds(actor.tenantId(), role.getId())` [M1, locking]. If `size() <= 1` and the locked set contains the target assignment's id ⇒ `LastAdminRoleException` (409 `RBAC_002`) — **actor-agnostic**: this guard fires for *any* caller revoking the tenant's last active `TENANT_ADMIN`, not only self-revocation (Gate 1 Resolution 5 resolved AC5's ambiguous title this way).
4. `userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, actor.tenantId())` [M3, projection] → empty ⇒ 404 `ROLE_ASSIGNMENT_NOT_FOUND` (covers both "never assigned" and "already revoked" — **never** a silently-idempotent 204, per Res. 7).
5. `userRoleAssignmentPort.revoke(ref.id())` [M6] → `0` affected rows ⇒ 404 (lost race, someone else revoked first); `1` ⇒ proceed.
6. Same `afterCommit`/inline-fallback side-effect pattern as `assign`, calling `recordRoleRevoked`.

**`listActive(RoleChangeActor actor, UUID targetUserId)`:**
1. **`userDirectoryPort.findTenantId(targetUserId)` + tenant-equality check — MANDATORY, not redundant with M4's own predicates (T-E8 fix).** Empty ⇒ 404; mismatch ⇒ 403 `CROSS_TENANT_TARGET`. Skipping this because "M4 already filters by tenant" is exactly the bug the threat model found: it produces a silent `200 {"data":[]}` for a cross-tenant probe instead of the `403`/`404` contract, and destroys the WARN-log/metric signal that makes cross-tenant probing on `POST`/`DELETE` detectable.
2. `userRoleAssignmentPort.findActiveAssignmentViews(targetUserId, actor.tenantId())` [M4].
3. **O-10 decision (T-I5):** if the caller does **not** hold an active `TENANT_ADMIN` assignment in this tenant (reuse `hasActiveAdminAssignment` against the caller), map each `ActiveRoleAssignment` to a response with `assignedBy` omitted/null. Admins see the full view.

**Constraints carried from the threat model, non-negotiable:**
- **T-E10**: this service's public methods accept **only** `RoleChangeActor`, `UUID`, `RequestContext` — no `Authentication`, no `java.security.Principal`, no `java.util.Map`, no `AuthenticatedRequestDetails`. All three types would keep `HexagonalArchitectureTest`'s existing Spring-Security rule green while reintroducing raw authentication data into the application layer through an unblocked laundering path.
- **T-S3**: `assignedBy`/actor identity comes **only** from `actor.userId()`, sourced by the controller from the JWT principal — never from a method parameter derived from the path or body.

**Dependencies:** T-002, T-004, T-005, T-006, T-008, T-009, T-012 (needs `DenialReason.CROSS_TENANT_TARGET`/`NOT_TENANT_ADMIN` to exist).

**Files created:** `rbac/application/RoleAssignmentService.java`

**Complexity:** L — this is the story's core logic, all 8 ACs, and the two Critical-risk properties (T-E1/AC8, AC4).

**Risks:** T-E7, T-E8, T-E9 (documented, not code — see below), T-E10, T-S3 — all addressed by the constraints above. **T-E9 (accepted, deferred):** add a Javadoc note on `revoke` stating that revocation of `TENANT_ADMIN` is gated only by `user:write` + the AC5 last-admin guard, asymmetric with AC8 by conscious decision, currently unreachable (only `TENANT_ADMIN` holds `user:write` pre-US-015), and that **US-015 must add a symmetric "only an active `TENANT_ADMIN` may revoke `TENANT_ADMIN`" check as an entry criterion**, not a follow-up.

**Testing requirements:** the bulk of T-016 (unit) and all of T-017/T-018/T-019/T-020 (integration) exercise this class. See those tasks.

**Definition of Done:** all 8 ACs pass their integration tests (T-017–T-021); `./mvnw verify -DskipITs` run immediately after the first skeleton lands, specifically to catch an accidental `Authentication`/`Principal`/`Map` parameter via `HexagonalArchitectureTest`'s `domain_and_application_must_not_depend_on_spring_security` rule before the rest of the class is built on top of a violation; `*.application.*` JaCoCo branch coverage ≥ 0.85 including every error branch, not just happy paths.

---

## Backend — Interfaces

### T-011 — `UserRoleController` + DTOs

**Description.** First controller in the `rbac` bounded context. Three endpoints per `03-design.md` §4.1/§8:

- `POST /api/v1/users/{userId}/roles` — `@RequiresPermission("user:write")` → `RoleAssignmentResponse`, 201, `Location` header.
- `GET /api/v1/users/{userId}/roles` — `@RequiresPermission("user:read")` → `RoleAssignmentListResponse` (`{"data": [...]}` envelope, no pagination — bounded result set, see design §8.3).
- `DELETE /api/v1/users/{userId}/roles/{roleId}` — `@RequiresPermission("user:write")` → 204.

**Hard constraints (each traceable to a specific threat):**
- **Every handler is `public` and non-`final` (R-2/T-E11).** The nearest in-repo template, `UserProfileController#me()`, is package-private, which per `@RequiresPermission`'s own Javadoc means Spring AOP may silently never enforce the annotation — no error, no test failure. Do not copy that visibility.
- **`{userId}`/`{roleId}` path variables and the request body's `roleId` are `String`, validated by `@Pattern`/Bean Validation, parsed to `UUID` only after validation passes (D15/R-12 fix)** — never a `UUID`-typed `@PathVariable` or body field, which would raise `MethodArgumentTypeMismatchException`/`HttpMessageNotReadableException` and fall through to a 500 (`GlobalExceptionHandler` is a plain `@RestControllerAdvice`, not `ResponseEntityExceptionHandler`).
- **Principal parsing fails closed (T-S4 fix).** `AuthenticatedRequestDetails.fromAuthentication(authentication, requiredPermission)` for the tenant (existing fail-closed behavior); a null/non-`String`/non-UUID `authentication.getPrincipal()` must throw `InsufficientPermissionException(requiredPermission, DenialReason.MALFORMED_AUTHENTICATION)` — do not let an unparseable principal fall through to the generic 500 handler.
- **No `assignedBy`/`tenantId` field on `AssignRoleRequest`** — enforced by not modeling the field at all (stronger than validating it away).
- `RequestContext.of(req.getRemoteAddr(), MDC.get("traceId"), req.getHeader("User-Agent"))`, mirroring `RegistrationController#requestContext`.

**Dependencies:** T-010, T-013 (feature flag annotation must exist for the controller's `@ConditionalOnProperty`).

**Files created:**
```
rbac/interfaces/rest/UserRoleController.java
rbac/interfaces/rest/dto/AssignRoleRequest.java
rbac/interfaces/rest/dto/RoleAssignmentResponse.java
rbac/interfaces/rest/dto/RoleAssignmentListResponse.java
```

**Complexity:** M.

**Risks:** T-E11 (mitigated by public/non-final + mandatory paired positive/negative tests — see T-019), T-S4, R-12/D15 — all mitigated by the constraints above.

**Testing requirements:** `UserRoleControllerTest` (MockMvc slice) — principal unwrapping; the differing-path-vs-JWT-`sub` provenance case (T-E10: path `userId` must never become the actor); `MISSING_TENANT`/`MALFORMED_AUTHENTICATION` fail-closed cases; malformed-UUID-in-path-and-body → 400 not 500; `Location` header on 201.

**Definition of Done:** all three endpoints wired; springdoc `@Tag`/`@Operation`/`@ApiResponse` annotations present (matches `RegistrationController`'s convention); zero new `GlobalExceptionHandler` code required (verify by inspection).

---

## Cross-cutting

### T-012 — `DenialReason` additions

**Description.** Add `CROSS_TENANT_TARGET` and `NOT_TENANT_ADMIN` to `common.security.DenialReason` (D5). Purely additive — no dispatch-logic change in `GlobalExceptionHandler`, which already handles `InsufficientPermissionException` generically and logs the `reason` field. This is the mechanism that makes AC4/AC8 denials separately alertable from ordinary `RBAC_001` denials via the existing `nexus.rbac.permission_denied{reason}` metric tag, at zero new plumbing cost.

**Dependencies:** none (can run in parallel with T-002–T-009).

**Files impacted:** `common/security/DenialReason.java` (+2 constants)

**Complexity:** S.

**Risks:** none — check whether any existing test asserts exhaustively over `DenialReason.values()` (`InsufficientPermissionExceptionTest`, `AuthenticatedRequestDetailsTest`, `TenantAwarePermissionEvaluatorTest`, `GlobalExceptionHandlerTest`) and update it if so — grep before editing, don't assume.

**Testing requirements:** update any exhaustive test found above; no new test needed otherwise.

**Definition of Done:** two constants added; `GlobalExceptionHandler` requires no changes; existing US-011 tests still green.

---

### T-013 — Feature flag wiring

**Description.** `feature.nexus-us012-rbac-role-assignment.enabled` — `@ConditionalOnProperty(havingValue = "true")` on `UserRoleController` (T-011 depends on this constant existing). Per `03-design.md` §10.1, this **overrides the story's own "Feature flag required: No"** — this endpoint is the platform's only control against a Critical self-escalation threat, and two production-only hazards (R-1, R-4) were unproven at design time (now resolved, but the flag remains the right operational posture regardless — every other controller in the codebase is flag-gated, and a config flip is the fastest possible kill switch if a bypass is ever found post-deploy).

| Environment | Value | File |
|---|---|---|
| default (incl. prod) | `false` | `application.yml` |
| `dev` | `true` | `application-dev.yml` |
| `test` | `true` | `application-test.yml` |

**Two traps, both must be handled:**
1. Every HTTP-level `*IT` (T-018, T-019, T-020, T-021) must set `@ActiveProfiles("test")`, or the controller bean is absent and every request 404s — a confusing "endpoint doesn't exist" failure that a naive negative-control test could misread as a passing 403 check. Security tests must assert the literal status code, never "not 2xx".
2. The flag **must** live in the profile YAML, not a `DynamicPropertyRegistrar` — `@ConditionalOnProperty` on a `@Component` evaluates during component scan, which runs before `DynamicPropertyRegistrar` contributions are visible (a known Spring Boot 4 property-precedence issue already documented for this repo).

**Dependencies:** none (can run early, in parallel).

**Files impacted:**
```
src/main/resources/application.yml
src/main/resources/application-dev.yml
src/main/resources/application-test.yml
```

**Complexity:** S.

**Risks:** the two traps above, called out explicitly for whoever picks this up.

**Testing requirements:** covered implicitly by every HTTP IT depending on the flag being `true` under `@ActiveProfiles("test")`.

**Definition of Done:** flag present in all three files with the values above; a smoke request against `application-smoke.yml` (where the flag is absent ⇒ defaults `false`) returns 404 for the new endpoints, proving fail-closed behavior.

---

### T-014 — ArchUnit rules

**Description.** Two additions to `architecture/HexagonalArchitectureTest.java`:

1. **`rbac_must_not_depend_on_identity` (D9).** `noClasses().that().resideInAPackage("..rbac..").should().dependOnClassesThat().resideInAPackage("..identity..")`, `allowEmptyShould(true)`. Verified currently green (zero `identity` imports in `rbac/src/main` today) — this converts the Gate-1-resolved dependency direction from documentation into a build failure, closing the exact drift the US-010 code review flagged once already.
2. **(T-E10 hardening, recommended)** a rule forbidding any `..rbac.application..` method from declaring a `java.security.Principal` or `java.util.Map` parameter — closes two laundering paths (`Principal extends java.security.Principal` and `authentication.getDetails()`'s raw `Map`) that the existing Spring-Security-package rule does not cover, since neither type lives in a banned package.

**Dependencies:** none for rule 1; logically follows T-010 for rule 2 (verifying it doesn't false-positive against the real service), but can be written first.

**Files impacted:** `architecture/HexagonalArchitectureTest.java`

**Complexity:** S.

**Risks:** none — additive, `allowEmptyShould(true)` per the existing convention in this file.

**Testing requirements:** the rules are themselves the test; run `./mvnw verify -DskipITs` after T-010 lands to confirm no violation.

**Definition of Done:** both rules present; full test suite green; rule 1's `because(...)` clause names the `common`-laundering path too (per the threat model's T-E10 finding) even though no ArchUnit rule can close that specific path mechanically — document it as a known limitation in the comment.

---

### T-015 — Observability: counters, alerts, dashboard config

**Description.** Per `03-design.md` §9 (as revised):

1. **New counter in `GlobalExceptionHandler#handleConflict`**: `nexus.domain.conflict{code}` — closes the gap that `RBAC_002`/`RBAC_004` currently log at DEBUG with no metric.
2. **New counter `nexus.rbac.audit_write_failed{operation}`**, incremented by T-009's `RbacAuthEventAdapter` catch-all (this task registers/wires the counter; T-009 increments it — sequence T-009 after this task or coordinate).
3. **Five new alert rules** (§9.3 — all Prometheus expressions specified in the design, copy verbatim): `nexus_rbac_self_escalation_attempt` (page), `nexus_rbac_cross_tenant_attempt` (ticket), `nexus_rbac_tenant_lockout_blocked` (ticket), `nexus_rbac_audit_write_lost` (**page** — T-R3), `nexus_rbac_role_change_error_rate` (page), `nexus_rbac_audit_lane_drops` (ticket, informational now that T-R4's `PRIORITY` fix is applied — should rarely if ever fire).
4. **Dashboard row** "RBAC / Role Assignment" per §9.4's panel list.
5. **Zero-active-admins detection control** (adopted unconditionally per the threat-model's T-D4 finding, modeled on the existing `RbacDbPrivilegeHealthIndicator` pattern) — a health indicator or scheduled check alerting if any tenant has zero active `TENANT_ADMIN` assignments. This is the only control that catches an AC5 bypass from *any* cause (bug, future grant change, `roles.name` casing mismatch, a raw-SQL path), not just the specific race the design's primary mitigation already closes.
6. **(Recommended, small) Positive grant check** in `RbacDbPrivilegeHealthIndicator` — DOWN/WARN if `information_schema.COLUMN_PRIVILEGES` lacks `UPDATE` on `user_roles.revoked_at` for the current DB user, **or** if `TABLE_PRIVILEGES` shows a table-scoped `UPDATE` on `user_roles` (the silent-grant-widening scenario T-E12 flags — currently undetectable, since the existing indicator only checks for over-grant via `DELETE`/root/`ALL PRIVILEGES`).

**Dependencies:** T-004 (for the conflict-code list), T-006 (for the zero-admins query pattern).

**Files impacted:**
```
common/web/GlobalExceptionHandler.java
rbac/infrastructure/health/RbacDbPrivilegeHealthIndicator.java
```

**Files created:**
```
rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java  (name indicative — pick per team convention)
```

**Complexity:** M.

**Risks:** T-R3 (mitigated by the audit-write-failed counter + page alert), T-E12 (mitigated by the positive grant check), T-D4 (mitigated by the zero-admins detector — this is the design's own "adopt unconditionally" instruction, not optional).

**Testing requirements:** `GlobalExceptionHandlerTest` — counter increments on `RBAC_002`/`RBAC_004`; zero-admins indicator unit test with a mocked tenant-with-no-admins case; positive grant check unit test.

**Definition of Done:** both counters registered and incrementing; alert rules present in whatever config the platform's alerting lives in (Prometheus rule files / equivalent); dashboard row added; zero-admins detector reports DOWN/alerts correctly in a test fixture.

---

## Tests

### T-016 — Unit test suite

**Description.** Consolidated unit-test task covering everything not already assigned to its own task above:
- `RoleAssignmentServiceTest` (Mockito) — all 8 ACs, every error branch (404 user, 404 role, 403 cross-tenant ×2, 403 non-admin, 409 duplicate, 409 last-admin, 404 already-revoked, 404 lost-race), the `afterCommit`-vs-inline-fallback branch, the `equalsIgnoreCase` mixed-case `TENANT_ADMIN` matching branch, and an explicit assertion that side effects **never** fire on any throwing path.
- `RbacRoleNamesTest` (or a dedicated case-mix branch inside the above) — case-insensitive matching.

(`LastAdminRoleExceptionTest`, `DuplicateRoleAssignmentExceptionTest` are T-004's; `RbacAuthEventAdapterTest`, `JpaUserDirectoryAdapterTest` are T-009's/T-008's; `UserRoleControllerTest` is T-011's — listed here only for cross-reference, not duplicated as separate line items.)

**Dependencies:** T-010.

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java` (+ `RbacRoleNamesTest.java` if split out)

**Complexity:** L — `*.application.*` carries a 0.85 JaCoCo branch-coverage gate and `RoleAssignmentService` is one of the codebase's larger application-layer classes with many distinct failure branches; budget accordingly, do not treat this as a quick add-on to T-010.

**Risks:** under-testing error branches is the single most likely way this gate fails in CI.

**Testing requirements:** this task is the test.

**Definition of Done:** `*.application.*` JaCoCo branch coverage ≥ 0.85 for `RoleAssignmentService`; every AC has at least one dedicated test method; every side-effect-ordering claim (post-commit, inline fallback) has an explicit assertion.

---

### T-017 — `RoleAssignmentIT`

**Description.** Happy-path and near-happy-path integration coverage (Testcontainers MySQL, per `docs/TESTING.md` — never H2):
- Scenario 1/2: 201 with `revoked_at IS NULL`; 204 with `revoked_at` set and the row **not** deleted.
- Reassign-after-revoke succeeds (a plain second INSERT, per the M2 correction in `03-design.md` §5.2 — no separate "distinguish new-vs-reassign" logic needed).
- Duplicate active assignment → 409 `RBAC_004`.
- 404 paths (nonexistent user, nonexistent role, revoke-already-revoked).
- **Assign-then-immediately-revoke, asserting `revoked_at >= assigned_at` AND `MICROSECOND(revoked_at) <> 0`** — the second assertion is what actually proves the `FUNCTION('now', 6)` rendering rather than merely the ordering (R-8 fix verification).
- 201 body carries a non-null `assignedAt` (proves the M4a projection re-read works, per `03-design.md` §5.4).
- **T-S3 provenance test**: using four *distinct* UUIDs (actor ≠ target ≠ role ≠ tenant), assert the persisted row has `user_id` = target, `assigned_by` = the JWT `sub`, `tenant_id` = the JWT `tenant_id` — catches a positional-argument transposition bug that the type system cannot.

**Dependencies:** T-006, T-010, T-011, T-013.

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentIT.java`

**Complexity:** M.

**Risks:** must use `@ActiveProfiles("test")` (feature flag, T-013's trap #1); must use randomized role names / `is_system_role=false` fixtures per the shared-Spring-context caveat (`RbacSchemaMigrationIT`'s scoped seed counts would otherwise break).

**Testing requirements:** this task is the test.

**Definition of Done:** all scenarios above pass against Testcontainers MySQL.

---

### T-018 — `LastAdminLockoutIT`

**Description.**
- Scenario 4: last-`TENANT_ADMIN` revoke → 409 `RBAC_002`, row still active afterward.
- **Actor-agnostic assertion**: Admin B revoking Admin A's assignment (not self-revocation) is blocked identically to self-revocation — verifies Gate 1 Resolution 5's reading of AC5.
- **Concurrency test (Res. 8/R-3)**: 8-thread `ExecutorService` + `CyclicBarrier` harness (pattern: `ActiveAssignmentIT#should_allowExactlyOneWinner…` / `RefreshTokenRotationIT#concurrent_rotation_single_winner`) with two admins in one tenant, both attempting concurrent revocation — exactly one succeeds, the tenant retains ≥ 1 active admin, the loser gets 409.
- **Second, non-bootstrap tenant** with its own `TENANT_ADMIN` row — proves R-9 (a hardcoded-bootstrap-UUID implementation would pass the bootstrap-tenant case and silently fail this one).
- **`EXPLAIN` assertion** pinning M1's plan to `key = fk_user_roles_role` (or whatever MySQL 8.4 actually reports — confirmed `fk_user_roles_role` in threat-model verification), `type = ref`, and that the emitted SQL contains `for update`.

**Dependencies:** T-006, T-010, T-011, T-013.

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/LastAdminLockoutIT.java`

**Complexity:** M.

**Risks:** the concurrency harness is the highest-value single test in the story for T-D3/R-3 — do not skip or simplify it under time pressure.

**Testing requirements:** this task is the test.

**Definition of Done:** all scenarios above pass; `EXPLAIN` assertion is real (not a TODO), directly checking the query plan MySQL returns.

---

### T-019 — `RoleAssignmentSecurityIT`

**Description.** The story's highest-consequence test class, modeled on `rbac/security/CrossTenantPermissionIT`. Covers:

- **Scenario 3/8**: cross-tenant on **all three verbs** — `POST`/`GET`/`DELETE` against a target in a different tenant → 403 `CROSS_TENANT_TARGET` on all three (T-E8 fix verification — `GET` must **not** return `200 {"data":[]}`); non-admin-with-`user:write` grants `TENANT_ADMIN` → 403 `NOT_TENANT_ADMIN`.
- **T-E7 test (the one thing that catches a claim-based AC8 implementation)**: an actor holding a still-valid JWT whose `TENANT_ADMIN` assignment was revoked out-of-band (directly in the DB, bypassing the API) attempts to grant `TENANT_ADMIN` → must be denied. If the implementation reads `authentication.getAuthorities()` instead of the M5 live DB read, this is the only test that catches it.
- **Paired positive/negative controls per endpoint (T-E11 fix)**: for each of the 3 endpoints, assert 403 *without* the permission and 2xx *with* it — a negative-only test can "pass" for the wrong reason (e.g., a missing `AnnotationTemplateExpressionDefaults` bean denying everyone).
- **T-E10 provenance test**: a request where the path `{userId}` differs from the JWT `sub` must never let the actor act as the path user — assert the persisted `assigned_by`/effective actor is always the JWT `sub`, regardless of path content.
- Assert `reason=CROSS_TENANT_TARGET`/`NOT_TENANT_ADMIN` appears in the log/metric for the relevant denials (verifies T-012's `DenialReason` additions are actually wired through, not just added to the enum).
- Malformed path/body UUIDs → 400, not 500 (D15/R-12 fix verification).
- Unparseable-principal fail-closed case (T-S4 fix verification) — may need a purpose-built fixture since a real JWT always carries a valid UUID `sub`.

**Dependencies:** T-006, T-009, T-010, T-011, T-012, T-013.

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/security/RoleAssignmentSecurityIT.java`

**Complexity:** L — this class carries the majority of the threat model's required test coverage; do not compress it to save time.

**Risks:** this is the test suite that, if thin, lets T-E7/T-E8/T-E10/T-E11 regress silently in the future. Treat every "mandatory" test named across the design and threat model as non-negotiable, not aspirational.

**Testing requirements:** this task is the test.

**Definition of Done:** every bullet above has a passing, named test method; `@ActiveProfiles("test")` set (T-013's trap #1); assertions check literal status codes and `reason` values, never "not 2xx".

---

### T-020 — `RoleAssignmentCacheIT`

**Description.**
- Scenario 5: after a successful assign/revoke, assert **both actual Redis keys are deleted** — `{prefix}:rbac:roleset:{tenantId}:{userId}` and `{prefix}:rbac:permset:{tenantId}:{userId}` (with whatever `nexus.redis.key-prefix` the test config uses, default `nexus`). **Do not** write this test against AC6's literal `permissions:{tenant_id}:{user_id}` — that key does not exist anywhere in the codebase and the test would pass vacuously, deleting a key that was never there (R-7).
- Redis-down case: request still returns 2xx (`RedisPermissionCacheAdapter.evict` is verified fail-open — this test proves it end-to-end through the service, not just at the adapter).
- No eviction call on a 403/409 path (afterCommit-only side effects — a thrown exception must not touch the cache).

**Dependencies:** T-006, T-010, T-011, T-013.

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentCacheIT.java`

**Complexity:** S.

**Risks:** R-7 (mitigated by asserting the *real* keys, not the story's literal text).

**Testing requirements:** this task is the test.

**Definition of Done:** all three cases pass; test explicitly names both real Redis keys in its assertions (grep-verifiable — no reference to `permissions:{t}:{u}` anywhere in the file).

---

### T-021 — `RoleAssignmentAuditIT`

**Description.**
- Scenario 6: `ROLE_ASSIGNED`/`ROLE_REVOKED` rows present with the full Res. 3 payload (`user_id`=target, `tenant_id`, `metadata` containing `roleId`/`roleName`/`assignedBy`-or-`revokedBy`/`traceId`) — assert via `JSON_VALID()` and `JSON_EXTRACT`, **never string equality** (MySQL's binary JSON normalizes key order, verified in the threat model).
- Adversarial `roleName` round-trip cases (see T-009's testing requirements — same set, exercised here end-to-end against real MySQL rather than mocked).
- **No audit row on a rolled-back (403/409/404) request** — the after-commit contract, T-R3-adjacent.
- **T-R3 forced-failure case**: simulate an audit-write failure (e.g., inject a metadata payload that fails serialization, or mock the port to throw) and assert the `RBAC_AUDIT_WRITE_LOST` ERROR log and `nexus.rbac.audit_write_failed` counter both fire — this is the only test proving the T-R3 fix actually works end-to-end, not just that the code compiles.

**Dependencies:** T-006, T-009, T-010, T-011, T-013, T-015 (counter must exist to assert against).

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentAuditIT.java`

**Complexity:** M.

**Risks:** T-T5 (verified via the adversarial set), T-R3 (verified via the forced-failure case — do not skip this, it's the only test for the story's second-most-important threat finding).

**Testing requirements:** this task is the test.

**Definition of Done:** all cases above pass; the T-R3 forced-failure case specifically asserts the ERROR-level log line and counter increment, not merely "the request didn't 500."

---

### T-022 — `AuthEventTypeTest` update

**Description.** `should_defineAllTwentyConstants_when_valuesCalled` (asserts `hasSize(20)` + exhaustive name list) → update to **22**, adding `ROLE_ASSIGNED`/`ROLE_REVOKED`. Per T-009/T-R4's reversal of D10, also add/update a `PRIORITY` assertion confirming both new constants **are** priority (the existing `EnumSource(EXCLUDE)`-based non-priority test would otherwise silently assert the wrong thing if left unmodified — this must be an explicit, reviewed change, not an auto-pass).

**Dependencies:** T-009.

**Files impacted:** `nexus-backend/src/test/java/com/example/nexus/identity/domain/AuthEventTypeTest.java`

**Complexity:** S.

**Risks:** if this edit is skipped, the existing exhaustive-count test simply fails (loud, not silent) — low risk of this slipping through unnoticed, but sequence it right after T-009 regardless.

**Testing requirements:** this task is the test update itself.

**Definition of Done:** test asserts 22 constants by exact name; `PRIORITY` assertion explicitly covers both new constants as priority members.

---

## Documentation

### T-023 — `monitoring.md` + `runbook.md`

**Description.** Per `03-design.md` §9.4:
- `docs/features/US-012/monitoring.md` — the log queries, dashboard link, and a baseline-metrics capture once T-015's dashboard is live.
- `docs/features/US-012/runbook.md` — first-check procedure for the `nexus_rbac_role_change_error_rate` alert ("the single most likely cause is a DB-privilege regression — check the MySQL error log for `command denied`"), and the recovery procedure for a tenant with zero active admins (T-015's detector firing).

**Dependencies:** T-015 (needs the actual counters/alerts/dashboard to document, not a planned version).

**Files created:**
```
docs/features/US-012/monitoring.md
docs/features/US-012/runbook.md
```

**Complexity:** S.

**Risks:** none.

**Testing requirements:** none (documentation).

**Definition of Done:** both files exist and reference the actual, shipped alert names/dashboard panels — not placeholders.

---

### T-024 — Story/epic text corrections (O-6)

**Description.** Per `03-design.md` §6.5 and the requirements/impact docs' own findings, correct the **source story text** (not just the design docs, which already carry the correct information):
- `docs/story/2-rbac/US-012.md` AC5's title ("Self-revocation of last admin role blocked") — correct to reflect the actor-agnostic reading actually implemented (Gate 1 Resolution 5).
- AC6's Technical Notes cache-key literal `permissions:{tenant_id}:{user_id}` — correct to the real two-key scheme, or remove the literal and reference `PermissionCachePort.evict` by name.
- The Technical Note's `WHERE role_id = TENANT_ADMIN` — correct to reflect resolve-by-`(tenant_id, name)`, since there is no such constant and the literal invites the R-9 bug in a future reader.
- Mirror the same three corrections in `docs/story/2-rbac/EPIC-002.md` wherever it repeats this story's text inline.

**Dependencies:** none (pure documentation, can run any time, but logically last since it's a wrap-up correction).

**Files impacted:**
```
docs/story/2-rbac/US-012.md
docs/story/2-rbac/EPIC-002.md
```

**Complexity:** S.

**Risks:** none — corrections only, no behavior implied.

**Testing requirements:** none.

**Definition of Done:** all three corrections applied to both files; no remaining reference to the nonexistent `role_id = TENANT_ADMIN` constant or the nonexistent single-key cache literal anywhere in the story docs.

---

## Sequencing summary (suggested implementation order)

1. **Parallel start:** T-001, T-002, T-003, T-004, T-012, T-013 (all dependency-free).
2. T-005 (ports) once T-002–T-004 land.
3. T-006, T-007, T-008 in parallel once T-005 lands.
4. T-009 once T-005 lands (parallel with T-006–T-008).
5. T-010 once T-006, T-008, T-009, T-012 all land — this is the critical-path bottleneck task.
6. T-011 once T-010 and T-013 land.
7. T-014 any time, but verify against the real T-010/T-011 code before closing it out.
8. T-015 once T-004/T-006 land (can start early, finish late).
9. T-016 alongside/immediately after T-010.
10. T-017–T-021 once T-006, T-009, T-010, T-011, T-013 (and T-015 for T-021) all land — these can run in parallel with each other.
11. T-022 immediately after T-009.
12. T-023 after T-015. T-024 any time.

---

### Cross-references
- `docs/features/US-012/03-design.md` — all D1–D15 decisions plus the 8 post-threat-model revisions (marked inline with their T-xx ids)
- `docs/features/US-012/03b-threat-model.md` — full STRIDE analysis; every "Required mitigation" cited above traces to a numbered finding there
- `docs/features/US-012/02-impact.md`, `01-requirements.md` — earlier gates, cited where a task resolves an open item from either (e.g. O-6, O-9, O-10, O-11)
