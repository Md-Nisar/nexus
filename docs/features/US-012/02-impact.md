# US-012 — Impact Analysis

**Feature:** Enable role assignment and revocation API
**Epic:** EPIC-002 (RBAC Foundation)
**Phase:** 2 (Impact Analysis) — inputs: `docs/features/US-012/01-requirements.md` (Gate 1 approved, §11 Resolutions binding)
**Author:** Principal Architect
**Status:** Draft for Gate 2 entry

> This document is *read-only analysis*. Every §11 Gate 1 Resolution is treated as settled and applied, not re-litigated. Where this analysis contradicts an assumption in the source story or epic, it is called out explicitly with the verified evidence.

---

## 0. Executive summary

US-012 is **additive-only** and needs **no new Flyway migration for table shape** — `V5__rbac_schema.sql` already carries every column the story requires. Three findings dominate the risk profile and should drive `/design`:

| # | Finding | Severity |
|---|---|---|
| **F1** | A naive JPA `findById → revoke() → save()` revocation emits an `UPDATE` touching **all** updatable columns, which the production `nexus_app` grant (`UPDATE (revoked_at)` — column-scoped) will **reject**. All Testcontainers ITs run as `test` (full DML), so this fails **only in production**. | **Critical** |
| **F2** | `@RequiresPermission` is silently unenforced on non-`public` handler methods. `UserProfileController#me()` — the controller the author is most likely to copy — is **package-private**. Copying that style produces an unguarded admin endpoint with no error and no test failure. | **Critical** |
| **F3** | `SELECT ... FOR UPDATE` (Resolution 8) on `user_roles` has **no index on `tenant_id`**. If the lockout-guard query is written to drive off `user_roles.tenant_id`, MySQL full-scans and takes next-key locks on **every row in the table**, serialising all revocations platform-wide. The query must drive off `roles (tenant_id, name)`. Separately, MySQL requires SELECT + one of DELETE/LOCK TABLES/UPDATE for a locking read — whether the **column-scoped** `UPDATE (revoked_at)` grant satisfies that is unverified. | **High** |

Everything else is routine: 2 new ports, 1 new application service, 1 new controller + 2 DTOs, 2 new exceptions, 2 new `AuthEventType` constants, 2 new adapters in `identity.infrastructure`, ~4 new repository methods. **Zero frontend impact. Zero new dependencies. Zero breaking changes.**

---

## 1. Modules / classes affected

### 1.1 Backend — `rbac` bounded context (`nexus-backend/src/main/java/com/example/nexus/rbac/`)

**Existing inventory (verified by full read):**

| Layer | Existing classes |
|---|---|
| `domain/` | `Permission`, `Role`, `RolePermission`, `RolePermissionId`, `UserRole`, `ResolvedPermissions` |
| `application/` | `RoleResolutionService` |
| `application/port/out/` | `UserRoleQueryPort`, `PermissionCachePort` |
| `infrastructure/persistence/` | `JpaPermissionRepository`, `JpaRoleRepository`, `JpaRolePermissionRepository`, `JpaUserRoleRepository`, `JpaUserRoleQueryAdapter` |
| `infrastructure/cache/` | `RedisPermissionCacheAdapter` |
| `infrastructure/health/` | `RbacDbPrivilegeHealthIndicator` |
| `interfaces/` | **does not exist** |

**NEW files:**

| Path | Kind | Notes |
|---|---|---|
| `rbac/application/RoleAssignmentService.java` | `@Service` | Orchestrates AC1–AC8. `@Transactional` on the write methods, `@Transactional(readOnly = true)` on `GET`. Sits beside `RoleResolutionService`. **Must not** reference any `org.springframework.security` type (see §5.3). |
| `rbac/application/port/out/RbacAuditPort.java` | interface | Resolution 1. One method, e.g. `void recordRoleAssigned(RbacAuditEvent)` / `recordRoleRevoked(RbacAuditEvent)`. Contract must restate `AuthEventPort.record`'s "never throws, never blocks" guarantee (Resolution 9). |
| `rbac/application/port/out/RbacAuditEvent.java` *(or `rbac/domain/`)* | record | Typed carrier for the Resolution 3 payload superset. See §1.3/F5 — needed because `RequestContext.toMetadataJson()` cannot express it. |
| `rbac/application/port/out/UserDirectoryPort.java` | interface | Resolution 4. `Optional<UUID> findTenantId(UUID userId)`. |
| `rbac/application/port/out/UserRoleAssignmentPort.java` | interface | Read+write port for the assignment aggregate. **Recommended over extending `UserRoleQueryPort`** — that port's Javadoc declares itself read-only, `RoleResolutionService` depends on it, and its adapter/mocks are asserted in `RoleResolutionServiceTest`. `/design` decides; state the choice explicitly. |
| `rbac/domain/LastAdminRoleException.java` | exception | Resolution 11. `extends com.example.nexus.common.domain.ConflictException`, code `RBAC_002`. |
| `rbac/domain/DuplicateRoleAssignmentException.java` | exception | Resolution 7 registers `RBAC_004` but §11 OQ-10 only named `LastAdminRoleException`. Either a sibling class (recommended, for symmetry and testability) or a bare `new ConflictException("RBAC_004", …)`. **Small open item for `/design`.** |
| `rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java` | `@Component` | Implements `UserRoleAssignmentPort`. Mirrors `JpaUserRoleQueryAdapter`'s thin-delegation shape. |
| `rbac/interfaces/rest/UserRoleController.java` | `@RestController` | **First controller in `rbac`.** `@RequestMapping("/api/v1/users")`. See §1.4 for convention detail. |
| `rbac/interfaces/rest/dto/AssignRoleRequest.java` | record | `{ "roleId": "…" }`, `@NotNull` — see §3.2. |
| `rbac/interfaces/rest/dto/RoleAssignmentResponse.java` | record | 201 body + `GET` list element. Shape is `/design`'s job (Gap 2). |

**MODIFIED files:**

| Path | Change |
|---|---|
| `rbac/infrastructure/persistence/JpaUserRoleRepository.java` | +4 query methods (§1.2). Currently only `findActiveRoleNames` / `findActivePermissionNames`. |
| `rbac/domain/UserRole.java` | **Probably unchanged.** `revoke(Instant)` already exists. But see F1 — if `/design` chooses entity-dirty-check revocation, this file *must* gain `updatable = false` on `userId`/`roleId`/`tenantId`/`assignedBy`. Recommended alternative (JPQL bulk `UPDATE`) leaves it untouched, and `revoke()` becomes unused on the write path — a deliberate, documentable outcome consistent with the entity's own Javadoc ("set via a targeted UPDATE, never load-mutate-save"). |

**UNCHANGED (explicitly verified, reused as-is):**
- `PermissionCachePort.evict(tenantId, userId)` — already implemented in `RedisPermissionCacheAdapter`, Javadoc says "Unused until US-012". **Ready to call; no code change.** (But see F4 — the key names do not match AC6's literal text.)
- `RoleResolutionService`, `UserRoleQueryPort`, `JpaUserRoleQueryAdapter`, `RedisPermissionCacheAdapter`, `RbacDbPrivilegeHealthIndicator`, `Role`, `Permission`, `RolePermission`.

### 1.2 New repository methods (all on `JpaUserRoleRepository`)

Four methods are needed; **none exist today**. Exact JPQL is `/design`'s job — this is the *requirement* list:

| # | Purpose | AC | Notes |
|---|---|---|---|
| M1 | Lock + count the tenant's active `TENANT_ADMIN` assignments (`SELECT … FOR UPDATE`) | AC5 / Res. 8 | Must drive off `roles (tenant_id, name = 'TENANT_ADMIN')` → `uq_roles_tenant_name`, then nested-loop into `user_roles` via the FK index on `role_id`. **Do not filter on `user_roles.tenant_id` as the driving predicate** — F3. Spring Data `@Lock(PESSIMISTIC_WRITE)` on a JPQL join emits `FOR UPDATE` across all joined tables on MySQL; consider `FOR UPDATE OF` scoping or restructuring so `roles` is not locked. |
| M2 | Find the existing `UserRole` for `(userId, roleId)` **regardless of revoked state** | AC1 / US-009 Test Scenario 8 | Distinguishes "assign new" vs. "re-assign after revocation" so the code returns `RBAC_004` deliberately rather than surfacing a raw `DataIntegrityViolationException` from `uq_user_role_active`. Served by the FK index on `user_id` (few rows/user) — no new index. |
| M3 | Find the **active** assignment for `(userId, roleId)` within a tenant, for revocation + the `404`-on-already-revoked rule | AC2 / Res. 7 | |
| M4 | List active assignments for `(userId, tenantId)` **projected with `roles.name`** | AC3 | Single projection query — see §7 N+1. |
| M5 | Does the *caller* hold an active `TENANT_ADMIN` assignment in the target tenant? | AC8 | **Must be a fresh DB read, not the JWT `roles[]` claim** — see F6. May be expressible as a boolean over M1's non-locking twin. |

> **Naming caution (real correction to the story):** US-012's Technical Note writes `WHERE role_id = TENANT_ADMIN`. There is no such constant. `TENANT_ADMIN` is a **per-tenant `roles` row** (`uq_roles_tenant_name`); Epic 3 will seed a distinct `roles.id` per tenant. The seeded literal `019f6839-1810-…-00000000000a` is the **bootstrap tenant's** admin role only. Every AC5/AC8 query must resolve the role by `(tenant_id, name = 'TENANT_ADMIN')`, never by that hardcoded UUID.

### 1.3 Backend — `identity` bounded context

**MODIFIED:**

| Path | Change |
|---|---|
| `identity/domain/AuthEventType.java` | Add `ROLE_ASSIGNED("ROLE_ASSIGNED")`, `ROLE_REVOKED("ROLE_REVOKED")` (Resolution 2). **Do not add to the `PRIORITY` `EnumSet`** — that set is documented as "the 4 highest-value forensic/security-incident signals" and drives `AuthEventRetryBuffer` lane routing. Whether authz-change events warrant priority-lane treatment is a US-014 decision; record it as such. |

**NEW:**

| Path | Kind | Notes |
|---|---|---|
| `identity/infrastructure/audit/RbacAuthEventAdapter.java` | `@Component` | Resolution 1. Implements `rbac.application.port.out.RbacAuditPort`; maps the typed RBAC event → `AuthEvent` (+ metadata JSON, §1.3 F5) → `SecureEventService.recordEvent(...)`. Reuses `@Transactional(REQUIRES_NEW)` + retry-buffer machinery **unchanged**. Sits beside `AuthEventDbPrivilegeHealthIndicator`, `AuthEventRetryBuffer`, `LoggingAuditAlertAdapter`. |
| `identity/infrastructure/persistence/JpaUserDirectoryAdapter.java` | `@Component` | Resolution 4. `userRepository.findById(userId).map(User::getTenantId)`. **No `JpaUserRepository` change needed** — `findById` is inherited from `JpaRepository`, and `User.tenantId` is a `UUID` field. |

**UNCHANGED (verified):** `AuthEventPort` (no signature change), `SecureEventService` (`recordEvent(AuthEvent)` reused verbatim), `JpaAuthEventAdapter`, `AuthEventRetryBuffer`, `JpaUserRepository`, `JpaUserRegistrationAdapter`, `AuthEvent` (`withUserId`/`withTenantId`/`withMetadata` builders already sufficient).

> **F5 — audit metadata gap (new finding).** `AuthEvent` has native columns only for `user_id`, `tenant_id`, `event_type`, `outcome`, `ip_address`, `user_agent`, `metadata` (JSON). The Resolution 3 superset therefore needs `role_id`, `role_name`, and `assigned_by`/`revoked_by` inside `metadata`. The only existing metadata builder is `common.domain.RequestContext#toMetadataJson()`, which emits **exactly** `{traceId, ip, userAgent}` and nothing else. `correlation_id` is satisfied by the existing `traceId` key; the other three are not expressible. `/design` must choose: (a) widen `RequestContext` — touches `common.domain`, consumed by five identity use-cases, broad blast radius, **not recommended**; or (b) build the JSON in `RbacAuthEventAdapter` from the typed `RbacAuditEvent` — **recommended**. Either way the new builder **must** replicate `RequestContext#jsonEscape`'s RFC 8259 control-character escaping: `role_name` is tenant-supplied free text once US-015 ships, making it a JSON-injection vector into a native `JSON` column (the T-T1 threat class).
>
> `auth_events.user_id` has **no FK** (verified, `V2__identity_schema.sql:76-86`), so nullable/unknown subjects are safe. `outcome` is `NOT NULL` → `"SUCCESS"`.

### 1.4 Backend — `interfaces.rest` conventions to follow

Verified against `identity/interfaces/rest/`:

- **DTO placement:** yes, there is a `dto` subpackage. Controllers live directly in `interfaces/rest/`; every request/response record lives in `interfaces/rest/dto/` (`RegisterRequest`, `RegisterResponse`, `MeResponse`, `LoginRequest`, …). US-009's own Technical Notes already named `interfaces/rest/dto` as the intended `rbac` layout. **Mirror exactly.**
- **Annotations:** `@RestController`, `@RequestMapping("/api/v1/…")`, springdoc `@Tag` / `@Operation` / `@ApiResponse` (`RegistrationController`), `@Valid @RequestBody`, `@ResponseStatus(HttpStatus.CREATED)`.
- **Principal access:** `UserProfileController` reads `Authentication.getDetails()` as an untyped `Map<?,?>` via `AuthenticationDetailKeys`, and `(String) authentication.getPrincipal()` is the user-id string. `common.security.AuthenticatedRequestDetails.fromAuthentication(auth, requiredPermission)` is the safer, validating alternative and **must be called from the controller, never the service** (§5.3).
- **Feature flag:** every existing controller is `@ConditionalOnProperty`-gated (`feature.nexus-us00X-….enabled`, wired in `application.yml` + `-dev`/`-test`). US-012's story says "Feature flag required: No" — so this will be the **first ungated controller**. That is a deliberate deviation from an otherwise universal pattern; record it in `/design` §10 rather than letting it happen silently.

> **F2 — `@RequiresPermission` + method visibility (Critical).** `UserProfileController#me()` is **package-private** (`MeResponse me(Authentication)`). `@RequiresPermission`'s own Javadoc and `SECURITY.md` §3.1 both state that Spring AOP cannot proxy `final` or non-`public` methods, so the annotation is *silently never enforced* — no error, no log, no test failure unless a negative-path test exists. `RegistrationController#register` is `public`. **Every US-012 handler must be `public` and non-`final`.** This belongs in `/design` and as an explicit task-level checklist item, plus a mandatory negative-control test per endpoint.

### 1.5 Backend — `common` and `config`

**No changes required.** Verified:
- `common.web.GlobalExceptionHandler` — generic `@ExceptionHandler(ConflictException.class)` → `409` using `e.code()`, and `@ExceptionHandler(ResourceNotFoundException.class)` → `404`. Both dispatch by base type; **zero new handler code** for `RBAC_002`, `RBAC_004`, or the `404`s.
- `config.SecurityConfig` — `.anyRequest().authenticated()` already covers `/api/v1/users/**`; the new paths are not in the `permitAll` list. **No change.**
- `config.MethodSecurityConfig` — `AnnotationTemplateExpressionDefaults` bean already registered, so `@RequiresPermission`'s `{value}` substitution works. **No change.**
- `common.security.*` — `@RequiresPermission`, `TenantAwarePermissionEvaluator`, `InsufficientPermissionException`, `DenialReason`, `AuthenticatedRequestDetails`, `AuthenticationDetailKeys` all reused unchanged.

### 1.6 Frontend — **zero impact (explicit)**

Confirmed by inspection, not assumed:
- `docs/story/2-rbac/US-012.md` → Out of Scope: "Role assignment UI (Epic 3)".
- The only `/users/…` call anywhere in `nexus-frontend/src` is `GET /v1/users/me` (`features/auth/auth.service.ts:192`, `features/dashboard/dashboard.component.ts:73`). No client calls `/users/{userId}/roles`.
- `shared/types/auth.ts` models `roles: readonly string[]` sourced from `/users/me`; that response (`MeResponse`) is **not** modified by this story.
- `core/http/api-error.interceptor.ts` maps RFC 7807 problem documents generically by `status`/`code`; there is no exhaustive error-code enum that would need `RBAC_002`/`RBAC_004` added.

**Conclusion: no file under `nexus-frontend/` changes. No Vitest, no Playwright, no lockfile touch.** (Which also sidesteps the known npm-Windows `@emnapi` lockfile-prune trap entirely.)

---

## 2. Database changes

### 2.1 Migration assumption — **CONFIRMED, with one caveat**

Read `nexus-backend/src/main/resources/db/migration/V5__rbac_schema.sql` in full. Existing migrations: `V1__baseline`, `V2__identity_schema`, `V3__add_password_hash_to_users`, `V4__auth_events_add_user_agent`, `V5__rbac_schema`.

`user_roles` (V5:63-89) already has **every column US-012 needs**: `id`, `user_id`, `role_id`, `tenant_id`, `assigned_by`, `assigned_at`, `revoked_at`, `active_key`. Plus:
- `uq_user_role_active UNIQUE (active_key)` — backs `RBAC_004`.
- `chk_user_roles_revoked_not_before_assigned CHECK (revoked_at IS NULL OR revoked_at >= assigned_at)`.
- `trg_user_roles_no_delete` (BEFORE DELETE → `SIGNAL SQLSTATE '45000'`) — Test Scenario 7 is a pure regression check, zero new code (as Assumption 1 stated).

`auth_events` (V2:76-90) already has the `metadata JSON` column and `idx_auth_events_event_type_created_at`. `event_type` is `VARCHAR(64)`, **not** a DB `ENUM` → adding two `AuthEventType` constants needs **no migration**.

**⇒ No new migration is required for table or column shape.**

### 2.2 Index analysis for the AC5 lockout guard — **F3**

Indexes that exist on `user_roles` today:

| Index | Source |
|---|---|
| `pk_user_roles (id)` | PK |
| `uq_user_role_active (active_key)` | explicit `CREATE UNIQUE INDEX`, V5:89 |
| implicit `(user_id)` | InnoDB auto-index for `fk_user_roles_user` |
| implicit `(role_id)` | InnoDB auto-index for `fk_user_roles_role` |
| implicit `(assigned_by)` | InnoDB auto-index for `fk_user_roles_assigner` |

**There is no index on `tenant_id`, and no composite covering `(tenant_id, role_id, revoked_at)`.**

Two possible query shapes for M1, with materially different consequences:

- **(A) Drive off `roles`** — `roles (tenant_id, name='TENANT_ADMIN')` hits the unique `uq_roles_tenant_name` → exactly one `role_id` → nested-loop into `user_roles` via the implicit FK index on `role_id` → residual filter `revoked_at IS NULL AND ur.tenant_id = :tenantId`. Because roles are tenant-scoped, the matched row set is *one tenant's admins* — a handful of rows. `FOR UPDATE` takes next-key locks confined to that `role_id` range. **Efficient and safe. No new index needed.**
- **(B) Drive off `user_roles.tenant_id`** — no usable index → **full table scan**, and under `FOR UPDATE` at REPEATABLE READ that means next-key locks on **every row in `user_roles`**, i.e. all revocations across all tenants serialise behind each other and unrelated assignments block. **This is a platform-wide availability hazard, not a slow query.**

**Recommendation:** `/design` must specify shape (A) and add an `EXPLAIN`-asserting integration test. *Optionally*, an additive `V6__user_roles_tenant_role_index.sql` creating `idx_user_roles_tenant_role_active (tenant_id, role_id, revoked_at)` would make shape (B) safe too and make (A) covering — but on the evidence it is **not required**, and "prefer boring tech / don't add what you don't need" applies. Recommend: **no new migration; enforce query shape (A) by test.** If `/design` disagrees, it is a new `V6__*.sql` (append-only, ADR 0003 — never edit V5).

Ancillary index checks:
- M2/M3 (`WHERE user_id = ? AND role_id = ?`) — served by the implicit `(user_id)` index; row count per user is ≤ a handful. No index needed.
- M4 (`GET`, `WHERE user_id = ? AND tenant_id = ? AND revoked_at IS NULL` + join `roles`) — same. No index needed.

`RbacSchemaMigrationIT#should_createExpectedIndexes_when_v5MigrationApplied` uses `contains(...)`, so a future added index would not break it. `should_createExpectedColumns_…` uses `containsExactly(...)` — **any added column would break it**, another reason to stay column-additive-free.

### 2.3 The `revoked_at >= assigned_at` CHECK — clock-skew hazard

`assigned_at` defaults to MySQL's `CURRENT_TIMESTAMP(6)`. If revocation writes an application-side `Instant`/`Clock` value, an app-server clock running behind the DB (or a revoke issued microseconds after an assign) can produce `revoked_at < assigned_at`, violating `chk_user_roles_revoked_not_before_assigned`. `ActiveAssignmentIT#should_rejectInsert_when_revokedAtBeforeAssignedAt` documents that MySQL error 3819 is **not** in Spring's `SQLErrorCodeSQLExceptionTranslator` table and surfaces as an untranslated `UncategorizedSQLException` via raw JDBC — i.e. a **500**, not a clean domain error.

**Recommendation for `/design`:** set `revoked_at` DB-side (`NOW(6)` / `CURRENT_TIMESTAMP(6)`) in the JPQL/native `UPDATE`, or clamp app-side to `max(now, assignedAt)`. Add an IT for assign-then-immediately-revoke.

### 2.4 `nexus_app` grants — **F1 (Critical) + one unverified assumption**

Current grants (identical in all three provisioning artifacts — `nexus-database/mysql/init/02-grants-post-schema.sql:30-36`, `nexus-backend/src/test/resources/nexus-app-grants.sql` + `TestcontainersConfiguration#nexusAppGrantsCallback:155-166`, and `docs/runbooks/nexus-app-provisioning.md`):

```
GRANT SELECT                 ON nexus.permissions      TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON nexus.roles            TO 'nexus_app'@'%';
GRANT SELECT, INSERT, DELETE ON nexus.role_permissions TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON nexus.user_roles       TO 'nexus_app'@'%';
GRANT UPDATE (revoked_at)    ON nexus.user_roles       TO 'nexus_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.users    TO 'nexus_app'@'%';
GRANT INSERT, SELECT         ON nexus.auth_events      TO 'nexus_app'@'%';
```

Every operation US-012 performs is nominally covered: `SELECT` on `roles`/`permissions`/`user_roles`/`users`, `INSERT` on `user_roles`, `UPDATE (revoked_at)` on `user_roles`, `INSERT` on `auth_events`. **⇒ No new grant is required — the ADR-0014 D6 / ADR-0015 D7 grant set is sufficient as written.**

**But two grant-adjacent hazards make this the highest-risk area of the story:**

> **F1 (Critical) — column-scoped `UPDATE` vs. Hibernate's default UPDATE statement.**
> `UserRole` marks only `assignedAt` and `activeKey` as `insertable=false, updatable=false`. `userId`, `roleId`, `tenantId`, and `assignedBy` are plain updatable mappings. A `findById → revoke(now) → save()` flow therefore makes Hibernate emit
> `UPDATE user_roles SET user_id=?, role_id=?, tenant_id=?, assigned_by=?, revoked_at=? WHERE id=?`
> — five columns, four of which `nexus_app` has **no** `UPDATE` privilege on. MySQL rejects this with `UPDATE command denied`. **Every existing `*IT` connects as the Testcontainers default `test` user (full DML), so this bug is invisible to the entire test suite and fails only in production.** `RbacDbPrivilegeHealthIndicator` deliberately checks only for over-grant (`DELETE`), so it would not catch it either.
>
> **`/design` must mandate one of:** (a) a JPQL bulk `UPDATE UserRole ur SET ur.revokedAt = :now WHERE ur.id = :id AND ur.revokedAt IS NULL` — **recommended**, matches `UserRole`'s own Javadoc ("set via a targeted UPDATE, never load-mutate-save"), matches `ActiveAssignmentIT`'s production-intent comment, and returns an affected-row count that doubles as the optimistic guard for the `404`-on-already-revoked rule (there is no `@Version` on `UserRole`); (b) `@DynamicUpdate` on the entity; or (c) `updatable = false` on the four immutable columns. (a) is the only option that is both minimal and self-documenting.
>
> **Mandatory new test:** a privilege-level IT connecting **as `nexus_app`** that performs a real revocation. The pattern already exists — `identity/infrastructure/persistence/AuthEventsPrivilegeAppendOnlyIT.java`.

> **Unverified assumption — locking reads under a column-scoped grant.** MySQL requires, for `SELECT … FOR UPDATE`, the `SELECT` privilege *plus at least one of* `DELETE`, `LOCK TABLES`, or `UPDATE`. `nexus_app` holds `UPDATE` on `user_roles` only at **column** scope, and no `DELETE`/`LOCK TABLES` at all (by design — `DELETE` is exactly what `RbacDbPrivilegeHealthIndicator` treats as drift). Whether MySQL 8.4 accepts a column-scoped `UPDATE` grant as satisfying that requirement is **not established anywhere in this codebase and must be empirically verified**, not assumed. If it does not, Resolution 8's `FOR UPDATE` guard fails in production with a privilege error while passing every IT. **Action: add this to the same `nexus_app` privilege IT above, before `/design` finalises the locking strategy.** If it fails, the fallbacks are `GRANT LOCK TABLES` (widens surface, needs an ADR) or a lock-free alternative (e.g. a conditional `UPDATE … WHERE (SELECT COUNT…) > 1` pattern).

### 2.5 Data migration

**None.** No existing row is reshaped, backfilled, or reinterpreted. No expand/contract needed. All schema interaction is DML on an existing, unchanged schema.

---

## 3. API changes

### 3.1 New endpoints (3) — all additive

| Method | Path | Permission (`@RequiresPermission`) | Success | AC |
|---|---|---|---|---|
| `POST` | `/api/v1/users/{userId}/roles` | `user:write` | `201` + assignment body | AC1 |
| `GET` | `/api/v1/users/{userId}/roles` | `user:read` | `200` + active assignment list | AC3 |
| `DELETE` | `/api/v1/users/{userId}/roles/{roleId}` | `user:write` | `204` no body | AC2 |

Paths match the EPIC-002 API table (`docs/story/2-rbac/EPIC-002.md:144-146`) exactly. `/api/v1` prefix and `@RequestMapping("/api/v1/users")` match `UserProfileController`. **No versioning strategy change** — v1 is new surface, not a modification.

Request/response *shapes* are deliberately left to `/design` (Gaps 2, 3). Two constraints this analysis fixes:
- `POST` body is `{ "roleId": "<uuid>" }` (AC1, verbatim). `assigned_by` **must not** appear in the body (FR2 / threat T-S2) — enforce by simply not modelling the field.
- `GET` needs `roles.name`, so its projection joins `roles` (§7).

### 3.2 Error contract (all reuse existing handlers — zero new handler code)

| Condition | Status | Code | Mechanism |
|---|---|---|---|
| Missing `user:write`/`user:read` | 403 | `RBAC_001` | Existing `@RequiresPermission` → `InsufficientPermissionException` → existing handler (`GlobalExceptionHandler:145-162`). Includes `requiredPermission` + `nexus.rbac.permission_denied` counter. |
| Cross-tenant target (AC4, all 3 verbs per Res. 6) | 403 | `RBAC_001` *(recommended)* | Throw `InsufficientPermissionException` from the service → inherits the WARN log, the `reason`/`requiredPermission` fields, and the metric **for free**. Alternative (a dedicated rbac exception) would need a new handler and lose the metric. `/design` decides; recommend reuse. |
| Non-admin grants `TENANT_ADMIN` (AC8) | 403 | `RBAC_001` | Same. Consider a distinct `DenialReason` constant so the metric can separate self-escalation attempts from ordinary denials (see §9). |
| Last active `TENANT_ADMIN` revocation (AC5) | 409 | `RBAC_002` | New `rbac.domain.LastAdminRoleException extends ConflictException` → **existing** `handleConflict` (`GlobalExceptionHandler:58-62`). |
| Duplicate active assignment | 409 | `RBAC_004` | New/plain `ConflictException` → same existing handler. `RBAC_003` reserved for US-015 — do not use. |
| Unknown `userId` / `roleId` | 404 | *(code TBD by `/design`)* | Existing `ResourceNotFoundException` → existing `handleNotFound`. |
| `DELETE` on already-revoked assignment | 404 | *(same)* | Res. 7 — explicitly **not** an idempotent `204`. |
| Malformed/missing `roleId` in body | 400 | `VALIDATION_FAILED` | Existing `handleBodyValidation` via `@Valid` + `@NotNull`. Covers Gap 4 with no new code. |
| Malformed `{userId}`/`{roleId}` path UUID | 400 | — | Spring's `MethodArgumentTypeMismatchException` currently falls through to `handleUnexpected` → **500**. `/design` should confirm the desired status; a `@ExceptionHandler` addition would be new `common.web` code, so prefer `UUID` `@PathVariable` binding + accepting Spring's default, or explicitly scope it out. **Minor open item.** |

All responses remain RFC 7807 with `code` + `traceId` (CLAUDE.md non-negotiable) — satisfied automatically by `GlobalExceptionHandler#problem`.

### 3.3 Breaking changes

**None.** Purely additive:
- No existing endpoint's path, method, request, or response changes.
- `MeResponse` and the JWT `JwtClaims` contract are untouched → **no `token_version` bump**, no `JwtClaimsContractTest` change.
- `AuthEventType` gains constants; existing wire names unchanged; `auth_events.event_type` is `VARCHAR`, so no DB-side compatibility concern and existing rows are unaffected.
- `AuthEventPort`, `SecureEventService`, `UserRoleQueryPort`, `PermissionCachePort` all keep their current signatures (the recommended new `UserRoleAssignmentPort` avoids widening `UserRoleQueryPort`).
- No frontend contract touched.

---

## 4. UI changes

**None.** See §1.6 for the verification. Downstream consumers (Epic 3 admin surface, and US-013's authors as future readers of `GET /users/{userId}/roles`) inherit this contract but require no work in this story.

---

## 5. Cross-context and dependency-direction impact

### 5.1 Current edge direction (verified by grep, both directions)

- `identity → rbac`: **exists** — `identity/infrastructure/security/JwtRs256Service.java:11-12` imports `rbac.application.RoleResolutionService` and `rbac.domain.ResolvedPermissions`.
- `rbac → identity`: **zero imports** in `src/main` today. (`RedisPermissionCacheAdapter`'s Javadoc mentions `RedisRateLimitStore` via a fully-qualified `{@link}` only — not an import, invisible to both the compiler and ArchUnit.)

### 5.2 Post-US-012 direction — preserved

`rbac.application.port.out` **declares** `RbacAuditPort` + `UserDirectoryPort`; `identity.infrastructure.{audit,persistence}` **implements** them. So:
- `rbac.application` → depends only on its own port interfaces. Still zero `identity` imports.
- `identity.infrastructure` → depends on `rbac.application.port.out`, reinforcing the existing `identity → rbac` direction.

**No cycle is introduced.** Resolution 1 and 4 hold up under verification.

### 5.3 ArchUnit conformance — checked rule by rule

Only two ArchUnit suites exist: `architecture/HexagonalArchitectureTest.java` and `architecture/LoggingStandardsTest.java` (the latter is logging-only and irrelevant here).

| Rule | US-012 verdict |
|---|---|
| `domain_must_not_depend_on_outer_layers` | ✅ New `rbac.domain` exceptions depend only on `common.domain.ConflictException`. |
| `application_must_not_depend_on_adapters` | ✅ `RoleAssignmentService` depends on `..port.out..` interfaces only. The adapters residing in `identity.infrastructure` are *outer* classes and are not matched by this rule. |
| `domain_must_not_use_spring_web` | ✅ |
| `domain_and_application_must_not_depend_on_redis` | ✅ Cache eviction goes through `PermissionCachePort` (already the case). |
| **`domain_and_application_must_not_depend_on_spring_security`** | ⚠️ **The one rule that constrains the design.** `RoleAssignmentService` **must not** accept an `Authentication` parameter and **must not** call `AuthenticatedRequestDetails.fromAuthentication(Authentication, String)` — the call's parameter type is a direct ArchUnit dependency on `org.springframework.security.core.Authentication`. **The controller must unwrap the principal and pass plain `UUID`/`String` values into the service.** Throwing `common.security.InsufficientPermissionException` from the service is fine — ArchUnit records only the direct reference, not the class's Spring Security supertype — but this is subtle enough that it should be validated by an actual `./mvnw verify -DskipITs` immediately after the first service skeleton lands, not assumed. |
| `only_jwtAuthenticationFilter_sets_authentication_details` | ✅ US-012 never calls `setDetails`. |
| `no_field_injection` / `no_standard_streams` / `no_java_util_logging` | ✅ Constructor injection + SLF4J throughout. |

**No ArchUnit rule is tripped by the two new ports.** (Answers investigation item 5 directly.)

**Optional, low-cost recommendation for `/design`:** there is currently **no** ArchUnit rule preventing `rbac` from importing `identity` — the direction discipline is documentation-only, and Risk R1/R9 exist precisely because a previous story (US-010 code review) let this drift. A single rule — `noClasses().that().resideInAPackage("..rbac..").should().dependOnClassesThat().resideInAPackage("..identity..")` — would mechanically lock in Gate 1 Resolutions 1 and 4 at effectively zero cost. Flag as an "ADR Required?" — no, it encodes an already-accepted decision, so it is a design choice, not a new one.

### 5.4 Tenant-ID type boundary

`AuthenticatedRequestDetails.tenantId()` is a **`String`**, explicitly documented as opaque: "no trimming, case-folding, or comparison is performed here (design §B5)". `UserRole.tenantId`, `Role.tenantId`, and `User.tenantId` are all **`UUID`**. The controller must therefore parse with `UUID.fromString(...)` and **fail closed** on a parse failure (403 via `InsufficientPermissionException(…, DenialReason.MISSING_TENANT)` — not an unhandled 500 through `handleUnexpected`). Provenance is safe in practice — `JwtRs256Service` mints the claim from `User.getTenantId().toString()` (canonical lowercase) — but the parse must still be defensive, matching `AuthenticatedRequestDetails`'s own fail-closed posture.

---

## 6. Security impact

**New attack surface:** three authenticated endpoints, the first genuinely privileged (tenant-admin) surface on the platform. This story is the sole control for threat **T-E1** (self-escalation to `TENANT_ADMIN`), rated Critical in US-009's threat model.

| Concern | Analysis |
|---|---|
| **Authn** | Unchanged. `SecurityConfig.anyRequest().authenticated()` already covers these paths; `JwtAuthenticationFilter` unchanged. |
| **Authz — coarse** | `@RequiresPermission("user:write"/"user:read")` (US-011). **`TenantAwarePermissionEvaluator` performs no tenant or resource comparison** — it checks JWT `permissions[]` membership only. AC4/AC8 are therefore **entirely** service-layer logic. This is restated from the requirements doc because it is the single most load-bearing fact in the design. |
| **Authz — tenant isolation (AC4, Res. 6)** | Applies uniformly to `POST`, `GET`, `DELETE`. Caller tenant sourced **exclusively** from the JWT; target tenant loaded **fresh from the DB** (`UserDirectoryPort.findTenantId` for the user, `Role.tenantId` for the role). Never from request input. |
| **Authz — AC8 (`TENANT_ADMIN` grants `TENANT_ADMIN`)** | **F6 (High):** the check must be a **fresh DB read** (M5), not the JWT's `roles[]` claim. The JWT is minted at login/refresh and lives ~15 min; an admin whose role was revoked 30 seconds ago still carries `TENANT_ADMIN` in `roles[]` and would pass a claim-based check — a live privilege-escalation window. Note `RoleResolutionService` already re-reads roles live at mint time for exactly this class of reason; US-012 must do the same at check time. |
| **IDOR** | `{userId}` is client-supplied. Mitigated by the AC4 tenant check on all three verbs. `{roleId}` likewise. |
| **Audit integrity (T-R1/T-S2)** | `assigned_by`/`revoked_by` sourced from `authentication.getPrincipal()` only. `auth_events` is append-only at the DB-trigger *and* privilege level (`GRANT INSERT, SELECT` only) — RBAC events inherit both protections with no new mechanism (matches US-014 AC3). |
| **Soft-delete integrity** | `trg_user_roles_no_delete` + absence of `DELETE` in `nexus_app`'s grants — both pre-existing, both regression-tested. |
| **JSON injection into `auth_events.metadata`** | New vector via `role_name` (tenant-controlled after US-015). See F5 — escaping is mandatory. |
| **Anti-enumeration** | Not applicable — these are authenticated admin endpoints, not the `/forgot`-class endpoints CLAUDE.md's timing-equalisation rule governs. `404` vs `403` for a cross-tenant `userId` does leak existence across tenants; Res. 6 + Res. 7 together mean cross-tenant → **403** and nonexistent → **404**, which technically distinguishes "exists in another tenant" from "doesn't exist". `/design` should decide whether to collapse cross-tenant to `404` for uniformity. **Minor open item, worth one line in the threat model.** |
| **Rate limiting** | Out of scope (Res. 10). No cross-cutting limiter exists beyond `LoginRateLimitFilter` (login/refresh only). Accepted gap; revisit on observed abuse. |

**Threat-model refresh needed at Gate 2** (`03b-threat-model.md`): the new items worth modelling are the AC5 `FOR UPDATE` lock-scope DoS (F3-B), the stale-JWT AC8 bypass (F6), `role_name` JSON injection (F5), and the 403/404 existence-oracle above.

---

## 7. Performance impact

| Path | Analysis |
|---|---|
| **`POST` (assign)** | Reads: target user tenant (PK lookup, `UserDirectoryPort`), role (PK lookup), existing `(userId, roleId)` row (M2, `user_id` index), AC8 admin check when the target role is `TENANT_ADMIN` (M5). Write: 1 `INSERT`. All index-served, single-digit rows. Comfortably inside the epic's 200 RPS / p95 < 300 ms figure. |
| **`DELETE` (revoke)** | Same reads + M1's locking count + 1 `UPDATE`. **The `FOR UPDATE` is the hot spot** — see F3. With query shape (A) the lock set is one tenant's admin rows; with shape (B) it is the whole table. This is the single most important performance decision in the story. |
| **`GET` (list)** | **N+1 risk (Medium):** the naive implementation loops assignments and calls `roleRepository.findById(roleId)` per row to obtain `roles.name`. Must instead be a **single JPQL projection joining `UserRole` + `Role`**, exactly like the existing `findActiveRoleNames` (`JpaUserRoleRepository:26-35`). No pagination requirement (Gap 3) — acceptable while the realistic per-user assignment count is ≤ 2, but `/design` should note the unbounded-list contract. |
| **Cache touches** | One `PermissionCachePort.evict(tenantId, userId)` per successful write = **two Redis `DEL`s** (roleset + permset keys). Best-effort, post-commit (Res. 9); `RedisPermissionCacheAdapter` already fails open with a WARN on any Redis error, so a Redis outage costs nothing on this path. |
| **Audit write** | One extra `INSERT` into `auth_events` in a `REQUIRES_NEW` transaction (a second DB round-trip + second connection from the pool per successful write). Pre-existing, well-characterised cost — `AuthEventLoadIT` / `AuthEventLoadSmokeIT` already benchmark this path. |
| **Connection-pool note** | `REQUIRES_NEW` borrows a second connection while the first is still held. This is the established pattern across `identity`, but US-012 is the first place it sits behind a **row lock** (`FOR UPDATE`), lengthening the window in which two connections are held simultaneously. Worth a line in `/design`'s observability plan; not a blocker. |

---

## 8. Integration impact

| Integration | Impact |
|---|---|
| **MySQL** | DML only on existing tables. No schema change. See §2.4 grant hazards. |
| **Redis** | Already fully wired (`spring-boot-starter-data-redis`, `RedisPermissionCacheAdapter`, docker-compose service, Testcontainers `redis:7.4-alpine` in `TestcontainersConfiguration#redisContainer`). US-012 activates the previously dormant `evict` path. **No new infrastructure.** |
| **Audit pipeline (US-008)** | Reused end-to-end and unchanged: `SecureEventService` → `AuthEventPort` → `JpaAuthEventAdapter` → `AuthEventRetryBuffer` (bounded, backed-off retry; `AuditLane` priority routing). RBAC events route to the standard lane. |
| **JWT / token issuance (US-010)** | Unaffected. `RoleResolutionService`'s live-role-set fingerprint already guarantees an assignment is reflected on the very next login/refresh **even without** cache eviction — see F4. |
| **US-014** | Becomes an extend/verify story (Res. 2). Its AC1/AC2 field lists are already satisfied by Res. 3's superset; its AC4 (`ROLE_ASSIGNMENT_DENIED`) remains US-014 scope. |
| **US-015** | Inherits this story's tenant-scoping and cross-context port pattern; `RBAC_003` stays reserved. |
| **Epic 3** | This API is one of the two kickoff-gate deliverables. Contract must be stable at ship. |
| **Upstream/downstream services** | None — Nexus is a modular monolith; no external service boundaries are crossed. |

---

## 9. Observability impact

Not a formal `/design` deliverable at this phase, but the gaps must be recorded here so `/design` §9 can close them (Requirements Gap 5):

- `RBAC_002` and `RBAC_004` route through `handleConflict`, which logs at **DEBUG** and emits **no metric**. A tenant-lockout attempt (`RBAC_002`) is operationally interesting and would be invisible at production log levels. `/design` should either raise it or add a counter.
- AC8 self-escalation attempts: if they throw `InsufficientPermissionException`, they inherit the existing WARN log **and** the `nexus.rbac.permission_denied{permission, reason}` counter for free (`GlobalExceptionHandler:145-162`). **Adding a dedicated `DenialReason` constant** (e.g. `NOT_TENANT_ADMIN`) would make self-escalation attempts separately alertable via the existing `reason` tag with zero new metric plumbing. Strongly recommended — this is the story's most security-critical control and currently has no alerting story at all.
- `correlationId`/`traceId` propagation is already handled by `CorrelationIdFilter` + MDC and lands in `auth_events.metadata` as `traceId`.

---

## 10. Dependency changes

**None.** No new libraries, no version bumps, no license review.

Everything required is already on the classpath: Spring Data JPA, Spring Security (`@PreAuthorize` machinery + `AnnotationTemplateExpressionDefaults`), springdoc (`@Tag`/`@Operation`/`@ApiResponse`), Jakarta Bean Validation, `spring-boot-starter-data-redis`, Micrometer, Lombok, ArchUnit, Testcontainers (MySQL + Redis), AssertJ, Mockito.

---

## 11. Test impact

### 11.1 Existing infrastructure to reuse (investigation item 7)

There is **no shared `*IT` base class**; the codebase uses a *copied configuration convention* instead. Two established shapes, both directly applicable:

1. **Persistence/DB-level IT** — `@SpringBootTest` + `@Import(TestcontainersConfiguration.class)` + `@Tag("IT")`, autowiring the JPA repositories and a raw `JdbcTemplate`. Canonical examples in this exact package: `rbac/ActiveAssignmentIT.java`, `rbac/RbacSchemaMigrationIT.java`, `rbac/RoleUniquenessIT.java`, `rbac/UserRolesAppendOnlyIT.java`.
2. **End-to-end HTTP + security IT** — `@SpringBootTest(webEnvironment = RANDOM_PORT)` + `@Import({TestcontainersConfiguration.class, GuardedTestControllerConfig.class})` + `@ActiveProfiles("test")` + a `RestTemplate` with a no-op `DefaultResponseErrorHandler`, minting real tokens via `JwtPort#issue`. **`rbac/security/CrossTenantPermissionIT.java` is the single best template for US-012's security tests** — it already seeds a user in the bootstrap tenant with the seeded `MEMBER` role plus a custom role in a second tenant, which is precisely the AC4 fixture shape.

Other reusable assets:
- `TestcontainersConfiguration` — MySQL 8.4 + Redis 7.4 containers, Flyway pinned on, `ddl-auto=validate`, `nexus_app` grants applied via an `AFTER_MIGRATE` Flyway callback, stub `MailSenderPort`.
- **Shared-context/shared-schema caveat (important):** all `*IT` classes using the identical `@SpringBootTest + @Import(TestcontainersConfiguration.class)` combination share **one** cached Spring context and therefore **one** MySQL schema for the whole run. `RbacSchemaMigrationIT`'s Javadoc documents this at length. US-012's fixtures **must** create roles with `is_system_role = false` and use randomised names/emails, or they will break `RbacSchemaMigrationIT`'s scoped seed counts.
- Seeded literals for fixtures (V5 header): bootstrap tenant `00000000-0000-7000-8000-000000000001`, `TENANT_ADMIN` `019f6839-1810-…-00000000000a`, `MEMBER` `019f6839-1811-…-00000000000b`, `user:write` `019f6839-1803-…-000000000004`, `user:read` `019f6839-1802-…-000000000003`.
- Concurrency harness: `RefreshTokenRotationIT#concurrent_rotation_single_winner` and `ActiveAssignmentIT#should_allowExactlyOneWinner…` (8-thread `ExecutorService` + `CyclicBarrier`, 5 s barrier / 15 s termination). **This is the pattern for the AC5 TOCTOU test** — note `ActiveAssignmentIT`'s Javadoc explicitly warns that `SecureEventServiceConcurrencyTest` is *not* a real concurrency harness despite prior docs pointing at it.
- `common/security/AuthenticationTestFixtures` (package-private to `common.security`; an rbac equivalent will be needed or the fixture widened).
- `support/web/GuardedTestController` + `GuardedTestControllerConfig` for `@RequiresPermission` harnesses.
- MockMvc + H2 controller-slice pattern: `common/security/RequiresPermissionWebTest`, `config/SecurityConfigWebTest`.

### 11.2 New tests required

**Unit:** `RoleAssignmentServiceTest` (Mockito, all 8 ACs + error branches), `LastAdminRoleExceptionTest` / `DuplicateRoleAssignmentExceptionTest` (see the known JaCoCo `toString()`/domain-coverage trap), `UserRoleControllerTest` (MockMvc slice), `RbacAuthEventAdapterTest`, `JpaUserDirectoryAdapterTest`, metadata-JSON-escaping test.

**Integration (`*IT`, Testcontainers MySQL):**
- `RoleAssignmentIT` — Test Scenarios 1, 2 (201/204, `revoked_at` set, row not deleted), reassign-after-revoke, duplicate → `RBAC_004`, 404 paths.
- `LastAdminLockoutIT` — Scenario 4 (`409` + `RBAC_002`) **plus** the concurrent two-admin TOCTOU test that Resolution 8 exists to satisfy.
- `RoleAssignmentSecurityIT` — Scenarios 3 and 8 (cross-tenant on **all three** verbs per Res. 6; non-admin grants `TENANT_ADMIN` → 403), modelled on `CrossTenantPermissionIT`.
- `RoleAssignmentCacheIT` — Scenario 5, asserting the **actual** Redis keys (see F4), not AC6's literal string.
- `RoleAssignmentAuditIT` — Scenario 6, asserting `ROLE_ASSIGNED`/`ROLE_REVOKED` rows with the full Res. 3 metadata payload.
- **`UserRolesPrivilegeIT` (NEW, mandatory)** — connects **as `nexus_app`** (pattern: `AuthEventsPrivilegeAppendOnlyIT`) and performs a real revocation + the `SELECT … FOR UPDATE` guard. **This is the only test that can catch F1 and the §2.4 locking-read assumption.** Without it, both bugs ship.
- Optional: an `EXPLAIN`-asserting test pinning the M1 query plan (F3).

**Modified tests:**
- `identity/domain/AuthEventTypeTest.java` — `should_defineAllTwentyConstants_when_valuesCalled` asserts `hasSize(20)` and an exhaustive name list. **Must become 22** with `ROLE_ASSIGNED`/`ROLE_REVOKED` added. (`should_returnFalse_when_isPriorityCheckedOnAllNonPriorityTypes` uses `EnumSource(EXCLUDE)` and auto-covers the new constants, correctly asserting they are non-priority.)
- `rbac/RbacSchemaMigrationIT` — only if `/design` adds the optional `V6` index (`contains(...)` assertions would still pass; an added assertion would be the deliberate change).

### 11.3 Coverage gates (`nexus-backend/pom.xml`)

JaCoCo enforces BUNDLE line ≥ **0.80**, `*.domain.*` ≥ **0.90**, `*.application.*` ≥ **0.85**, `*.interfaces.rest.*` ≥ **0.80**. `RoleAssignmentService` will be one of the larger application-layer classes in the codebase, with many error branches — the 0.85 gate needs branch-level unit coverage of every AC's failure path, not just happy paths. Budget for it in `/tasks`.

---

## 12. Backward compatibility assessment

| Dimension | Verdict |
|---|---|
| HTTP API | ✅ Purely additive; no existing endpoint touched. |
| JWT / `JwtClaims` | ✅ Unchanged → **no `token_version` bump**, no contract-test change. |
| `MeResponse` / `/users/me` | ✅ Unchanged → frontend unaffected. |
| Database schema | ✅ No DDL (or, if `/design` opts in, one additive index only — ADR 0003 compliant). Existing rows unaffected. |
| `auth_events` data | ✅ Two new `event_type` string values; column is `VARCHAR(64)`; existing consumers/queries unaffected. |
| Java port interfaces | ✅ `AuthEventPort`, `SecureEventService`, `UserRoleQueryPort`, `PermissionCachePort` all keep current signatures (given the recommended separate `UserRoleAssignmentPort`). |
| `nexus_app` grants | ✅ No change required — but see F1/§2.4 for the *usage* constraints those grants impose. |
| Rollback | ✅ Trivially reversible: no migration, no data reshaping. Reverting the code fully reverts the feature. Any `user_roles` rows written while live remain valid data. |

**Overall: non-breaking.**

---

## 13. Top risks

| # | Risk | Sev | Owner / mitigation |
|---|---|---|---|
| **R-1** | **Column-scoped `UPDATE (revoked_at)` grant rejects Hibernate's default multi-column `UPDATE`** — production-only failure, invisible to the entire IT suite (which runs as `test`) and to `RbacDbPrivilegeHealthIndicator` (which only checks for over-grant). | **Critical** | `/design`: mandate a JPQL bulk `UPDATE … SET revokedAt` (or `updatable=false` on the four immutable columns). `/tasks`: add `UserRolesPrivilegeIT` running as `nexus_app`. |
| **R-2** | **`@RequiresPermission` silently unenforced** if a handler is copied from `UserProfileController`'s package-private style. Result: an unguarded tenant-admin endpoint with no error, no log, no failing test. | **Critical** | `/design`: state "all handlers `public`, non-`final`". `/tasks`: a negative-control 403 test **per endpoint** (the only mechanism that catches this). Code-review checklist item. |
| **R-3** | **`SELECT … FOR UPDATE` locks the whole `user_roles` table** if the AC5 query drives off the unindexed `tenant_id`, serialising all revocations platform-wide. | **High** | `/design`: pin query shape (A) — drive off `roles (tenant_id, name)`. Add an `EXPLAIN`-asserting test. Reconsider the optional `V6` composite index only if (A) proves impractical. |
| **R-4** | **`SELECT … FOR UPDATE` may itself be denied** — MySQL requires SELECT + one of DELETE/LOCK TABLES/UPDATE for a locking read; whether a *column-scoped* `UPDATE` grant qualifies is unverified. Same production-only blindness as R-1. | **High** | Verify empirically in `UserRolesPrivilegeIT` **before** `/design` finalises the locking strategy. Fallbacks: `GRANT LOCK TABLES` (needs an ADR — widens the least-privilege surface) or a lock-free conditional-`UPDATE` guard. |
| **R-5** | **AC8 checked against the stale JWT `roles[]` claim** instead of a fresh DB read → a just-revoked admin retains grant power for up to a full token lifetime. Direct T-E1 privilege escalation. | **High** | `/design`: AC8 uses repository method M5 (live read), never `authentication.getAuthorities()`. Dedicated security test with a revoked-then-still-holding-token actor. |
| **R-6** | **`role_name` JSON-injection into `auth_events.metadata`** — tenant-controlled free text after US-015, and the existing escaper (`RequestContext#jsonEscape`) is not reachable from the new payload builder. | **Medium** | `/design`: build metadata in `RbacAuthEventAdapter` from a typed record, replicating RFC 8259 control-character escaping. Unit-test with adversarial `role_name` values. |
| **R-7** | **Cache-key drift between spec and implementation** — AC6, US-012's Technical Notes, and EPIC-002 all name `permissions:{tenant_id}:{user_id}`; the shipped adapter uses `{prefix}:rbac:roleset:{t}:{u}` **and** `{prefix}:rbac:permset:{t}:{u}`. Calling `PermissionCachePort.evict(...)` satisfies AC6's *intent* and needs no code change, but a test written against the AC's literal key text will pass vacuously (deleting a key that never existed). | **Medium** | `/design`: document the real keys and correct the story/epic text. `/tasks`: Scenario 5's IT asserts both actual keys. Also note that `RoleResolutionService`'s live-role fingerprint already makes assignments visible on the next refresh **without** eviction — so eviction is a latency optimisation plus coverage for permission-set (not role-set) changes, not the correctness mechanism. Don't over-engineer it. |
| **R-8** | **`revoked_at < assigned_at` CHECK violation under clock skew** (assign-then-immediately-revoke) surfaces as an untranslated MySQL 3819 → **500**, not a clean domain error. | **Medium** | `/design`: set `revoked_at` DB-side (`NOW(6)`) or clamp app-side. Add an assign-then-revoke IT. |
| **R-9** | **`TENANT_ADMIN` resolved by hardcoded seeded UUID** rather than by `(tenant_id, name)` — works in the bootstrap tenant, silently disables AC5 and AC8 for every tenant Epic 3 creates. The story's own Technical Note (`WHERE role_id = TENANT_ADMIN`) invites exactly this mistake. | **Medium** | `/design`: resolve by `roles.name = 'TENANT_ADMIN' AND roles.tenant_id = :tenantId`. Add a second-tenant test that is not the bootstrap tenant. |
| **R-10** | **ArchUnit `domain_and_application_must_not_depend_on_spring_security`** trips if `RoleAssignmentService` takes an `Authentication` or calls `AuthenticatedRequestDetails.fromAuthentication(...)`. | **Low** | `/design`: controller unwraps; service takes plain `UUID`/`String`. Run `./mvnw verify -DskipITs` immediately after the first service skeleton. |
| **R-11** | **`GET` N+1** if role names are fetched per assignment; and unbounded list (no pagination, Gap 3). | **Low** | `/design`: single JPQL projection join, mirroring `findActiveRoleNames`. Document the unbounded-list contract. |
| **R-12** | **Malformed path UUID → 500** via `MethodArgumentTypeMismatchException` falling through to `handleUnexpected`. | **Low** | `/design`: confirm desired status; either accept and document, or scope explicitly. Avoid adding `common.web` handler code for it in this story. |

---

## 14. Open items handed to `/design` (Gate 2)

Not Gate-1 re-litigation — these are genuine design-level choices this analysis surfaced and deliberately did not decide:

1. Exact M1 locking query (Res. 8), including `FOR UPDATE OF` scoping so `roles` is not needlessly locked — constrained by R-3/R-4.
2. Revocation write mechanism: JPQL bulk `UPDATE` (recommended) vs. `@DynamicUpdate` vs. `updatable=false` — constrained by R-1.
3. New port shape: separate `UserRoleAssignmentPort` (recommended) vs. widening `UserRoleQueryPort`.
4. `RBAC_004` carrier: dedicated `DuplicateRoleAssignmentException` (recommended) vs. bare `ConflictException`.
5. Exception type for AC4/AC8 403s: reuse `InsufficientPermissionException` (recommended — inherits WARN log + `nexus.rbac.permission_denied` metric) vs. a new rbac exception.
6. Metadata-JSON construction site and escaping (F5).
7. `GET` response DTO fields + the unbounded-list decision (Gaps 2, 3).
8. 403-vs-404 for a cross-tenant `userId` (cross-tenant existence oracle).
9. Whether to add the ArchUnit `rbac ↛ identity` rule (recommended, near-zero cost, mechanically locks in Resolutions 1 and 4).
10. Whether `ROLE_ASSIGNED`/`ROLE_REVOKED` belong in `AuthEventType.PRIORITY` (recommend: no, defer to US-014).
11. Whether to ship without a `@ConditionalOnProperty` feature flag (story says no flag; would be the first ungated controller — record the deviation explicitly).
12. Observability: raise `RBAC_002` above DEBUG and/or add a counter; add a `DenialReason` constant for AC8 self-escalation attempts (§9).

---

## 15. Files touched — quick index (all absolute)

**New — backend only:**
```
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\RoleAssignmentService.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\RbacAuditPort.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\RbacAuditEvent.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\UserDirectoryPort.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\UserRoleAssignmentPort.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\LastAdminRoleException.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\DuplicateRoleAssignmentException.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\infrastructure\persistence\JpaUserRoleAssignmentAdapter.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\UserRoleController.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\dto\AssignRoleRequest.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\interfaces\rest\dto\RoleAssignmentResponse.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\identity\infrastructure\audit\RbacAuthEventAdapter.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\identity\infrastructure\persistence\JpaUserDirectoryAdapter.java
```

**Modified:**
```
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\infrastructure\persistence\JpaUserRoleRepository.java   (+ M1..M5)
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\identity\domain\AuthEventType.java                          (+2 constants)
C:\entomo\ai\nexus\nexus-backend\src\test\java\com\example\nexus\identity\domain\AuthEventTypeTest.java                      (20 → 22)
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\domain\UserRole.java                                   (only if /design picks entity-dirty-check revocation)
```

**Read but unchanged (key evidence):**
```
C:\entomo\ai\nexus\nexus-backend\src\main\resources\db\migration\V5__rbac_schema.sql
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\common\web\GlobalExceptionHandler.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\common\security\AuthenticatedRequestDetails.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\common\security\RequiresPermission.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\common\domain\RequestContext.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\config\SecurityConfig.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\config\MethodSecurityConfig.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\infrastructure\cache\RedisPermissionCacheAdapter.java
C:\entomo\ai\nexus\nexus-backend\src\main\java\com\example\nexus\identity\application\service\SecureEventService.java
C:\entomo\ai\nexus\nexus-backend\src\test\java\com\example\nexus\architecture\HexagonalArchitectureTest.java
C:\entomo\ai\nexus\nexus-backend\src\test\java\com\example\nexus\TestcontainersConfiguration.java
C:\entomo\ai\nexus\nexus-backend\src\test\java\com\example\nexus\rbac\security\CrossTenantPermissionIT.java
C:\entomo\ai\nexus\nexus-database\mysql\init\02-grants-post-schema.sql
```

**Frontend:** no files.

---

### Cross-references
- `docs/features/US-012/01-requirements.md` — Gate 1 approved, §11 Resolutions applied throughout
- `docs/story/2-rbac/US-012.md`, `docs/story/2-rbac/EPIC-002.md` — source ACs, API table (lines 144-146), US-014/US-015 scope boundaries
- `docs/adr/0003` (Flyway append-only), `0013` (RBAC data model + enforcement contract), `0014` (bootstrap tenant + DB grants D6), `0015` (threat-model hardening D7), `0016` (Redis cache D3/D4/D6)
- `docs/features/US-009/03b-threat-model.md` — T-E1, T-S2, T-R1, T-T1, T-T3, T-E6
- `docs/features/US-010/06-code-review.md` — prior MEDIUM finding on `rbac`/`identity` coupling (now resolved by Res. 1/4)
- `SECURITY.md` §3.1 — `RBAC_001` response shape and the `@RequiresPermission` visibility/self-invocation pitfalls (R-2)
- `docs/TESTING.md` — Testcontainers-MySQL-only policy for `*IT`
