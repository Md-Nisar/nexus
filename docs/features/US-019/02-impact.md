# US-019 — Impact Analysis (Phase 2)

**Story:** Prerequisites for the RBAC Access Management UI (US-020 enablers)
**Epic:** EPIC-002 — RBAC Foundation
**Gate 1 basis:** `docs/features/US-019/01-requirements.md` §13a "Gate 1 decisions (2026-10-19)". These decisions are binding here and are not reopened: `user:directory:read` gates the directory (B1, B2), `user:read` unchanged; `isSensitive` is a static set in `Permissions`; B7 ships with an allow-list and `THROTTLED` becomes a real 429 + `Retry-After`; `ETag`/`If-Match` on the permission replace (428 missing, 412 stale, 409 business only); the set lock is taken when the before or after state of the role is admin-defining (to be confirmed by the Gate 2 threat model); B4 is an `rbac` controller under the us019 flag; A1 = parent `authGuard` + child `permissionGuard`; A11 = hand-written DTOs + contract test; C4 = Playwright against a compose backend, skips count as failures; S0–S5 split.
**Method:** every claim below was checked against the code on `feature/US-019` (base `main` @ `2962b0e`). **[VERIFIED]** = re-read in code for this document. **[REPORTED]** = taken from `00-discovery.md` or `01-requirements.md` and not re-checked. **[INFERENCE]** = my reading, not stated in code or a source. **[UNVERIFIED]** = could not be confirmed from the repository. Where this document contradicts the requirements, the discovery note or the story, it says so and cites the code.
**Precedent followed:** `docs/features/US-018/02-impact.md` (structure; verified findings kept apart from assumptions).
**Scope guard:** this is impact, not design. No class designs, DDL or endpoint schemas; options are listed as Gate 2 questions (§15).
**No PII.** People are referred to by role only. Dev-seed credentials in the code are not repeated.

---

## 0. Executive summary

| Question | Answer |
|---|---|
| Backend modules | `rbac` (all four layers: B3–B8, B4's controller, B10), `identity` (application + infrastructure.persistence + interfaces.rest for B1/B2; infrastructure.seed for C1; infrastructure.security for B7's throttle adapter; domain `AuthEventType` if Q-N1 audit), `common.security` (`Permissions`, `DenialReason`), `common.web` (`GlobalExceptionHandler`), `common.domain` (412/428 exceptions; paging types if Q-N9 moves them), `config` (`SecurityConfig` CORS, `OpenApiConfig`) |
| Frontend | `app.routes.ts`, `app.html`/`app.ts`, new shell under `core`/`shared`, `core/guards/*` (A1, A10), `shared/ui/*` (9 new wrappers, `NxTable`, `NxDialog`, `NxAnnouncer`), `shared/types/permission.ts` (new union member + labels), `features/dashboard`, `shared/pages/access-denied`, `core/config/app-config.ts` (A9), `app.config.ts` (A8 `TitleStrategy`), new RBAC/directory DTO types (A11), `e2e/` fixtures and `e2e/access-management/` |
| Flyway | Highest today is **V10** (`V10__rbac_roles_drop_tenant_name_unique.sql`) **[VERIFIED]**. **Next is V11**: seed `user:directory:read` with the mandatory B7 footer, **A-V9 variant** (`db/templates/permission-migration-footer.sql:58-82`). Data only, additive, no DDL. Any further migration (an index, a version column for the ETag) is a Gate 2 option, not a requirement (§11) |
| `nexus_app` grants | **No change expected.** B8 needs `INSERT`/`DELETE` on `role_permissions`, already granted (`02-grants-post-schema.sql:33`). **One to verify:** if B8 takes a locking read on `roles` (`FOR UPDATE`), MySQL's privilege requirement for locking reads against a column-scoped `UPDATE` grant (`:39`) must be proven under `nexus_app`, not the Testcontainers superuser (§5.4) |
| Contract changes | Additive fields on `RoleResponse` (B6) and `PermissionResponse` (B5), additive `reason` on the `RBAC_001` body (B7). **Wire-visible behaviour change:** throttled assign/revoke goes 403 → 429 (B7). New endpoints: B1, B2, B3, B4, B8. New headers: `ETag`, `If-Match` (CORS must change, §6.3) |
| New dependencies | **Backend: none.** **Frontend: possibly one dev dependency** for unit-level axe (G8); `@axe-core/playwright` is already a devDependency (`package.json:50`) **[VERIFIED]**. `axe-core` is MPL-2.0 (already present transitively) **[INFERENCE: license from upstream, not read in repo]** |
| ADRs | Next free number **0026** (`docs/adr/` holds 0001–0025) **[VERIFIED]**. Needed: ADR-0006 addendum (D5, directory PII), an ADR (or ADR-0021 addendum) for `user:directory:read` + `isSensitive` semantics, an ADR for B8 concurrency (ETag source and lock) if Gate 2 departs from existing patterns. ADR-0021 to ADR-0025 are all still **Proposed** although US-018 is merged **[VERIFIED]** (requirements R10) |
| **Largest finding** | **V11 changes the definition of "administrator" in every environment, including prod, the moment it applies — regardless of any feature flag.** The admin predicate reads the live catalogue (`RbacAdministrators.isAdminDefining`, `RbacAdministrators.java:28-29`, catalogue from M15). The B7 footer keeps the admin population constant *inside the migration*, but cached permission sets and in-flight tokens lag by up to 900 s + 900 s, and every *future* custom administrator role must now carry nine permissions, not eight (§3.2) |

### Re-trace of `[REPORTED]` claims the requirements left open

| Claim (requirements §3, discovery) | Result | Evidence |
|---|---|---|
| `findRole` filters soft-deleted roles | **CONFIRMED** | `JpaRoleRepository.findRoleViewById` has `r.deletedAt IS NULL` (`JpaRoleRepository.java:46-53`). B3 on a deleted role is therefore the same 404 `ROLE_NOT_FOUND` as a missing one |
| "No role-creation port found" (C1) | **WRONG** | `RoleManagementPort.createRole(tenantId, name, description)` and `attachPermission(roleId, permissionId)` exist (`RoleManagementPort.java:36`, `:110`). `DevDataInitializer` (in `identity.infrastructure`) may call an `rbac.application.port.out` port; it already does with `UserRoleAssignmentPort` (`DevDataInitializer.java:9`, `:116`) |
| Locked/pending users "need domain methods (unverified)" | **WRONG** | `User` is `PENDING` from its constructor (`User.java:91`); `lockAccount(Instant)` sets `LOCKED` (`:123-126`). Caveat: `unlockIfExpired` (`:182`) reverts an expired lock at login, so the seed needs a far-future `lockedUntil` |
| Discovery: "flags absent in prod" | **PARTLY WRONG** | `application-prod.yml` exists (`:1-36`) but sets **no** `feature.*` key, so prod inherits the base `false` (`application.yml:280-294`). An env-var override still cannot be ruled out from code (requirements R9) |
| `PageParams`/`PageMetadata`/`PageLinks` live in `rbac.interfaces.rest` | **CONFIRMED, plus one** | `PageParams` is package-private in `rbac.interfaces.rest` (`PageParams.java:15`); `PageMetadata`/`PageLinks` in `rbac.interfaces.rest.dto`; both depend on **`rbac.domain.PageResult`** (`PageMetadata.java:3`, `PageLinks.java:3`). 160 occurrences across 33 files (main + test) **[VERIFIED by count]** |
| Throttle "surfaces as `NOT_TENANT_ADMIN`" (B7) | **CONFIRMED and narrower than stated** | Only `RoleAssignmentService.evaluateThrottle` (`:624-646`) and only when the target is admin-defining or the caller themself (`:641-644`). `RoleManagementService` has **no** throttle collaborator (constructor `:123-145`), so attach, detach, PATCH, DELETE and B8 have no throttled path at all |
| `user:read` held by MEMBER | **CONFIRMED** | `V5__rbac_schema.sql:134-136` |
| Story: "B1/B2/B4 live in the identity context" (`US-019.md:82`) | **Story text superseded** | Gate 1 Q6 places B4 in `rbac`; `rbac` may not import `identity` (`HexagonalArchitectureTest.java:146-158`) |

### Top 3 risks (full list §14)

1. **V11 re-defines "administrator" globally and unflagged** (§3.2). The footer must be the A-V9 template with exactly the new id; admins' tokens and caches do not carry the new permission for up to ~30 min unless the permission-cache flush runs; ITs that hand-build an "8-permission administrator" silently stop being administrators.
2. **B8's ETag is ineffective without a lock, and the lock order is fixed by existing protocols** (§5.4). Under `REPEATABLE READ`, two `PUT`s with the same valid `If-Match` both pass a compare-then-write. The ETag source has no schema backing today (no `@Version` on `roles` or `role_permissions`).
3. **Directory PII leaks through URLs and links, and e2e can be silently green** (§4.1, §8.3). `?email=` lands in nginx access logs, browser history and, if echoed, in `PageLinks`; shared Playwright `storageState` across parallel workers triggers refresh-token reuse detection, and specs skip when the backend is unreachable.

---

## 1. Slice map

| Slice | Items | Code? | Hard upstream | Section |
|---|---|---|---|---|
| **S0** Human decisions | D2, D3, D4 text, D5, C3, A9 contact value, Q11/Q-N5/Q-N8/Q-N10 | No | — | §2 |
| **S1** Backend P0 | **V11**, B1, B2, B3, B4, B5 | Yes | D5 + threat model before B1 merges; V11 before B1 | §3, §4 |
| **S2** Frontend foundations | A2 → A1, A4, A3, A5, A6 | Yes | A1 needs A2; A5 needs V11's name | §6 |
| **S3** Backend P1 | B6, B7, B8, B10 | Yes | B8 needs B3 (ETag on a GET); B10 last | §5 |
| **S4** Environments and tests | C1, C2, C4 | Yes | C1 needs V11 + S1 endpoints; C2 needs C1; C4 needs C2 | §8 |
| **S5** Frontend P1/P2 and docs | A7, A8, A9, A10, A11, D6, B9 doc fix | Yes | A2; A11 needs S1/S3 DTOs final; D6 last | §7 |

---

## 2. S0 — Human decisions (D2, D3, D4, D5, C3)

No code. Impact is on sequencing and on what the code must not pre-empt.

| Item | Code that waits on it | Note |
|---|---|---|
| D5 (privacy/security) | B1/B2 merge (requirements §8). B4 and B7 are in the threat model's scope too | Must also rule on: email in URL query (§4.1), the lookup audit event (Q-N1), `memberCount` disclosure (B6, Q-N7), and `isSensitive` membership (§3.3) |
| D4 (propagation text) | D3, US-020 copy | Re-grounded numbers **[VERIFIED]**: `permission-cache-ttl-seconds: 900` (`application.yml:157`), `access-token-ttl-seconds: 900` (`:251`). Since US-018 A9/A10, detach bumps every holder's epoch and attach evicts every holder's cache entry (`RoleManagementService.java:285-293`, `:344-356`; `application.yml:151-156`), so the 900 s TTL now bounds only out-of-band changes (migrations, SQL, failed evictions). **Effect on D4:** for API-driven changes the lag is much shorter than "30 minutes" (detach: next request after the bump; attach: next refresh after eviction, so up to one token TTL). "About 30 minutes" remains the worst case only for V11-style migrations without a cache flush. Recompute before D3 is approved |
| C3 (flag plan) | C4 (CI must run with us012, us015, us019 on) | Prod file sets no flags (§0 re-trace). A new flag adds one row |
| D2, D3 | US-020 only | No US-019 code depends on them, except A3/A4 variants that US-020 designs consume |
| A9 contact (Q-N5) | A9 | `AppConfig` has no contact field (`app-config.ts:33-71`) **[VERIFIED]** |

---

## 3. S1-a — V11 and the `user:directory:read` permission (prerequisite of B1/B2/C1/A5)

### 3.1 Files

| File | Change | New / Mod |
|---|---|---|
| `db/migration/V11__…sql` | Insert `user:directory:read`; B7 footer, **A-V9 variant** (`deleted_at IS NULL`), placeholder bound to exactly the inserted id. Next literal in the V5/V6 sequence is `019f6839-1808-7000-8000-000000000009` **[INFERENCE: continues V5 `:7-11` and V6 `:8`]** | New |
| `common/security/Permissions.java:20-39` | New constant, add to `ALL`. B5's static sensitive set lands here too (Gate 1 Q2). Javadoc `:7` ("V5 seeds seven, V6 adds…") updated | Mod |
| `rbac/domain/RbacSeededPermissionIds.java` | Only if any code checks the new permission by id (none identified). Its Javadoc `:9` still says "until the typed catalogue (B5) lands" (stale; mention, don't fix) | Conditional |
| `nexus-frontend/src/app/shared/types/permission.ts:13-33` | New union member and `PERMISSIONS` entry; Javadoc `:5` | Mod |
| `docs/runbooks/…` permission-migration runbook | The footer template's "also required" steps (`permission-migration-footer.sql:23-31`): custom-admin exposure check before/after, **permission-cache flush** | Ops step |

### 3.2 Who is an administrator after V11 (High risk; analysed precisely)

**Definition in force [VERIFIED].** A role is admin-defining iff it carries every id in the live `permissions` table (`RbacAdministrators.java:28-29`); a user is an administrator iff they actively hold one such role (per role, never the union; `:52-59`, ADR-0021 D3). The catalogue is read from the database on every decision (M15, `UserRoleAssignmentPort.findCatalogueIds`, used at `RoleAssignmentService.java:506`, `RoleManagementService.java:634`, `:675`). It is not cached. The health indicator and the canary compare `COUNT(DISTINCT permission)` with the catalogue count computed in SQL (`RbacZeroActiveAdminsHealthIndicator.java:18-26`, `JpaUserRoleRepository.java:378-385`).

**So the catalogue grows from 8 to 9 at V11's commit, and with it the admin threshold.** Consequences, case by case:

| Population | Without the footer | With the A-V9 footer (mandatory, scanner-enforced) |
|---|---|---|
| System `TENANT_ADMIN` (bootstrap tenant; any other tenant that has one) | Demoted (8/9) | Statement (b) re-syncs every system `TENANT_ADMIN` to the whole catalogue: **stays administrator** |
| Live custom role carrying all 8 | Demoted; tenants with custom-only administrators drop to zero administrators | Statement (a) attaches the new id: **stays administrator** |
| Soft-deleted custom role carrying all 8 | n/a | Excluded by `r.deleted_at IS NULL`. Harmless: a deleted role has no active holders (invariant at `RoleManagementService.java:443-446`) |
| Custom role carrying 7 of 8, or a union-holder | Not an administrator | Unchanged: gains nothing. **No promotion is possible**, because (a) only completes roles already complete |
| `MEMBER` (system) | Unchanged | Unchanged; does not get the new permission (R1 closed by design) |

**Residual effects the footer does not cover:**

1. **Cache and token lag.** The footer inserts rows; it bumps no epoch and evicts no cache (template note `:29-31`). Administrators' JWT `permissions[]` lack `user:directory:read` until their cached set expires (≤ 900 s) and they refresh (≤ 900 s token TTL). With the us019 flag on, administrators get 403 on B1 for up to ~30 min after deploy. **Ordering rule:** V11 deploy → cache flush → enable us019. This is an operational precondition, not a code change.
2. **Authorization decisions are not affected by the lag.** Every admin decision reads the DB (M13/M15), so the lag affects only JWT-gated `@RequiresPermission` checks for the new permission.
3. **Rolling deploy.** Flyway runs on the first booting new instance; old instances keep serving. Old code reads the same live catalogue, so its admin decisions stay consistent; its `Permissions.ALL` (8) is used only by tests. **[UNVERIFIED]** that Flyway runs a data-only MySQL migration in one transaction (Flyway's documented default; not checked in this repo's config). If it does not, a crash between the `permissions` insert and statement (a) would demote every custom administrator until repaired. V6 has the same shape and shipped.
4. **Concurrent attach during the migration.** An attach that completes a role's 8 pre-migration permissions and commits *after* statement (a) scans leaves that role at 8/9: it does not become admin-defining, and old or new code computes it the same way. Narrow, fail-closed (no unintended promotion). Note for the threat model.
5. **Future custom administrator roles** need nine permissions. Any runbook, persona (C1) or test that builds an administrator by listing permission ids explicitly breaks silently. ITs that select ids from the `permissions` table survive; ~18 test files carry V5/V6 literals and must be audited (`grep 019f6839-180[0-7]` over `src/test`, 44 hits in 20 files) **[VERIFIED count; per-file reliance on "full catalogue" not verified]**.
6. **Grant-subset spill-over.** After V11, only holders of `user:directory:read` (today: administrators) may attach it (A3), assign a role carrying it (A2), or detach/PATCH/DELETE/B8 any role carrying it (role-subset, ADR-0021 D5). A "role manager" (`role:read`, `role:write`) can no longer edit a role that contains it. Intended, but it changes C1 persona semantics and US-020 affordances.
7. **`RBAC_010` threshold shifts.** "Would make the role admin-defining" now means reaching 9 (`RoleManagementService.java:668-681`). No code change; test fixtures that construct the "8th attach" case must add one.
8. **Second tenant (C1) without a system `TENANT_ADMIN`.** Statement (b) cannot reach it; its administrator is admin-defining only if its custom role passes statement (a) on a *later* migration. Recovery there has no break-glass (ADR-0021 RES-41).

**Verification needed:** the semantic IT the template requires (`permission-migration-footer.sql:24-25`): seed a full-catalogue custom role before V11, assert it gains the new permission; assert a 7-of-8 role gains nothing; the zero-admin health indicator stays green across the migration; `PermissionMigrationFooterScannerTest` passes on V11.

### 3.3 `isSensitive` (B5) membership interacts with V11

The static set lives in `Permissions` (Gate 1 Q2). Which members are sensitive is a human decision (D5/Security). `user:directory:read` (PII read) is a candidate. `PermissionsCatalogueIT` (`:28-35`) today asserts only `ALL` equals the table; it must also assert the sensitive set ⊆ `ALL` (and fail when they disagree, per B5).

---

## 4. S1-b — Backend P0 endpoints (B1, B2, B3, B4, B5)

### 4.1 B1/B2 user directory (identity)

| Layer | File | Change | New / Mod |
|---|---|---|---|
| interfaces.rest | `identity/interfaces/rest/…` directory controller | `GET /api/v1/users`, `GET /api/v1/users/{userId}`, `?ids=`. `@RequiresPermission(USER_DIRECTORY_READ)`, `@ConditionalOnProperty(feature.nexus-us019-user-directory.enabled)`. Path vars as `String` + parse (house style, `RoleController.java:56-59`) | New |
| interfaces.rest.dto | directory response DTO(s) | Exactly `userId, email, status, emailVerified, createdAt` (B1). `emailVerified` derives from `email_verified_at` (`V2__identity_schema.sql:19`) | New |
| application | identity directory use case(s) | `@Transactional(readOnly = true)`; tenant from the JWT; `EmailBlindIndexService.blindIndex` for `email=` (ADR-0006) | New |
| application.port.out | identity directory query port | No existing identity port lists users; `UserRegistrationPort.findByTenantAndEmailHmac` exists (used by `DevDataInitializer.java:77`) | New |
| infrastructure.persistence | `JpaUserRepository.java` | New tenant-scoped list/count/by-ids methods. **`TenantIsolationArchitectureTest` applies**: `User` has `tenantId` (`User.java:26-27`), so each method needs "Tenant" in its name or `@Param("tenantId")` (`TenantIsolationArchitectureTest.java:117-122`). `findById` is inherited and not policed (`:33-35`) — B1's by-id read must not use it unscoped | Mod |
| infrastructure.persistence | adapter for the new port | Decrypts `email_cipher` per row (`AttributeEncryptor`); never maps `email_hmac`, `password_hash`, counters (`User.java:39-59`) | New |
| infrastructure.security / identity | throttle + audit for `email=` (Q-N1 (a), adopted) | A new `RateLimitStore` bucket (identity-owned, no layering issue); 429 via the existing `RateLimitException` handler (`GlobalExceptionHandler.java:93-101`); a new `AuthEventType` value with **no email in metadata**. `auth_events.event_type` is `VARCHAR(64)` (`V2:80`), so no migration | New / Mod |
| common | paging types | See §4.6 | Mod (if moved) |

**Findings for design:**

- **Paging limits.** `PageParams` already rejects `size` > 100 and non-integers with 400, never clamps (`PageParams.java:20-31`). Reusing it settles Q-N6 as "reject".
- **`PageLinks` drops filters.** Links carry only `page` and `size` (`PageLinks.java:25-27`). For B1 they would lose `status`; adding `email` to a link would echo PII into the response body and into whatever logs URLs.
- **Email in the query string.** `ApiRequestLoggingFilter` logs `getRequestURI()` only, not the query (`ApiRequestLoggingFilter.java:32`, `:80`, `:90-91`) **[VERIFIED]**, so the app log is safe. But the frontend container's nginx proxies `/api/` (`nexus-frontend/nginx.conf:45`) with no `access_log` directive, so nginx's default combined log records the full request line including `?email=` **[INFERENCE: nginx default behaviour]**. Browser history and any APM URL capture are further sinks. Gate 2 / D5 decision (§15 Q-D3).
- **Route coexistence on `/api/v1/users`.** Already mapped by `UserProfileController` (`/me`, us003; `UserProfileController.java:19-23`), `UserRoleController` (`/{userId}/roles`, us012; `UserRoleController.java:61-64`), `AccessReviewController` (`/users/{userId}/effective-permissions`, us015; `AccessReviewController.java:48-51`, `:135`). B1's `/{userId}` must not shadow `/me` (Spring prefers the literal segment **[REPORTED framework behaviour]**); an EndpointClassification sweep proves it.
- **Flag off is distinguishable from "user not found".** Flag off → no handler → `NoResourceFoundException` → 404 `RESOURCE_NOT_FOUND` (`GlobalExceptionHandler.java:187-191`). A missing or cross-tenant id with the flag on → whatever `code` B1 chooses (e.g. a `USER_NOT_FOUND`-style code). This **corrects** requirements §10 ("the UI cannot tell flag-off from not-found per id"): it can, by `code`. Design must keep the two codes distinct on purpose or merge them on purpose.
- **Users have no soft delete.** Statuses are `PENDING, ACTIVE, LOCKED, DISABLED` (`UserStatus.java:4-9`); "deleted users" (Gap G7) do not exist in the schema. Whether `DISABLED` is listed by default is a design call.
- **Existence oracle (B2).** `?ids=` with silent omission must also be timing-flat versus a miss; PK lookups with a residual tenant predicate are naturally flat **[INFERENCE]**.

### 4.2 B3 single role (rbac)

| Layer | File | Change |
|---|---|---|
| interfaces.rest | `RoleController.java` (`@RequestMapping("/api/v1/roles")`, us015, `:61-67`) | New `GET /{roleId}`, `@RequiresPermission(ROLE_READ)`; reuses `toResponse` (`:312-315`). If Gate 2 puts the B8 `ETag` here, the header is set here (§5.4) |
| application | `RoleManagementService.java` | New read method via the existing private `resolveRoleInTenant` (`:521-543`): 404 missing, deleted (`JpaRoleRepository.java:51`) and cross-tenant, with WARN `RBAC_CROSS_TENANT_TARGET` and the `permission_denied{reason=CROSS_TENANT_TARGET}` counter. No new port method (`findRole`, `RoleManagementPort.java:42`) |
| tests | `RoleControllerTest`, `RoleManagementServiceTest`, cross-tenant equivalence (`CrossTenantNotFoundEquivalenceIT` exists) | Extend |

### 4.3 B4 own authorization profile (rbac, us019 flag)

| Layer | File | Change |
|---|---|---|
| interfaces.rest | new controller in `rbac/interfaces/rest/`, path `/api/v1/users/me/authorization`, `@ConditionalOnProperty(us019)` | **The first `rbac` controller on a non-us015/us012 flag.** `@AuthenticatedEndpoint`; ArchUnit `authenticated_endpoints_take_no_uuid_identifier` (`HexagonalArchitectureTest.java:424-440`) forbids any `@PathVariable`/`@RequestParam`/UUID/`HttpServletRequest` parameter, so the handler cannot build a `RequestContext` the way `RbacControllerSupport.requestContext(httpRequest)` does. Fine for a read with no audit (AS8) |
| application | new read service, or a method on an existing service | Live reads only: `UserRoleQueryPort.findActiveRoleNames`/`findActivePermissionNames` (`UserRoleQueryPort.java:16-22`, both filter `r.deletedAt IS NULL`, `JpaUserRoleRepository.java:50`, `:69`), plus M13 `findHeldRolePermissionIdsForAuthorization` (`:136-139`) and M15 for `isAdministrator` via `RbacAdministrators.isAdministrator` (`RbacAdministrators.java:57-59`). Not `RoleResolutionService` (cache), not `/users/me` (JWT, `UserProfileController.java:32-38`) |
| ArchUnit | `rbac_application_methods_must_not_accept_principal_or_map` (`:166-180`), `rest_handlers_must_carry_exactly_one_access_marker` (`:326-335`), `rbac_must_not_depend_on_identity` (`:146-158`) | Apply as usual |

The wrapper `isCallerAdministrator` named in discovery is gone; the call is `RbacAdministrators.isAdministrator(heldRolePermissions, catalogueIds)` (`RoleAssignmentService.java:740`, `RoleManagementService.java:640`) **[VERIFIED]**.

### 4.4 B5 `isSensitive`

| File | Change |
|---|---|
| `rbac/interfaces/rest/dto/PermissionResponse.java:11` | Additive `isSensitive`. **Naming trap:** the `boolean isSystemRole` precedent (`RoleResponse.java:9-13`) serialises as `isSystemRole`; the same holds for `isSensitive` |
| `PermissionController.toResponse` (`PermissionController.java:73-75`) | The one mapper; used by **three** endpoints: catalogue (`:60-71`), role permissions list (`RoleController.java:148-152`) and attach 201 body (`:195-197`). All three gain the field |
| `Permissions.java` | Static set (Gate 1 Q2), §3.3 |
| `PermissionControllerTest`, `RoleControllerTest`, `PermissionsCatalogueIT` | Extend |

### 4.5 S1 ArchUnit and test summary

| Rule / test | B1/B2 | B3 | B4 | B5 | V11 |
|---|---|---|---|---|---|
| `rest_handlers_must_carry_exactly_one_access_marker` | ● | ● | ● | | |
| `authenticated_endpoints_take_no_uuid_identifier` | | | ● | | |
| `requires_permission_methods_must_be_public_and_non_final` | ● | ● | | | |
| `rbac_must_not_depend_on_identity` | (identity side) | | ● | | |
| `TenantIsolationArchitectureTest` | ● | | | | |
| `RETIRED_SYMBOLS` scan (`:234-274`) | | ○ new code must not reintroduce | ○ | | |
| `EndpointClassificationWebTest` "all flags enabled" (`:322-339`) | ● add us019 | | ● | | |
| `PermissionMigrationFooterScannerTest` | | | | | ● must pass on V11 |
| `RbacSchemaMigrationIT` | | | | | ● counts 8→9 (`:256-260`), 9→10 system-role pairs (`:273-279`), names list (`:56`, `:290-295`); V11 footer re-execution test like V6's (`:339-472`) |
| `PermissionsCatalogueIT` | | | | ● | ● |
| new feature-flag test for us019 (pattern: `RbacRoleManagementFeatureFlagTest`) | ● | | ● | | |

### 4.6 Paging types relocation (Q-N9) — blast radius

Identity cannot use `rbac.interfaces.rest.PageParams` (package-private) and should not import `rbac.interfaces` from `identity.interfaces` (allowed by ArchUnit, since only `rbac → identity` is forbidden, but it couples two contexts' web layers). Options for `/design`: (a) move `PageParams`, `PageMetadata`, `PageLinks` and `rbac.domain.PageResult` to `common` (`common.web` / `common.domain`); (b) duplicate in identity; (c) identity imports rbac's types. **Blast radius of (a):** 20 main files and 13 test files (33 files, 160 occurrences), including `RoleManagementPort`, `UserRoleAssignmentPort`, both JPA adapters, all four rbac controllers, five list DTOs, `PageParamsTest`, `PageLinksTest`, `PageResultTest`. Mechanical, but it touches US-018 C2/C3 code and every RBAC list endpoint; it should be its own commit with no behaviour change. The HexagonalArchitectureTest note (`:154-157`) warns that a shared `common.*` helper recreates coupling invisibly; paging types are neutral enough to accept that, but say so in the design.

---

## 5. S3 — Backend P1 (B6, B7, B8, B10)

### 5.1 B6 role counts

| File | Change |
|---|---|
| `RoleResponse.java:20-21` | Additive `memberCount`, `permissionCount`. Used by create 201, list, PATCH 200 and the new B3 (`RoleController.java:101`, `:125-128`, `:277`, `:312-315`) — Gate 2 decides whether all four carry counts |
| `RoleManagementPort` + `JpaRoleManagementAdapter` + `JpaRoleRepository`/`JpaUserRoleRepository` | New grouped reads, one per page per count. `RolePermission` has **no** `tenantId`, so `TenantIsolationArchitectureTest` does not police a `role_permissions` query; it must be driven from tenant-scoped role ids or join `roles` with a tenant predicate |
| `RoleView` (`rbac/domain/RoleView.java`) | Discovery recommends a separate summary projection rather than widening `RoleView` (used across services) **[REPORTED]** |

- **Index paths.** `permissionCount`: `pk_role_permissions (role_id, permission_id)` covers `GROUP BY role_id` (`V5:49`). `memberCount`: `fk_user_roles_role_tenant (role_id, tenant_id)` (V8) narrows rows; `revoked_at IS NULL` needs a row lookup per assignment (revoked rows included in the scan) **[INFERENCE from index definitions]**. At ≤ 500 roles/tenant (`nexus.rbac.max-roles-per-tenant`, `RoleManagementService.java:131`) and today's volumes no index is required; a covering index is an additive Gate 2 option if `EXPLAIN` shows otherwise.
- **"Active holder" definition.** Excluding `LOCKED`/`DISABLED` users would need a join to `users` from an `rbac` query: a cross-context SQL dependency ArchUnit cannot see. Recommend counting active assignments only and saying so.
- **Downstream (US-020 C5) is wrong as written.** "`memberCount` 1 on an admin-defining role = last administrator" (`US-020.md:81`) does not match the lockout's distinct-holder count across **all** admin-defining roles (ADR-0021 D6). The UI can know a role is admin-defining from `permissionCount == catalogue size` **[INFERENCE: `pk_role_permissions` makes the count exact]**, but not "last administrator". Flag to US-020.

### 5.2 B7 denial reason and real 429

| Layer | File | Change |
|---|---|---|
| common.web | `GlobalExceptionHandler.handleInsufficientPermission` (`:161-178`) | Additive `reason` property from an allow-list; `requiredPermission` stays the endpoint permission (ADR-0021 D4). Today `reason` is logged (`:164`) and a metric tag (`:169-173`) but not in the body |
| common.security | `DenialReason.java:8-21` | Allow-list membership (story: `GRANT_EXCEEDS_CALLER`, `SELF_ASSIGNMENT`, `NOT_TENANT_ADMIN`); `CROSS_TENANT_TARGET` never reaches 403 since US-018 B1 (it is a 404); `MALFORMED_AUTHENTICATION`, `MISSING_TENANT` stay opaque. **`NOT_TENANT_ADMIN` is a stale enum name** (the predicate is no longer name-based since ADR-0021 D3): exposing it freezes an internal name on the wire. Gate 2: decouple wire values from enum names |
| rbac.application.port.out | `RoleChangeThrottlePort.java:35` | `isThrottled` returns `boolean`, no retry-after. A real `Retry-After` needs the port to expose remaining window time: a **port signature change** with **two adapters** to update: `RedisRoleChangeThrottleAdapter` (`rbac/infrastructure/cache`, `:37`) and `RateLimitRoleChangeThrottleAdapter` (`identity/infrastructure/security`, `:67`). Fail-safe contract (`:26-29`) must survive |
| rbac.application | `RoleAssignmentService.evaluateThrottle` (`:624-646`) | `:643` throws `InsufficientPermissionException(…, NOT_TENANT_ADMIN)`; becomes a 429. `RateLimitException` (`common.domain`) and its handler already exist |
| tests | Every assertion on the throttled 403 (`RoleAssignmentServiceTest`, throttle ITs, `RbacAuthEventAdapterTest` only if the denial audit changes) | Change |

**Oracle note for the threat model.** The throttled branch already leaks one bit ("target is admin-defining or self", RES-33, `:615-617`). A 429 makes that bit explicit; `GRANT_EXCEEDS_CALLER` tells a caller without `role:read` that the target role holds something they lack (one bit of role composition; ADR-0021 D4 avoided this oracle for `requiredPermission`). Both need explicit acceptance.

**Not flagged.** `GlobalExceptionHandler` and the throttle are shared; B7 ships to every endpoint that raises `RBAC_001` (us012, us015, and the evaluator's `PERMISSION_ABSENT` path) without a flag of its own. Gate 2 decides whether that is acceptable.

### 5.3 B10 OpenAPI error documentation

| File | Change |
|---|---|
| `config/OpenApiConfig.java` | Sets only title/version **[REPORTED]**; gains a `ProblemDetail` schema component |
| Every RBAC and directory controller | `@ApiResponse` codes. Today prose only (e.g. `RoleController.java:87-90`, `:169-180`); `RBAC_001`–`RBAC_010` exist in code (`RBAC_010`: `AttachProvenanceConflictException.java:21`) **[VERIFIED by grep]** |
| new test | No OpenAPI test exists (only `EndpointClassificationWebTest` and `ApiRequestLoggingFilterIT` mention api-docs) **[VERIFIED]**. springdoc is disabled only in prod (`application-prod.yml:20-24`), so a test-profile test can read `/v3/api-docs` |

### 5.4 B8 atomic permission replace

| Layer | File | Change |
|---|---|---|
| interfaces.rest | `RoleController.java` | New `PUT /{roleId}/permissions`, `@RequiresPermission(ROLE_WRITE)`; reads `If-Match`. **`@RequestHeader` is fine here** (the ban applies only to `@AuthenticatedEndpoint`) |
| interfaces.rest.dto | request DTO | New |
| application | `RoleManagementService.java` | New use case composing the existing rules: `resolveRoleInTenant` (`:521`), `requireMutableRole` (`:546`, 409 `RBAC_003`), A3 per added id (`requireCallerHoldsPermission`, `:573-600`, one M13 read can serve all), role-subset for removals (`requireRoleSubset`, `:620-660`), `RBAC_010` on the after-state (`:668-681`), inline audit per change (A6: `recordRolePermissionGranted`/`Revoked`, `:261-264`, `:328-331`), post-commit cache eviction for additions (`:289-293`) and epoch bump for removals (`:348-356`). No-op set → no audit, no bump |
| application | set lock | `acquireSetLockBeforeRoleRow` (`:501-508`) reuses `RoleAssignmentService.resolveAdminDefiningRoleIds` and `buildAscendingLockSet`. Gate 1 Q5: take it when before **or** after is admin-defining |
| common.domain + common.web | 412 / 428 | **No existing exception or handler** for 412/428 in `GlobalExceptionHandler` (handlers `:66-193`) **[VERIFIED]**. New exception type(s) and handlers |
| config | `SecurityConfig.corsConfigurationSource` (`:205-219`) | **`If-Match` is not an allowed request header (`:209`) and `ETag` is not exposed (`:213`).** In dev the SPA (`:2000`) calls the API (`:1000`) cross-origin (`environment.development.ts:42`), so the browser would strip both. Prod is same-origin (`environment.ts:42`). `SecurityConfigWebTest` likely pins the CORS lists **[UNVERIFIED]** |

**Findings the design must resolve (all High):**

1. **ETag source has no schema backing.** `roles` has `updated_at ON UPDATE` (`V5:37`), which changes only on a `roles` row update, not on `role_permissions` changes. `RolePermission` has no `@Version` (`RoleManagementPort.java:115-116`). Options: a content hash of the sorted permission ids (no migration), or a version column on `roles` (V-next, expand, plus a grant change on a column-scoped `UPDATE`, plus `RbacDbPrivilegeHealthIndicator` and `RolePermissionsPrivilegeIT:167-205` updates). The hash also makes the ETag independent of rename.
2. **Which representation carries the ETag.** Requirements Q4 says "a header contract on `GET /roles/{id}` (B3)"; the `PUT` target is `/roles/{id}/permissions`, whose GET already exists (`RoleController.java:137-153`). HTTP semantics favour the ETag on the same resource the `PUT` replaces. Decide one; US-020 G3 (`US-020.md:120`, "Last-write-wins, with no ETag") must be updated either way.
3. **Compare-then-write is a TOCTOU under `REPEATABLE READ`.** Two concurrent `PUT`s with the same `If-Match` both read the same snapshot and both pass. The ETag only works if the comparison happens under a lock that serialises replaces on the role. Candidates: the role row (`FOR UPDATE` or a no-op `UPDATE`), or the set lock when it is taken anyway. **Lock order is fixed by existing protocols**: on admin-defining roles, set lock first, then the role row (RC-46 option (a), `RoleManagementService.java:438-441`, US-018 `03-design.md:1110-1113`); on others, role row first. B8 must follow the same order or reintroduce the deadlock RC-46 removed.
4. **`nexus_app` privilege for a locking read on `roles`.** `nexus_app` holds `SELECT, INSERT` plus column `UPDATE (name, description, deleted_at)` on `roles` (`02-grants-post-schema.sql:32`, `:39`). Whether MySQL 8.4 accepts `SELECT … FOR UPDATE` on `roles` with only column-level `UPDATE` must be proven by an IT connected as `nexus_app` (the `RolePermissionsPrivilegeIT` pattern, `:70-75`); every other IT connects as the superuser and would pass regardless (the same trap US-018 §2.1 recorded for `permissions`).
5. **Concurrency with attach/detach.** Attach/detach take no set lock (RES-28) and no role-row lock. A `PUT` serialised against other `PUT`s still races a single attach/detach unless those also participate. Gate 2 decides whether that residual is accepted (US-020 G3 already treats `RBAC_005`/`ROLE_PERMISSION_NOT_FOUND` as convergence).
6. **Request bounds and unknown ids (G9).** Catalogue is 9 after V11; the request should be bounded by it. An unknown permission id: 404 `PERMISSION_NOT_FOUND` as attach does (`:240-244`), or 400. Permissions are global, so "other-tenant permission" cannot exist; "other-tenant role" is the existing 404.
7. **Status for empty set.** "Remove all permissions" is legal for a custom role (a role with zero permissions grants nothing, ADR-0021 D2); if the role is admin-defining it is a demotion and needs the admin-through-another-role rule.
8. **Epoch fan-out cost.** A replace that removes permissions bumps every holder once (not once per removed permission); additions evict once. Same bounded O(holders) post-commit cost as detach (`RoleManagementService.java:344-356`).

---

## 6. S2 — Frontend foundations (A1–A6)

### 6.1 Files by item

| Item | Files | New / Mod | Specs that must change |
|---|---|---|---|
| **A2** shell | New layout route component (under `core/` or `shared/layout`), typed nav config filtered by permission; `app.routes.ts:120-125` (`/dashboard` moves under the shell parent) | New / Mod | `app.routes.spec.ts`, `permission-guard-contract.spec.ts` (real-table walk), `dashboard.component.spec.ts`, `app.spec.ts` |
| A2 / Q12(b) | `app.html:1-18` renders `<header class="app-header">` **unconditionally** above `<router-outlet>`; `app.ts`, `app.scss` | Mod | `app.spec.ts`. Q12(b) (keep for public pages, shell has its own) needs the root header to stop rendering for shell routes; either a public layout route or a condition |
| A2 landmarks | `DashboardComponent` template renders `<main data-testid="dashboard-root">` and `<h1>` (`dashboard.component.ts:38-49`) | Mod | `dashboard.component.spec.ts`, `e2e/auth/logout.spec.ts` (5 test-id hits), `e2e/auth/session-refresh.spec.ts` |
| A2 logout | Logout moves to the user menu; `logout-button` id must survive or e2e changes in the same commit. The dashboard's `httpResource('/v1/users/me')` exists only to prime proactive refresh (`:61-71`); moving logout does not move that, but the shell may be its better home | Mod | as above |
| A2 vs Access Denied | `AccessDeniedComponent` owns `<main>` + `h1` (`access-denied.component.ts:13`, `:32-35`) and **must stay a top-level, unguarded route** (`app.routes.ts:143-148`), i.e. outside the shell | Keep | `access-denied.component.spec.ts`, `e2e/access-denied.spec.ts` unchanged if kept outside |
| **A1** | `permission.guard.ts:14-26` (wrong "sequentially" comment `:22`, wrong example `:19`); `permission-guard-contract.spec.ts` | Mod | Contract spec: `checkGuardArray` accepts same-array composition (`:46-52`); option (b) inverts that. Existing synthetic cases that use `[authGuard, permissionGuard]` (`:175`) and the router-integration tests (`:267-287`) must be rewritten; add a real-Router test with a 500 ms delayed refresh and one asserting exactly one `POST /refresh` (R5) |
| **A4** `NxTable` | `shared/ui/table/table.ts` (`CellType` `:14`, empty slot `:218`) | Mod | `table.spec.ts`. **Only consumer is the design-system preview** (`design-system-preview.component.{ts,html}`) **[VERIFIED by grep]**, so "existing callers unchanged" is cheap |
| **A3** wrappers ×9 + dialog variant + announcer | `shared/ui/<name>/*` ×9, `shared/ui/dialog/dialog.ts` (`DialogData.variant` is `'default' \| 'danger'`, `:92`), new `NxAnnouncer`, `shared/ui/index.ts`, `design-system.html` preview | New / Mod | 9 new specs, `dialog.spec.ts`. G8: unit-level axe needs a mechanism (none today) |
| **A5** | `shared/types/permission.ts` (+ new member from V11), labels and grouping | Mod | New label-completeness test; `app.routes.spec.ts:35-52` unchanged in logic |
| **A6** | `core/http/api-error.interceptor.ts`, `skip-access-denied-redirect.ts` | Verify | `api-error.interceptor.spec.ts`: both branches (branch coverage not verified) |

### 6.2 Budgets and standards

- Component style budget 4 kB warn / 8 kB error, initial bundle 500 kB / 1 MB (`angular.json:42-51`) **[VERIFIED]**. A shell is in the initial route path for every signed-in page: keep it lazy behind the parent route.
- ADR-0004: only `shared/ui` imports Material/CDK; ESLint does not enforce it **[REPORTED]**.
- `TitleStrategy` (A8) and the shell's focus management must not double-handle AccessDenied's own focus (`access-denied.component.ts:71-72`).

### 6.3 Frontend coupling to backend changes

| Backend change | Frontend effect |
|---|---|
| V11 | `Permission` union + label; `app.routes.spec.ts` lets US-020 gate the users route on the new name |
| B5/B6 | A11 DTO types |
| B7 | A11 error type (`reason`), interceptor unaffected (`RBAC_001` still drives the redirect) |
| B8 ETag | Requires the CORS change in §5.4 for dev; client must send `If-Match` |
| B4 | A9 live role names (if chosen), US-020 G6 |

---

## 7. S5 — Frontend P1/P2 and docs (A7–A11, D6, B9)

| Item | Files | Note |
|---|---|---|
| A7 Not Found | `app.routes.ts:160-173` (no wildcard today) | Inside the shell when signed in: the wildcard must be a child of the shell parent **and** a top-level fallback for signed-out users. Ordering against `access-denied` matters |
| A8 `TitleStrategy` | `app.config.ts` (router providers; interceptor order `correlationId, apiError, auth` **[REPORTED, US-018 §10]**) | Route `title` on every route |
| A9 Access Denied | `access-denied.component.ts:50-55` (`TODO(PM)` mailto), `app-config.ts:33-71`, both `environments/*.ts` | Blocked on Q-N5 |
| A10 `returnUrl` | `auth.guard.ts:27-30` (redirect has no query params), `features/auth/login-form/login-form.component.ts` (always `/dashboard`) | Adversarial specs (NF-S6). Note `permissionGuard` deliberately reflects nothing into the URL (`permission.guard.ts:71-74`); `returnUrl` is a deliberate exception scoped to `authGuard` |
| A11 typed contract | New DTO interfaces under `shared/types/`; a contract test against **recorded** backend responses | Where the recordings come from is a design question: a backend IT writing fixtures into the frontend tree couples the two modules' builds |
| D6 | `docs/DEVELOPMENT_GUIDE.md:120-170` (`:149` example, `:158-163` "sequentially"), `:235-245` | Last. Also `nexus-frontend/src/app/features/dashboard/README.md` mentions the test ids (3 hits) |
| B9 | `docs/features/US-018/STATUS.md` | Doc fix only |

---

## 8. S4 — Environments and tests (C1, C2, C4)

### 8.1 C1 personas (`identity/infrastructure/seed/DevDataInitializer.java`)

| Finding | Evidence | Effect |
|---|---|---|
| Profile is `dev & !break-glass` | `:41` | Never in `test`; ITs create their own data (Q-N2 recommendation) |
| Custom roles can be created through `RoleManagementPort` | `RoleManagementPort.java:36`, `:110` | Discovery's "no port" is wrong. These calls skip grant-subset and A6 audit, as the existing `assign` call does (`:30-34`); acceptable for dev seed, state it |
| **A second tenant's administrator cannot sign in on the same instance** | Login resolves the tenant from `nexus.identity.default-tenant-id` (`LoginController.java:69`; `LoginUseCase.execute(UUID tenantId, …)` `:129`); dev sets it to the bootstrap tenant (`application-dev.yml:40`) | C1's "second tenant with its own admin" is usable only as cross-tenant **fixture data** (ids for negative tests) unless a second backend instance runs with another default tenant. Gate 2 decision. Requirements K7 is therefore deeper than stated |
| The second tenant has no system roles | V5 seeds only the bootstrap tenant (`V5:119-125`); `createRole` inserts `is_system_role = FALSE` only (`RoleManagementPort.java:31-36`) | Its "admin" must be a custom full-catalogue role (an administrator by ADR-0021 D3). Must enumerate the catalogue dynamically, not 8 or 9 literals (§3.2 item 5) |
| Locked/pending reachable via domain | `User.java:91`, `:123-126` | No new domain method; seed a far-future `lockedUntil` |
| Constructor already has 6 collaborators | `:56-69` | Growth makes it a ">4 dependencies" smell (spring-boot-standards); split per seed concern |
| **Logs the seeded email at INFO** | `:100` | Violates NF-O4 (counts, not emails) and observability-standards ("full email addresses" forbidden). Fix in C1 |
| Persona semantics after V11 | §3.2 item 6 | The "user manager" (`user:read`, `user:role:assign`) cannot use the directory (B1) without `user:directory:read`; decide whether a persona holds it |
| `DevDataInitializerTest` | exists | Extend: idempotency, `prod` seeds nothing (R17) |

### 8.2 C2 Playwright fixtures

| Finding | Evidence | Effect |
|---|---|---|
| Specs hardcode the backend `http://localhost:1000` | `e2e/auth/*.spec.ts:21`, `logout.spec.ts:97` | Fixture should own the base URL |
| Backend-dependent specs skip on unreachable backend | `registration.spec.ts:77,113`, `session-refresh.spec.ts:31`, `logout.spec.ts:39` | R6; C4 must fail on skip |
| **Shared `storageState` breaks under `fullyParallel`** | `playwright.config.ts:10`; refresh-token rotation with reuse detection, no grace window (`RefreshTokenUseCase.java:47-53`) | The SPA refreshes on every cold start (`auth.guard.ts:27`); two workers presenting the same stored refresh cookie make the second a "reuse" and revoke the family. Per-worker login is needed |
| Login rate limits | `application.yml:256-259`: 10/min/IP, 5/900 s per email | Per-worker logins for ~7 personas plus retries (`retries: 2` in CI, `playwright.config.ts:12`) can trip the per-IP limit. Design must budget logins or configure the CI profile |
| `@axe-core/playwright` already present | `package.json:50` | No new e2e dependency |

### 8.3 C4 CI job

| Finding | Evidence | Effect |
|---|---|---|
| Today's `e2e` job has no backend | `frontend-ci.yml:61-99` | New or extended job |
| `performance-smoke.yml` runs the jar on **8080** because port 1000 is privileged for the runner user | `performance-smoke.yml:30-32`, `:81-91` | The SPA's dev API base is `http://localhost:1000/api` (`environment.development.ts:42`) and specs hardcode 1000, so the jar-on-8080 pattern does not fit as is |
| Compose `full` profile already provides backend + migration + grants + frontend | `docker-compose.yml:71-152`: `flyway-migrate` runs migrations as root and applies `02-grants-post-schema.sql`; `backend` runs **as `nexus_app`** under `dev`, published on `127.0.0.1:1000`; `frontend` (nginx, prod build, same-origin `/api`) on `2000` | Docker publishes the port, so the privileged-port issue does not arise **[INFERENCE]**. Running as `nexus_app` is a feature: it exercises real grants (B8's `role_permissions` writes, any `FOR UPDATE`). The `frontend` container would replace Playwright's `webServer` (`playwright.config.ts:25-30`) |
| Flags in dev | `application-dev.yml:48-56` | Add us019 `true`, or C4 cannot reach B1/B4 |
| Required status check | not visible in repo (Q9) | Ops |

---

## 9. Cross-context effects, dependencies and ordering

### 9.1 Dependency direction

| From → To | Allowed? | Used by |
|---|---|---|
| `identity.infrastructure` → `rbac.application.port.out` | Yes (established: `JpaUserDirectoryAdapter`, `DevDataInitializer`) | C1 (`RoleManagementPort`), B7 (identity throttle adapter) |
| `identity.interfaces` → `common.security.Permissions` | Yes | B1 |
| `identity.*` → `rbac.interfaces.rest.*` | ArchUnit-allowed, not recommended | §4.6 |
| `rbac` → `identity` | **Forbidden** (`HexagonalArchitectureTest.java:146-158`) | B4 must use rbac ports only; B6 must not join `users` via an identity type |

### 9.2 Upstream and downstream

- **Upstream:** US-018 (merged): ADR-0021 footer template and scanner, M13/M15 reads, set-lock protocol, A6 inline audit, A9/A10 freshness, C1 soft delete, C2 paging. Nothing blocks.
- **Downstream: US-020** must change with US-019's Gate 1 decisions: users routes gate on `user:directory:read`, not `user:read` (`US-020.md:77`, `:139-140`); nav visibility rule (`:124`); G3 last-write-wins becomes ETag-aware (`:120`); C5's last-admin rule (§5.1). **Epic 3** reuses the shell and directory (`US-020.md:187`).
- **External:** none. No new service, no Redis key family except the B1 lookup throttle bucket (existing `RateLimitStore`).

### 9.3 Ordering and parallelism

1. **V11 first** (S1). Then B1/B2, C1's directory persona, A5's label and US-020's route gate can name the permission.
2. **In parallel with S1:** S2 entirely (A2 → A1; A3/A4 independent; A5 needs only the name string). S0 human tracks.
3. **B3 before B8** (the ETag GET), unless the ETag lives on the existing `/permissions` GET.
4. **B7** is independent of B8, but both touch `GlobalExceptionHandler`; serialise the two commits.
5. **Paging relocation (Q-N9), if chosen, lands before B1** as a no-behaviour-change commit.
6. **C1 after V11 and S1**; C2 after C1; C4 after C2 and after us019 is on in `application-dev.yml`.
7. **B10 after every new/changed endpoint**; **A11 after B10/S3 DTOs are final**; **D6 last.**

### 9.4 File contention map

| File | S1 | S2 | S3 | S4 | S5 |
|---|---|---|---|---|---|
| `db/migration` | V11 | | (opt. index/version) | | |
| `Permissions.java` | ● V11, B5 set | | | | |
| `permission.ts` | | ● A5 | | | |
| `RoleController.java` | ● B3 | | ● B6, B8, B10 | | |
| `PermissionController.java` | ● B5 | | ○ B10 | | |
| `RoleManagementService.java` | ● B3 | | ● B6, B8 | | |
| `RoleAssignmentService.java` | | | ● B7 | | |
| `RoleChangeThrottlePort` + 2 adapters | | | ● B7 | | |
| `GlobalExceptionHandler.java` | | | ● B7, B8 (412/428) | | |
| `SecurityConfig.java` (CORS) | | | ● B8 | | |
| `JpaUserRepository.java` | ● B1/B2 | | | | |
| `DevDataInitializer.java` | | | | ● C1 | |
| `application-dev.yml` / `-test.yml` / `application.yml` | ● us019 flag | | | ○ | |
| Paging types (33 files) | ● if moved | | | | |
| `app.routes.ts` | | ● A1, A2 | | | ● A7, A8 |
| `app.html` / `app.ts` | | ● A2 | | | |
| `permission-guard-contract.spec.ts` | | ● A1 | | | |
| `e2e/**`, `playwright.config.ts` | | ○ test ids | | ● C2 | |
| `.github/workflows/frontend-ci.yml` | | | | ● C4 | |
| `docs/DEVELOPMENT_GUIDE.md` | | | | | ● D6 |

---

## 10. API and contract changes

### 10.1 New endpoints (all `/api/v1`, no version bump)

| Item | Method + path | Gate | Flag |
|---|---|---|---|
| B1 | `GET /users`, `GET /users/{userId}` | `user:directory:read` | us019 |
| B2 | `GET /users?ids=` | `user:directory:read` | us019 |
| B3 | `GET /roles/{roleId}` | `role:read` | us015 |
| B4 | `GET /users/me/authorization` | authenticated | us019 (rbac controller) |
| B8 | `PUT /roles/{roleId}/permissions` | `role:write` | us015 |

### 10.2 Changed contracts and breaking-change risk

| Change | Wire effect | Breaking? | Consumers today |
|---|---|---|---|
| `PermissionResponse` + `isSensitive` | Additive field on 3 endpoints (§4.4) | No for tolerant readers. `fail-on-unknown-properties` is not configured (api-design target) | No frontend consumer **[REPORTED]**; k6 RBAC read smoke (`npm run test:smoke:rbac-read`) parses responses **[UNVERIFIED whether strictly]** |
| `RoleResponse` + counts | Additive on up to 4 endpoints (§5.1) | No | as above |
| `RBAC_001` + `reason` | Additive property | No, but **disclosure change** (threat model) | Frontend interceptor reads only `status`/`code` **[REPORTED]** |
| Throttled assign/revoke 403 → 429 + `Retry-After` | Status change on one branch | **Yes for any client asserting 403**; only tests today | ITs/unit tests |
| `ETag` / `If-Match` | New headers; 412, 428 new statuses | New endpoint only | — |
| Paging relocation | None on the wire if done mechanically | No | — |
| V11 | Catalogue list grows by one (`GET /permissions` total 8 → 9) | No, but every "8" assertion breaks (§12) | tests, k6 |

---

## 11. Data

### 11.1 Migrations (ADR 0003: append-only, `ddl-auto=validate`)

| Version | Item | Content | Additive? | Existing-data risk |
|---|---|---|---|---|
| **V11** | V11 (Q1) | Insert `user:directory:read`; footer A-V9 (a) + (b) | **Additive, data only.** No DDL, no grant | §3.2. Fail-safe by template; runbook flush required |
| (option) V12 | B8 | Version column on `roles` for the ETag | Expand step; needs a column grant and health-indicator change | Only if Gate 2 rejects the content-hash ETag |
| (option) V12/13 | B1, B6 | Indexes for directory ordering or holder counts | Additive. `ALGORITHM=INPLACE` for a plain secondary index **[INFERENCE]** | Only if `EXPLAIN` demands it (§13) |

Assign version numbers at merge time; Flyway rejects out-of-order versions by default (US-018 §12.1 precedent). One statement per DDL file (RC-40.4, `V9:16-19`) applies to any DDL option; V11's three DML statements follow V6's precedent.

### 11.2 Grants (ADR-0014 D6 three-artifact rule)

No change for V11, B1 (users `SELECT`, `02-grants-post-schema.sql:26`), B3–B6, B8 writes (`:33`). A B8 locking read on `roles` needs proof (§5.4 item 4). A version column would need `UPDATE (… , version)` in all three artifacts (`02-grants-post-schema.sql`, `docs/runbooks/nexus-app-provisioning.md`, `TestcontainersConfiguration`) plus `RbacDbPrivilegeHealthIndicator` and `RolePermissionsPrivilegeIT:189-201`.

### 11.3 Caches and epochs

- V11: no epoch bump; cached permission sets stale up to 900 s → flush step (§3.2).
- B8: additions → evict holders (fail-safe), removals → bump holders' epochs (fail-closed), exactly as attach/detach.
- B4, B1: no cache; B4 must never read `RoleResolutionService` (cache) or JWT claims.

---

## 12. Test impact

### 12.1 Must change

| Slice | Test | Why |
|---|---|---|
| S1 V11 | `RbacSchemaMigrationIT` (`:56`, `:256-260`, `:273-279`, `:290-295`) + a V11 footer re-execution test | Counts and names; RC-48.2 semantic IT |
| S1 V11 | `PermissionsCatalogueIT` | `ALL` grows; sensitive-set parity (B5) |
| S1 V11 | `PermissionsCatalogueTest` (`common/security`) | Scans `@RequiresPermission` values; new constant used by B1 |
| S1 V11 | ITs that build an administrator from literal ids (20 files with V5/V6 literals, §3.2 item 5) | May silently stop being admin-defining |
| S1 V11 | Frontend `permission.ts` consumers: `app.routes.spec.ts`, `auth.store.spec.ts` (2 refs to `PERMISSIONS`) | New member |
| S1 V11 | k6 scenarios referencing the catalogue (`token-refresh.js`, `detach-refresh-storm.js`) | **[UNVERIFIED]** whether they hardcode 8 |
| S1 | `EndpointClassificationWebTest` (all-flags context, `:322-339`) | us019 flag, 5 new handlers |
| S1 | `RbacRoleManagementFeatureFlagTest` | B3 handler under us015 |
| S1 | New us019 flag test | B1/B2/B4 |
| S1 | `PermissionControllerTest`, `RoleControllerTest` | B5 field, B3 |
| S1 (if moved) | `PageParamsTest`, `PageLinksTest`, `PageResultTest` + 10 other test files | Package move |
| S3 | `RoleAssignmentServiceTest` and throttle ITs | B7 403 → 429 |
| S3 | `GlobalExceptionHandler` tests asserting the `RBAC_001` body | B7 additive `reason` (G13: no test was found that freezes the body shape by field set **[UNVERIFIED]**) |
| S3 | `SecurityConfigWebTest` | CORS headers (B8) |
| S3 | `RoleManagementServiceTest` (Mockito: unstubbed M13 = deny, US-018 §15.1) | B8 success paths need stubs |
| S2 | `permission-guard-contract.spec.ts` (`:46-52`, `:175`, `:267-287`) | Option (b) |
| S2 | `dashboard.component.spec.ts`, `app.spec.ts`, `table.spec.ts`, `dialog.spec.ts` | A2, A4, A3 |
| S2 | `e2e/auth/logout.spec.ts`, `e2e/auth/session-refresh.spec.ts` | Test ids if moved |
| S4 | `DevDataInitializerTest` | Personas, idempotency, profile |

### 12.2 Must keep passing unmodified

`CrossTenantPermissionIT`, `CrossTenantNotFoundEquivalenceIT` (extended, not changed), `UserRolesAppendOnlyIT`, `UserRolesPrivilegeIT`, `RolePermissionsPrivilegeIT` (unless a grant changes), `PermissionMigrationFooterScannerTest` (must pass on V11 unmodified), the four `permission.guard.spec.ts` fail-open tests (pinned, RES-39), `e2e/access-denied.spec.ts` (Access Denied stays outside the shell), `api-error.interceptor.spec.ts` (A6 verify only), `LastAdminLockoutIT` outcomes.

### 12.3 New tests the design must name

V11 semantic IT; B1 two-tenant isolation, exact field set, email miss vs other-tenant hit indistinguishable; B2 101 ids; B3 deleted/cross-tenant; B4 revoked-before-refresh and admin-equivalent custom role; B8 one-violation-rolls-back-all, no-op, 412/428, concurrent `PUT`s, `PUT` vs detach, `nexus_app` locking-read IT; B7 429 with `Retry-After` and allow-list; B10 OpenAPI completeness; A1 delayed-refresh router test and single-refresh assertion; A10 adversarial `returnUrl`; C4 executed-test count and zero skips.

---

## 13. Performance, observability, rollout

### 13.1 Performance and N+1 hot spots

| Path | I/O | Risk | Verification |
|---|---|---|---|
| B1 list, status filter | `idx_users_tenant_id_status (tenant_id, status)` (`V2:30`); InnoDB secondary index carries the PK, so `ORDER BY id` within one status is index-ordered **[INFERENCE]** | Low | `EXPLAIN` |
| B1 list, no status filter | `WHERE tenant_id = ? ORDER BY id` is not index-ordered by that index → filesort over the tenant's users **[INFERENCE]** | Medium at large tenants | `EXPLAIN` at seeded volume; index option §11.1 |
| B1 count query | One `COUNT(*)` per page (as roles do, `JpaRoleRepository.java:37-38`) | Low | — |
| B1 email decryption | AES-GCM per row, ≤ 100 rows | Low CPU | Microbenchmark not required |
| B1 `email=` | `uq_users_tenant_id_email_hmac` (`V2:27`) | Low | — |
| B4 | 3–4 indexed reads per call (role names, permission names, M13, M15), no cache, called once per console open | Low (not hot path, NF-F1) | p95 at dev volume |
| B6 | Two grouped reads per page, never per role (NF-F2) | N+1 if done per row | Query-count assertion in an IT (Hibernate statistics or a counting datasource) |
| B8 | ≤ 9 inserts/deletes + ≤ 9 audit inserts in one transaction; set lock when admin-defining; post-commit O(holders) | Lock hold time on admin roles | Re-baseline the lock-hold timer (US-018 kept it) |
| V11 | Footer statements scan `roles` × `permissions` once | Negligible at today's volume | Migration IT |

No RPS/p95 targets exist (Gap G1); requirements NF-F1 proposes p95 < 200 ms at dev volume.

### 13.2 Observability additions (names are placeholders for `/design`; `docs/observability-standards.md:96-108`)

- **Metrics:** request/outcome counters for B1, B2, B4, B8; B1 email-lookup counter and throttle counter; cross-tenant misses through the existing `nexus.rbac.permission_denied{reason=CROSS_TENANT_TARGET}` series for rbac, an identity equivalent for B1/B2; B8 outcomes including 412/428 and "no-op"; B7 throttled 429 through the existing `nexus.rbac.denial_throttled` (`RoleAssignmentService.java:127`, `:648-653`). **Never** email, user id or tenant id as a label (`observability-standards.md:106-108`; US-018 B3 removed `tenantId` tags).
- **Logs:** actor id, tenant id, correlation id, outcome; WARN on cross-tenant (existing `RBAC_CROSS_TENANT_TARGET` shape, `RoleManagementService.java:528-534`). Never the email, the queried email or a request body. Fix `DevDataInitializer.java:100`.
- **Audit:** B8 one event per change via the existing `ROLE_PERMISSION_GRANTED`/`REVOKED` (inline, A6); B1 lookup event per Q-N1 (new `AuthEventType`, no email); B4 none (AS8); B7 denial audit unchanged.
- **Dashboards/alerts:** B1 lookup rate per tenant is an enumeration signal; it must come from logs or audit (tenant is not a metric label).

### 13.3 Rollout and flags

| Change | Flag | Implication |
|---|---|---|
| V11 | **None** (migrations are unconditional) | Applies to prod on deploy; §3.2 runbook (exposure check, cache flush) is mandatory |
| B1, B2, B4 | new `feature.nexus-us019-user-directory.enabled`, default `false` in `application.yml`, `true` in `-dev.yml`/`-test.yml` | Add to `application.yml:280-294`; prod file needs no change (inherits `false`) |
| B3, B5, B6, B8 | us015 (existing) | Additive fields appear wherever us015 is on |
| B7 | **None of its own** | Changes every `RBAC_001` body and the us012 throttled status; Gate 2 decides whether to flag it |
| A-group | None (frontend ships with the build) | Shell, guards and wrappers change the signed-in UX for everyone on deploy; no runtime toggle |
| Kill switch | us019 off → 404 `RESOURCE_NOT_FOUND` on B1/B2/B4 | B4 off also removes the console's live profile (US-020 F6) |

Percentage rollout is not possible with boolean flags (Q-N8, `docs/deployment-process.md` **[REPORTED]**). Flag clean-up is unplanned (G10).

---

## 14. Top risks

| # | Risk | Severity | Verification |
|---|---|---|---|
| 1 | V11 changes the admin threshold globally and unflagged; a wrong footer demotes every custom administrator; cache/token lag gives admins 403 on B1; literal-id test fixtures silently lose admin status (§3.2) | **High** | Scanner on V11; RC-48.2 semantic IT (full-catalogue custom role gains it, 7-of-8 gains nothing); zero-admin indicator green across the migration; runbook flush before enabling us019; audit of the 20 literal-id test files |
| 2 | B8 ETag TOCTOU, lock order versus RC-46, unproven `nexus_app` privilege for a locking read on `roles`, residual race with attach/detach, zero-administrator race on demotion (§5.4) | **High** | Concurrent-`PUT` IT; `PUT` vs detach IT; `nexus_app` raw-JDBC locking-read IT; harness re-run with the set-lock path; health indicator after a demoting `PUT` race |
| 3 | Directory PII: `?email=` in nginx logs, browser history, `PageLinks`; enumeration oracle via `email=` and `ids=` (§4.1) | **High** | D5 ruling; log-scan test of a full request cycle; miss vs other-tenant-hit byte equality; throttle IT |
| 4 | C2/C4 silently green: skip-on-unreachable, shared `storageState` reuse revocation, login rate limits, port mismatch (§8.2, §8.3) | **High** | CI asserts executed count > 0 and zero skips; backend health gate before tests; per-worker login |
| 5 | B7 disclosure: explicit 429 on the RES-33 bit; `GRANT_EXCEEDS_CALLER` as a one-bit composition oracle; stale `NOT_TENANT_ADMIN` name frozen on the wire; unflagged (§5.2) | **High** | Threat model sign-off; allow-list unit tests; opaque-path tests (malformed, missing tenant) |
| 6 | A1 second `POST /refresh` on cold start (R5) | **High** | Router test counting refresh calls |
| 7 | B4 `isAdministrator` diverges from the server's predicate (R7) | **High** | IT with an admin-equivalent custom role and with a revoked role before refresh |
| 8 | C1 second tenant cannot sign in (single-tenant login) and has no system roles or break-glass (§8.1) | Medium | Gate 2 decision; e2e scope stated accordingly |
| 9 | Paging relocation touches 33 files of US-018 code (§4.6) | Medium | Mechanical commit, full `./mvnw verify` |
| 10 | Shell + `app.html` double header, nested `<main>` landmarks, test-id churn (§6.1) | Medium | axe landmark rules in e2e; specs updated in the same commit |
| 11 | CORS strips `If-Match`/`ETag` in dev (§5.4) | Medium | `SecurityConfigWebTest`; e2e of a `PUT` in dev |
| 12 | B6 `memberCount` misused by US-020 C5 as "last administrator" (§5.1) | Medium | US-020 correction; B6 Javadoc |
| 13 | ADR-0021–0025 still "Proposed"; B8 builds on 0021/0024 (R10) | Medium | Status confirmed before Gate 2 |

---

## 15. Open questions for `/design` (architect pass at Gate 2)

**Data and catalogue**
- **Q-D1** Is `user:directory:read` in the `isSensitive` set? Which other members? (D5/Security owns membership; design owns the parity test.)
- **Q-D2** Does any C1 persona besides administrators hold `user:directory:read` (the "user manager")?

**Directory (B1/B2)**
- **Q-D3** Email lookup transport: `GET ?email=` (api-design default for filters) versus a body-carrying lookup to keep PII out of URLs and proxy logs. D5 must accept whichever is chosen.
- **Q-D4** Response code for missing/cross-tenant user and whether it is deliberately distinct from flag-off `RESOURCE_NOT_FOUND`.
- **Q-D5** List ordering (by id, by `created_at`) and whether an index is added; default status filter (include `DISABLED`?).
- **Q-D6** `ids=` shape, duplicate handling, malformed-UUID response, 101-id response; combination rules with `email`/`status`.
- **Q-D7** `PageLinks` with filters: echo `status`, never echo `email`?
- **Q-D8** Lookup throttle bucket key and limits; audit event type and metadata (no email).
- **Q-D9** Paging types: move to `common` (and `PageResult` with them), duplicate, or import.

**B3/B4/B5/B6**
- **Q-D10** B4 response for a user with zero roles; B4's port placement (`UserRoleQueryPort` versus `UserRoleAssignmentPort` M13/M15).
- **Q-D11** Which `RoleResponse` endpoints carry counts (list only, or also create/PATCH/B3)?
- **Q-D12** `memberCount` definition (active assignments of a live role; users' status ignored) and the projection shape.

**B7**
- **Q-D13** Wire values for `reason` decoupled from `DenialReason` names? Final allow-list after US-018 (is `NOT_TENANT_ADMIN` still meaningful)?
- **Q-D14** `RoleChangeThrottlePort` change shape for retry-after; 429 `code`; fail-safe preserved.
- **Q-D15** Flag B7 or ship unflagged?

**B8**
- **Q-D16** ETag source: content hash of permission ids versus version column (migration, grant, health indicator).
- **Q-D17** ETag on `GET /roles/{id}` (B3) or on `GET /roles/{id}/permissions`; weak or strong.
- **Q-D18** Serialisation mechanism for compare-then-write, its lock order relative to the set lock (RC-46), and proof of `nexus_app` privilege.
- **Q-D19** Confirm Q5 (set lock on before-or-after admin-defining) in the threat model; accepted residual versus concurrent attach/detach.
- **Q-D20** Semantics of empty set, unknown id (404 vs 400), duplicates, max length; response body and status (200 with the new set, or 204).
- **Q-D21** Audit metadata: per-change rows only, or also a correlation id tying the rows of one `PUT`?

**Frontend**
- **Q-D22** Q12(b) mechanics: public layout route versus conditional root header.
- **Q-D23** Where the shell primes proactive refresh (today the dashboard's `/v1/users/me` fetch).
- **Q-D24** Unit-level axe mechanism (G8) and its dependency cost.
- **Q-D25** A11 recorded-response source and how it stays current without coupling the builds.

**Environments**
- **Q-D26** C1 second tenant: fixture-only data, or a second backend instance with another default tenant in compose/CI?
- **Q-D27** C2 login strategy under `fullyParallel` and the login rate limits.
- **Q-D28** C4 on compose `full` (backend as `nexus_app` on 1000, nginx frontend on 2000) versus jar + dev server; replace Playwright's `webServer` in CI?

---

## 16. Not verified

- Flyway transactional behaviour for V11 in this repo's config (§3.2 item 3).
- MySQL 8.4 privilege rule for `SELECT … FOR UPDATE` with column-level `UPDATE` only (§5.4).
- nginx default access logging of the query string in the frontend image (§4.1).
- Whether `SecurityConfigWebTest` pins the CORS lists; whether any test freezes the `RBAC_001` body field set (G13); whether k6 scenarios hardcode the catalogue size.
- Which of the 20 test files with seeded-id literals rely on a full-catalogue administrator.
- Angular `combineLatest` versus per-level sequencing (A1) and Spring literal-over-variable path precedence: framework behaviour **[REPORTED]**, to be proven by the A1 router test and the EndpointClassification sweep.
- Whether frontend-ci's `e2e` job is a required status check (Q9).
- Production flag values (only the absence of overrides in `application-prod.yml` is verified).
