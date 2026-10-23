# US-020 — RBAC Access Management console (tenant administrators): Requirements

**Status:** Gate 1 approved · **Owner:** Business Analyst · **Approver:** the story owner (Md Nisar Ahmed)

**Gate 1:** approved 2026-10-23 by Md Nisar Ahmed (all open questions resolved by Claude under his delegation, section 12a; none is a Legal, DPO, UX, PM or Ops sign-off)
**Date:** 2026-10-23 · **Base:** `main` @ `adda702` (US-019 merged, PR #93), branch `feature/US-020`
**Risk tier (from discovery):** high-risk (permission gates, the lockout logic the UI predicts, PII shown to directory holders, user-authored text rendered in a page). Full Gate 2 threat model and Phase 7 audit apply. The tier is for the story owner to confirm (Q27).

**Sources:** `docs/story/2-rbac/US-020.md` (the story, written against `9820d4e`, "approved by the product owner 2026-10-05; not yet through Gate 1"), `docs/features/US-020/00-discovery.md`, `docs/features/US-019/{01-requirements,03-design,09-technical,14-pending-items,15-delegated-decisions}.md`, `docs/features/US-018/09-technical.md` (M9 and A9), `PROJECT.md`, `CLAUDE.md`, and the code at `adda702` (cited as `path:line`; paths under `nexus-backend/src/main/java/com/example/nexus/` are shortened to `…/`).

**Evidence tags.** **[VERIFIED]** = I read it in code or config on 2026-10-23. **[REPORTED]** = taken from a doc and not re-read in code. **[INFERENCE]** = my reading, not stated in a source. **[CONFIRM]** = needs stakeholder sign-off.

**Ground rules for this document.** It states what must be true. It does not choose an implementation. Where the source is silent I say so (section 13) and ask (section 12); I do not fill the gap with a default (gaps are listed in section 13). Every "recommended default" in section 12 is a proposal and is **not approved**. No real names, emails or credentials appear; people are referred to by role, and users and roles by id or persona key.

---

## 1. Context

Tenant administrators can manage access today only with raw HTTP calls. The RBAC backend is complete and merged (US-009 to US-019): roles and permissions, assignments, grant-subset rules, last-administrator protection, the permission epoch, access-review reads, the user directory, the caller's live authorization profile and the atomic permission replace. No screen calls any of it. US-020 adds the Access Management console to the Angular app: a roles list, a role detail page, a role editor with a staged review step that shows what a change adds, removes and affects, a permission catalogue, a users area, and assign and revoke flows with lockout awareness. The goal, in business terms, is that an administrator can run least-privilege access control without API calls, support tickets or the risk of locking the tenant out, and that the console never claims more certainty than the server gives (frontend gating is UX only; the server is the only security boundary, `PROJECT.md` Key Constraints).

The story is **frontend only** ("No backend changes in this story", story Technical Notes). The code shows that claim is mostly, but not entirely, true (section 3.9, Q16 to Q19).

## 2. Scope and non-goals

**In scope:** the story's 45 criteria (A1 to A6, B1 to B7, C1 to C6, D1 to D4, E1 to E3, F1 to F8, G1 to G11), restated in section 5 against current code, plus six requirements that the shipped backend adds and the story lacks (FR-X1 to FR-X6).

**Non-goals** (story "Out of Scope", restated so nobody pulls them in): backend endpoints of any kind; user invitation, provisioning, deactivation and profile editing (Epic 3); direct user-to-permission grants; time-bound or eligible assignments; access-review campaigns; least-privilege recommendations; a per-role audit History tab; bulk assignment and CSV import; role hierarchy, ABAC, resource-scoped assignments; a platform or super-admin console; i18n.

## 3. Backend and platform facts the console is built against (re-grounded at `adda702`)

### 3.1 Endpoints, gates and flags **[VERIFIED]**

| Endpoint | Permission | Flag | Paging / notes | Code |
|---|---|---|---|---|
| `GET /api/v1/roles` | `role:read` | us015 | **Paged** (`page` 0-based default 0, `size` default 20, 1 to 100, out of range is 400, never clamped). Order `(name, id)`. Each role has `memberCount`, `permissionCount`, `isSystemRole`. No search or filter parameters | `…/rbac/interfaces/rest/RoleController.java:135-171`, `PageParams.java:17-28` |
| `POST /api/v1/roles` | `role:write` | us015 | 201; 409 `RBAC_006` / `RBAC_007` / `RBAC_008` | `RoleController.java:96-133` |
| `GET /api/v1/roles/{id}` | `role:read` | us015 | `memberCount`, `permissionCount`. **No ETag** | `RoleController.java:173-204` |
| `GET /api/v1/roles/{id}/permissions` | `role:read` | us015 | **Unpaged** `{data}`; carries the **`ETag`** of the set | `RoleController.java:206-242` |
| `PUT /api/v1/roles/{id}/permissions` | `role:write` (and `role:read` in live holdings) | us015 | Body `{permissionIds}` max 100, no repeats; `If-Match` required; atomic; unchanged set is a no-op 200 | `RoleController.java:244-326` (403 text `:270`) |
| `POST` / `DELETE /api/v1/roles/{id}/permissions[/{pid}]` | `role:write` | us015 | Attach 201, detach 204; no ETag | `RoleController.java:351-445` |
| `PATCH /api/v1/roles/{id}` | `role:write` | us015 | name and/or description; **no If-Match, last write wins** | `RoleController.java:447-495` |
| `DELETE /api/v1/roles/{id}` | `role:write` | us015 | Soft delete; 409 `RBAC_009` while holders exist | `RoleController.java:497-535` |
| `GET /api/v1/permissions` | `role:read` | us015 | **Paged**; `isSensitive` from `Permissions.SENSITIVE` | `…/rbac/interfaces/rest/PermissionController.java:49-89` |
| `POST /api/v1/users/{id}/roles` | `user:role:assign` | us012 | 201; 409 `RBAC_004`, `RBAC_012`; 429 `RBAC_011` | `…/rbac/interfaces/rest/UserRoleController.java:61-133` |
| `GET /api/v1/users/{id}/roles` | **`user:read`** | us012 | **Paged**, order `(assignedAt, id)`. Fields only `userId, roleId, roleName, assignedAt, assignedBy` | `UserRoleController.java:135-180`, `dto/RoleAssignmentResponse.java:13-14` |
| `DELETE /api/v1/users/{id}/roles/{roleId}` | `user:role:assign` | us012 | 204; 409 `RBAC_002`; 429 `RBAC_011` | `UserRoleController.java:182-231` |
| `GET /api/v1/roles/{id}/holders` | `audit:read` | us015 | Paged; **ids only**; `assignedBy` null unless caller is an administrator | `…/rbac/interfaces/rest/AccessReviewController.java:62-108` |
| `GET /api/v1/permissions/{id}/holders` | `audit:read` | us015 | Paged; user ids and granting role ids | `AccessReviewController.java:110-151` |
| `GET /api/v1/users/{id}/effective-permissions` | `audit:read` | us015 | Permission names with granting role ids | `AccessReviewController.java:153-186` |
| `GET /api/v1/users` | **`user:directory:read`** | us019 | Paged by id; `status` filter; or `ids=` batch of 1 to 100 (cannot combine with other params); **`email=` is rejected with 400**; `page x size` at most 10,000 | `…/identity/interfaces/rest/UserDirectoryController.java:82-140`, `DirectoryPageRequest.java:24-76` |
| `GET /api/v1/users/{id}` | `user:directory:read` | us019 | 404 `USER_NOT_FOUND` for missing or foreign | `UserDirectoryController.java:142-182` |
| `POST /api/v1/users/lookup` | `user:directory:read` | us019 | Exact email, body `{email}`; zero or one result; 429 `USER_DIR_001` (30 per 60 s) | `UserDirectoryController.java:184-236`, `application.yml:256-258` |
| `GET /api/v1/users/me/authorization` | authenticated only | us019 | `{userId, roles[{roleId,name}], permissions[], isAdministrator}`, live from the database | `…/rbac/interfaces/rest/CallerAuthorizationController.java:30-71`, `dto/CallerAuthorizationResponse.java:11-26` |

**Flags.** `feature.nexus-us012-rbac-role-assignment`, `…-us015-rbac-role-management` and `…-us019-user-directory` default `false` in `application.yml:303-316`; `true` in `application-dev.yml:53-58` and `application-test.yml:11-16`; no `application-prod.yml` entry, so `false` in production unless an environment override exists, which the repo cannot show **[VERIFIED]**. A disabled controller is absent and the route answers 404 `RESOURCE_NOT_FOUND` (`…/common/web/GlobalExceptionHandler.java:215-219`). A **missing resource** answers a different code (`USER_NOT_FOUND`, `ROLE_NOT_FOUND`), so flag-off is distinguishable from not-found by `code` (see 3.7).

**What a screen needs, by flag.** Roles, role detail, catalogue and Members/Effective/holders reads: us015. Users' roles, assign, revoke: us012. User directory (emails, ids to emails) and the profile that drives every affordance: us019. A fully working console therefore needs **all three** on; a role-only or users-only console is a partial state (Q9).

### 3.2 Error contract **[VERIFIED]**

RFC 7807 problem with `code`, `traceId`, `details[]` for validation (`GlobalExceptionHandler.java:106-112, 159-172`).

| Status / code | Meaning | Source |
|---|---|---|
| 403 `RBAC_001` + `requiredPermission` + `reason` ∈ {`GRANT_EXCEEDS_CALLER`, `SELF_ASSIGNMENT`, `ADMINISTRATOR_REQUIRED`, `UNSPECIFIED`} | `reason` is the allow-listed caller-facing value; everything else collapses to `UNSPECIFIED` | `…/common/security/CallerFacingDenialReason.java:14-26`; `GlobalExceptionHandler.java:188-206` |
| 403 `ACCESS_DENIED` | Filter-level; no `reason` | `GlobalExceptionHandler.java:208-213` |
| 409 `RBAC_002` | Would revoke the tenant's last active administrator. Message text hard-codes "TENANT_ADMIN" | `…/rbac/domain/LastAdminRoleException.java:20` |
| 409 `RBAC_003` system role · `RBAC_004` already assigned · `RBAC_005` already attached · `RBAC_006` duplicate name · `RBAC_007` reserved name · `RBAC_008` role limit · `RBAC_009` role has holders · `RBAC_010` would make a role admin-defining while a holder was assigned by a non-administrator · `RBAC_012` classification changed, **retryable** | | `…/rbac/domain/*Exception.java`; `RoleController.java:276-280` |
| 429 `RBAC_011` + `Retry-After` | Denial throttle on assign and revoke, **only** for an admin-defining or self target; other denials stay 403 | `UserRoleController.java:114-118, 215-219`; `GlobalExceptionHandler.java:120-128`; `application.yml:162-166` (5 per 60 s) |
| 429 `USER_DIR_001` (lookup) / `USER_DIR_002` (ceiling 600 per 60 s) + `Retry-After` | Directory throttles | `UserDirectoryController.java:102-106, 214-218`; `application.yml:256-264` |
| 412 `PRECONDITION_FAILED` / 428 `PRECONDITION_REQUIRED` | PUT permissions: stale or missing `If-Match`; bodies carry no state | `GlobalExceptionHandler.java:89-104`; `RoleController.java:281-295` |
| 404 `ROLE_NOT_FOUND`, `USER_NOT_FOUND`, `PERMISSION_NOT_FOUND`, `ROLE_PERMISSION_NOT_FOUND`, `ROLE_ASSIGNMENT_NOT_FOUND` | Cross-tenant and missing are indistinguishable | controllers' `@ProblemResponse` |
| 400 `VALIDATION_FAILED` | `details[{field,message}]` | `GlobalExceptionHandler.java:106-112, 159-186` |
| 503 `AUTH_005` + `Retry-After: 30` | Any authenticated call after the epoch store has been down past the fail-open window | `…/identity/infrastructure/web/JwtAuthenticationFilter.java:128-131`; `application.yml:188-192` |
| 401 `AUTH_003` | Missing, invalid, or **stale-epoch** token | `JwtAuthenticationFilter.java:124-127` |

**Order matters for the UI.** On revoke the server evaluates the 403s first and `RBAC_002` after them (`…/rbac/application/RoleAssignmentService.java:400-435`), so a caller who is not allowed never sees 409. On PUT the order is 400, 428, 404, 409, 404 permission, 403, then 412 (`RoleController.java:246-248`).

### 3.3 Administrator, admin-defining and "sensitive" **[VERIFIED]**

- A role is **admin-defining** iff it carries every permission in the catalogue; a user is an **administrator** iff they hold an active admin-defining role (per-role, never the union). `docs/features/US-018/09-technical.md` section 1. The profile returns `isAdministrator` (`CallerAuthorizationResponse.java:15-16`). **No endpoint returns "this role is admin-defining"** (`dto/RoleResponse.java:23-30` has `id, name, description, isSystemRole, createdAt, memberCount, permissionCount`).
- **Last-administrator** (`RBAC_002`) counts **distinct holders across all admin-defining roles**, excluding the assignment being revoked (`RoleAssignmentService.java:415-435, 660`). `memberCount` is "active assignments of this role, user status ignored" (`…/rbac/infrastructure/persistence/JpaUserRoleRepository.java:419-431`). So `memberCount == 1` on an admin-defining role does **not** mean "last administrator" (another admin-defining role may have holders), and a disabled or locked sole holder still counts as a holder. US-019 design already says the story's C5 reading is wrong (`docs/features/US-019/03-design.md:303`).
- **Sensitive** is a static set of 6 of the 9 permissions (`tenant:write`, `user:write`, `role:write`, `user:role:assign`, `user:directory:read`, `audit:read`), and it includes two **read** permissions (`…/common/security/Permissions.java:49-53`). The story's badge text ("Grants administrative control over users, roles or the tenant", A4) is narrower; the US-019 design says the copy must match the definition, which also covers PII and audit read (`03-design.md:585`).
- The server's "only an administrator may grant" rule for permissions is keyed to **`user:directory:read` only, "never by `isSensitive`"** (`…/rbac/application/PiiPermissionGrantRule.java:18, 87-93`; `application.yml:173-177`). Other sensitive permissions follow the ordinary grant-subset rule (caller must hold it) plus the admin-defining-role rules. The story's B6 ("a sensitive permission is disabled for non-administrators") and C3(c) are therefore **stricter than the server** (Q18).
- **Role-subset spill-over.** After V11 a role manager without `user:directory:read` cannot detach from, PATCH or DELETE a role that carries it (`03-design.md:366`); the editor must explain that 403.

### 3.4 Paging **[VERIFIED]**

Roles, permissions, a user's assignments, role holders, permission holders and the directory list are all paged with `data`, `page{size,number,totalElements,totalPages}`, `links{next,prev}`. `GET /roles/{id}/permissions`, `effective-permissions` and `/users?ids=` are not paged. The story's "lists are unpaginated" and "up to 500 roles, client-side search" are stale (row 1 below). Default tenant role cap is 500 but is configurable (`RoleManagementService.java:179`), so the story's fixed "500" copy in B2 must not be hard-coded.

### 3.5 PII visibility **[VERIFIED]**

Emails are returned only by the directory endpoints (`UserDirectoryEntryResponse.java:10-21`), which need `user:directory:read`. `user:read` returns **no emails** (it gates `GET /users/{id}/roles`, which returns ids). MEMBER holds `user:read` only (`db/migration/V5__rbac_schema.sql:128-136`). `user:directory:read` may be granted only by an administrator (default ON, `application.yml:173-177`). The dev "user manager" persona holds `user:read, user:role:assign, user:directory:read`; the "role manager" holds `role:read, role:write` (`…/identity/infrastructure/seed/DevDataInitializer.java:80-85`). Emails are self-asserted until verified; the console must show `status` and `emailVerified` beside every email (`03-design.md:496`).

### 3.6 Propagation timing (D4), re-grounded **[VERIFIED] unless tagged**

Config: `nexus.rbac.permission-cache-ttl-seconds` 900 (`application.yml:157`), `nexus.jwt.access-token-ttl-seconds` 900 (`application.yml:269`), epoch `key-ttl-seconds` 960 (`:187`), `fail-open-window` PT15M (`:192`), epoch read timeout 50 ms, bump timeout 500 ms (`:182-184`). The story's "900 + 900 = 30 minutes" is the sum of two TTLs; US-018 A9 has shipped, so the real behaviour is now action-dependent:

| Change | What the server does after commit | Effect on the affected user (healthy Redis) |
|---|---|---|
| **Revoke a role**; **detach** a permission; **replace** that removes any permission | Evicts the permission cache and **bumps the permission epoch** of the user, or of every active holder of the role (`RoleAssignmentService.java:456-475`; `RoleManagementService.java:484-498, 929-972`) | The holder's current access token is rejected on its next request with 401 `AUTH_003` (`JwtAuthenticationFilter.java:122-127`); the SPA then refreshes silently and replays the request (`nexus-frontend/src/app/core/http/auth.interceptor.ts:188-201`). Effect is **on the next request**, not 30 minutes [INFERENCE for the end-to-end timing; each step is verified] |
| **Assign a role**; **attach** a permission; **replace** that only adds | Evicts the permission cache only (`RoleAssignmentService.java:207`; `RoleManagementService.java:962-971`). No epoch bump | The holder's **existing token still carries the old permissions** (`JwtAuthenticationFilter.java:136-139`) until it is refreshed or they sign in again: up to the access-token TTL, 900 s (about 15 minutes), the proactive refresh threshold being 2 minutes before expiry (`auth.interceptor.ts:37`). The cache TTL adds to this only when an eviction fails or the change was out-of-band [INFERENCE] |
| Any of the above during a **Redis outage** | A refused bump is queued and replayed each second; the failing instance evicts the cache and treats tokens below its locally known epoch as stale; **tokens already issued stay valid on other instances for their TTL** (RES-46) (`docs/features/US-018/09-technical.md:161, 169`) | Revocation can lag up to the token TTL (900 s) on instances that did not see the bump. After the epoch store has been down longer than PT15M, **every authenticated request returns 503 `AUTH_005`** with `Retry-After: 30` (platform-wide, RES-30, SRE/PM acceptance pending, `09-technical.md:173`) |

Consequences for F3: (1) "about 30 minutes" is a safe **upper bound** for both actions, not the typical case, and it would mislead if the UI presented it as the expected delay; (2) revoke and grant behave differently; (3) a user who is on the page when their own access is revoked gets a 401-then-refresh, then possibly 403s; (4) the console must be able to render 503 `AUTH_005` on any call. The wording is a human decision (D4, Q3).

### 3.7 Flag-off versus not-found **[VERIFIED]**

Flag off: 404 `RESOURCE_NOT_FOUND`. Missing or foreign id: 404 `USER_NOT_FOUND` / `ROLE_NOT_FOUND` / etc. The US-019 design chose distinct codes on purpose so the console can tell them apart (`03-design.md:97`). The US-019 requirements doc says the UI "cannot tell flag-off from not-found per id" (`docs/features/US-019/01-requirements.md:225`); that is superseded by the shipped codes. Story F6 ("the whole resource returns 404") is therefore implementable per endpoint by `code`.

### 3.8 Frontend state at `adda702` **[VERIFIED]**

- Shell exists with `authGuard` on the parent; `/dashboard` and `**` are children; no console route (`nexus-frontend/src/app/app.routes.ts:112-130`).
- `NavItem.permission` is `Permission | null` (single permission); `NAV_ITEMS` holds Dashboard only; `visibleNavItems` tests one permission (`…/core/layout/nav.config.ts:5-38`).
- `Permission` union has 9 members including `user:directory:read`; `PERMISSION_LABELS` and `PERMISSION_GROUP_LABELS` are placeholder copy of backend descriptions "until D3" (`…/shared/types/permission.ts:13-62`).
- `apiErrorInterceptor` redirects on 403 `RBAC_001` unless `SKIP_ACCESS_DENIED_REDIRECT`; carries `reason` and `retryAfterSeconds`; toasts once per window on 503 `AUTH_005` (`…/core/http/api-error.interceptor.ts:27-88`).
- `authGuard` returns `false` (navigation cancelled) when the cold-start refresh fails with `AUTH_005` or a network error; the user is left on a blank shell with only the toast (`…/core/guards/auth.guard.ts:36-41`).
- Wire types exist for roles list, role, permission, caller profile, directory page, lookup, and the replace request. **Missing:** assignment list, holders, permission holders, effective permissions, create and update requests, `ETag` handling, and error codes `RBAC_002`, `RBAC_006` to `RBAC_009`, `USER_DIR_001/002` (the `RbacErrorCode` union is `RBAC_001, 003, 004, 005, 010, 011, 012`) (`…/shared/types/api/rbac.ts:79-80`). `contracts/api/` has 12 recorded fixtures and none for these shapes.
- Components in `shared/ui` the story needs exist: table, tabs, breadcrumb, chip, tooltip, menu, skeleton, search-field, page-header, dialog, checkbox, announcer, error-state, empty-state.
- E2E personas: `admin, admin2, member, roleManager, userManager` can sign in; `locked, pending, otherTenantAdmin` cannot (`nexus-frontend/e2e/fixtures/personas.ts:5-41`). Existing specs under `e2e/access-management/`: shell, cold-start, not-found, return-url. No gated route exists yet, so the unentitled-user `/access-denied` e2e (P-27) is still open.

### 3.9 Where "no backend changes" does not obviously hold

Stated as open questions, not assumptions (Q16 to Q19, Q10):

1. **Last-administrator prediction (C5).** Not derivable from `memberCount` and not otherwise exposed. Without a server change the UI cannot disable the action "up front" exactly; it can only rely on the 409.
2. **Admin-defining flag per role** (C3(c), C5, B3 impact). Not in any DTO. A client can only infer it by comparing `permissionCount` with the catalogue's `totalElements`, which re-implements a server rule in the UI (the exact trap the story names for `TENANT_ADMIN`).
3. **Audited CSV export (E3).** The US-019 design says export "is audited" (`03-design.md:496`). A client-side CSV built from paged reads leaves only the per-read access-review log, not an export audit event.
4. **Assignment dialog for a non-role-reader.** The user-manager persona has no `role:read`, so it cannot list roles or read a role's permissions to populate the picker (C3), though it holds everything else assignment needs.
5. **User access page needs a role join** (System badge, permission summary, admin-defining check): `GET /users/{id}/roles` returns names and ids only. Doing this by calls per row conflicts with F8 ("no request waterfalls beyond those named").

## 4. Story text versus current code (corrections)

Discovery rows were re-verified; each is marked **Confirmed**, **Corrected** or **Extended**. Rows N1 to N14 are new.

| # | Story says | Code at `adda702` | Verdict and effect |
|---|---|---|---|
| 1 | Lists are unpaginated `{data}` (Background); A2 "up to 500 roles", client-side search and filter; D4 "server pagination" waits on US-018 C2 | `GET /roles`, `GET /permissions`, `GET /users/{id}/roles`, holders and directory lists are paged; `GET /roles/{id}/permissions` is the unpaged one (3.1) | **Confirmed, extended** (discovery omitted the assignments list). D4 is not future work. Client-side search over "all roles" needs 5 sequential 100-row pages at the 500 cap, or a UX that searches only the loaded page (Q5). Server order is `(name, id)`, so A2 "system roles sort first" cannot be a server order across pages |
| 2 | Groups D and E wait for US-018 M9 | M9 shipped: PATCH/DELETE roles, role holders, permission holders, effective permissions all exist (3.1) | **Confirmed.** All three E endpoints and the D endpoints are behind **us015**, plus `audit:read` for D1/E; email join additionally needs us019 and the directory permission |
| 3 | Users list needs `user:read`; emails to `user:read` holders; routes `/admin/access/users[/:id]` gate on `user:read`; "MEMBER sees Users only" (scenario 2) | Directory is `user:directory:read` (3.1, 3.5). `user:read` gates only `GET /users/{id}/roles` and returns no emails. MEMBER has `user:read` only, so MEMBER has **no** directory access | **Confirmed, extended.** C1/C2/D1 route permission, nav gating and scenario 2 change; the US-019 design already supersedes it (`03-design.md:302`). A holder of `user:read` without the directory permission has a working `GET /users/{id}/roles` but no way to find a user id |
| 4 | B4: sequential attach/detach until B8; G3 "last-write-wins, no ETag" | `PUT` is atomic with `ETag`/`If-Match` (412, 428); 403 precedes 412; `RBAC_012` is retryable (3.1, 3.2) | **Corrected.** (a) The ETag is on `GET /roles/{id}/permissions`, **not** `GET /roles/{id}` (`RoleController.java:174-175`), so the editor needs that call. (b) PUT also requires `role:read` live. (c) `PATCH` has **no** If-Match (last write wins, `:450-451`), so G3's wording still holds for rename. (d) Test scenarios 7 and 18 are rewritten. (e) The US-019 design records a carry-forward: retry `RBAC_012` **exactly once**, awaiting US-020 acceptance (`03-design.md:8, 304`) |
| 5 | `RBAC_001` is generic until B7 | `reason` is one of four values; 429 `RBAC_011` with `Retry-After` (3.2) | **Confirmed, extended.** Copy is needed for four reasons, `RBAC_011`, `USER_DIR_001/002`, 412, 428, 503 `AUTH_005`; the frontend error-code union lacks `RBAC_002` and `RBAC_006` to `RBAC_009` (3.8). `UNSPECIFIED` also covers throttle and unknown cases, so it cannot be worded as "you lack the permission" without qualification (Q15) |
| 6 | Nav shows "Access management" to anyone holding `role:read` **or** `user:read` | `NavItem.permission` is one `Permission | null` | **Confirmed.** Any-of needs a shell model change or a single gating permission (Q7). Note `user:read` is the wrong half of the pair (row 3) |
| 7 | Role detail uses `GET /roles/{id}` | Exists with `memberCount`, `permissionCount` | **Confirmed.** Detail also needs `GET /roles/{id}/permissions` for the matrix and ETag |
| 8 | "Administrator" = `isAdministrator` from the live profile | `GET /users/me/authorization` exists, own data, live, **under the us019 flag** | **Confirmed.** When us019 is off the profile is a 404 and the console has no source for affordances (FR-X4) |
| 9 | Permission labels and groups come from the D3 deck | Placeholder copy of backend descriptions (3.8) | **Confirmed.** D3 is a hard dependency for A3/A4 copy; the catalogue now has 9 entries, not the 8 the US-019 doc mentions |
| 10 | F6: console shows "isn't enabled" if the resource returns 404 | Three flags; disabled controller gives `RESOURCE_NOT_FOUND`, a missing id gives a different code (3.7) | **Corrected.** Distinguishable by `code`. F6 must still say which area is off and what to do (Q9) |
| 11 | (Discovery) cold-start 503 leaves a blank shell | `authGuard` returns `false`; the interceptor toasts (3.8) | **Confirmed.** P-20/P-32 were closed by delegated decision to "accept for US-019; US-020 designs the retry view" (`15-delegated-decisions.md`), so the view is a US-020 deliverable (Q4, FR-X3). Backend 503 `AUTH_005` can also hit **any** console call after a Redis outage longer than 15 minutes |
| 12 | Propagation "about 30 minutes"; US-018 A9 "will shorten" | A9 shipped; behaviour is action-dependent (3.6) | **Corrected.** The story's premise is stale. Revoke is near-immediate with a healthy store; grant is up to the token TTL |
| N1 | C5: "admin-defining and `memberCount` is 1 means last administrator, disable up front" | Lockout counts distinct holders across all admin-defining roles; no admin-defining flag in any DTO (3.3) | **Incorrect story text** (`03-design.md:303`). Over- and under-predicts. See Q16 |
| N2 | B6 / C3(c): "sensitive permission is disabled for non-administrators", "admin-defining role needs an administrator" | Server's administrator requirement is keyed to `user:directory:read` (and to admin-defining roles), not to `isSensitive` (3.3) | **Story stricter than server.** UI would block actions the server allows (Q18) |
| N3 | C2: row shows "System badge", C5: "{permission summary}" from `GET /users/{id}/roles` | That DTO has no system flag and no permissions (3.1) | **Gap.** Needs `GET /roles` and per-role `GET /roles/{id}/permissions`, both `role:read` (3.9 items 4, 5) |
| N4 | A4 badge text "administrative control over users, roles or the tenant" | Sensitive set includes `audit:read` and `user:directory:read` (3.3) | **Text narrower than the data.** Copy must match the definition (D3) |
| N5 | B2 `RBAC_008` banner "maximum of 500 roles" | Cap is `nexus.rbac.max-roles-per-tenant`, default 500, configurable (`RoleManagementService.java:179`) | **Copy must not hard-code 500** |
| N6 | B1 description "no control characters" client rule | Server pattern forbids control characters only; `<`, `>` and quotes are accepted (`dto/CreateRoleRequest.java:29-33`); name pattern as story | Matches; shows why G9 (no HTML sinks) is load-bearing |
| N7 | Dev personas for e2e | `userManager` holds no `role:read`; **no persona holds `audit:read` without being an administrator** (3.5) | **Persona gaps** for C3 and for non-admin Groups D/E (Q12) |
| N8 | E3 export client-side | US-019 design: export "is audited", PENDING-user policy left to US-020 (`03-design.md:496`) | **Unresolved carry-forwards** (Q19, Q21) |
| N9 | C1 "exact-email lookup field", "paged `NxTable`" | Lookup is `POST /users/lookup`, 30 per 60 s per actor; search field must use `mode="submit"` (`03-design.md:968`); list order is by id; rows beyond offset 10,000 are unreachable (`DirectoryPageRequest.java:27, 71-75`) | **Extended** |
| N10 | G1 "page number in query params" | Directory paging is capped at `page x size <= 10,000` | Deep link past the cap gives 400 `VALIDATION_FAILED` |
| N11 | A2 "created date, permission count" present | Provided by `RoleResponse` | Confirmed |
| N12 | C2 "Assigned by (shown only when the API returns it)" | `assignedBy` is null for non-administrators (`RoleAssignmentResponse.java:9-11`; `RoleAssignmentService.java:495-498`) | Confirmed. A null also occurs for any other missing value, so "redacted" and "none" are indistinguishable [INFERENCE] |
| N13 | Background "Five areas: ... Access review" | Only Roles, Users, Permissions have routes in the story's route table; Access review is delivered as tabs and links | Story inconsistency (low) |
| N14 | G11 "Learn more link to the developer/admin guide" | The story names no guide and no URL | Gap (section 13, G13) |

## 5. Functional requirements (traceability A1 to G11)

Columns: **Story pri** is the story's; **Proposed** is my restated proposal (not approved); **Slice** is from section 6. "Depends on" lists shipped code or platform items; "Human" marks a decision or artefact that code cannot satisfy. Behavioural items use Given/When/Then. Every F and G requirement applies to **every page and dialog in every slice**; the slice column says where it first becomes testable.

### Group A: console area, roles list, catalogue

| ID | Requirement (testable) | Depends on | Story pri → Proposed | Slice |
|---|---|---|---|---|
| **FR-A1** | **Given** an entitled user, **when** they open or reload any console URL, **then** they stay on it. **Given** a user without the route's permission, **then** `/access-denied`. **Given** signed out, **then** `/auth/login` with `returnUrl`. Each child route carries `permissionGuard` with a typed `data.permission` and has a unit test (the guard fails open on a missing value). Nav items and the dashboard card use any-of or a single permission per Q7. The unentitled-user `/access-denied` e2e (P-27) lands here | Shell + `authGuard` parent (`app.routes.ts:112-130`); `permissionGuard` (`permission.guard.ts:83`); single-permission `NavItem` (`nav.config.ts:13`) | P0 → P0 | S1 |
| **FR-A2** | Roles list shows, per role: name, description ("No description" if empty), System badge (icon + text), `permissionCount`, created date. Loading (skeleton), empty ("No custom roles yet", CTA only with `role:write`) and error (`NxErrorState`, retry, `traceId`) states. Search and filter (All/System/Custom) behave as decided in Q5. Ordering behaves as decided in Q5 | `GET /roles` paged, order `(name,id)` (`RoleController.java:142-171`); no server filter | P0 → P0 | S1 |
| **FR-A3** | Catalogue lists every permission grouped by resource (segment before the first `:`), label, raw code in mono, backend description, Sensitive badge where `isSensitive`; searchable. A permission with no label shows the raw code with "Unlabelled" and is logged once, code only | `GET /permissions` paged (`PermissionController.java:56-81`); `PERMISSION_LABELS` placeholder (`permission.ts:44`); **Human D3** | P0 → P0 | S1 |
| **FR-A4** | The Sensitive badge has text and a tooltip or help link whose wording matches the real definition (3.3). Wording is a D3 deliverable | `Permissions.SENSITIVE` (`Permissions.java:49-53`); **Human D3**, Q2 | P0 → P0 | S1 |
| **FR-A5** | Role detail loads `GET /roles/{id}` and `GET /roles/{id}/permissions`, shows header (name, description, System/Custom, `memberCount`, `permissionCount`) and a read-only matrix. Zero permissions: "This role grants no access yet". System role: banner and Clone action. 404 `ROLE_NOT_FOUND`: "This role no longer exists" with link back. Members and Effective tabs only per Group D/E | `RoleController.java:179-242` | P0 → P0 | S1 |
| **FR-A6** | Permission matrix is a native `<table>` with `<caption>`, group header rows (`<th scope="row">`), per-row labelled checkbox in edit mode, group checkbox with `indeterminate`, "Granted"/"Not granted" as text plus icon in read mode, reflow to one section per resource at 600 px with no horizontal scroll | `nx-checkbox`, `nx-table` exist | P0 → P0 | S1 (edit mode S2) |

### Group B: building and editing custom roles

| ID | Requirement (testable) | Depends on | Story pri → Proposed | Slice |
|---|---|---|---|---|
| **FR-B1** | Create role form (`role:write`): name required, ≤ 64, `^[A-Za-z0-9][A-Za-z0-9 ._-]*$`; description ≤ 255, no control characters; live counts, inline errors; reserved names `TENANT_ADMIN` and `MEMBER` rejected client-side case-insensitively. After `POST /roles`, the permission set is applied with `PUT` (needs `If-Match` from `GET /roles/{id}/permissions` of the new role) | `dto/CreateRoleRequest.java:24-33`; `RoleController.java:101-133, 252-326`. Reserved-name list is [REPORTED]; the client list duplicates a server rule (Q28) | P0 → P0 | S2 |
| **FR-B2** | One shared error map, with copy from D3, covering `RBAC_001` (four `reason`s plus none), `RBAC_002` to `RBAC_012` (note 010 and 012), `RBAC_011`/`USER_DIR_001/002` (with wait time from `Retry-After`), 412, 428, `VALIDATION_FAILED` per field from `details[]`, the 404 codes, 503 `AUTH_005`, and unknown code (generic + `traceId`). Unit test enumerates every code in 3.2 | 3.2; `rbac.ts:79-80` union to extend; **Human D3** | P0 → P0 | S2 (used by S1 for read errors) |
| **FR-B3** | Staged edit of a custom role's permissions with a Review dialog: permissions to add and remove (label + Sensitive badge), members affected (`memberCount`, wording per Q17), propagation message (FR-F3). Adding a sensitive permission: confirm reads "Grant sensitive access", `danger` variant. A result with zero permissions warns "This role will grant no access". Leaving with staged changes prompts. The Save sends one `PUT` with `If-Match` | `PUT` atomic (`RoleController.java:244-326`); `memberCount` | P0 → P0 | S2 |
| **FR-B4** | Save is **one atomic call**. Success shows "Role updated: n added, m removed" announced politely; an unchanged set (no-op 200) shows "No changes" rather than an update toast. Failure leaves the editor in its pre-save state with the error mapped per FR-B2. No applied/failed/not-attempted lists (that was for the superseded sequential save) | `RoleController.java:260` ("unchanged is an authorised no-op 200") | P0 → P0 (rewritten) | S2 |
| **FR-B5** | Clone: opens Create pre-filled "Copy of {name}" and the source permissions minus those the caller does not hold, which are listed as "Not copied". Source permissions come from `GET /roles/{id}/permissions`; the caller's holdings from the profile | Grant-subset rule; B4 profile | P1 → P1 | S2 |
| **FR-B6** | In edit mode a permission the caller does not hold is disabled with a visible reason. A permission whose grant the server restricts to administrators is disabled for non-administrators with a visible reason. **Which permissions get the second rule is decided in Q18**: server fact is `user:directory:read` only. The server's 403 stays authoritative | profile `permissions`/`isAdministrator`; `PiiPermissionGrantRule.java:18, 87-93` | P0 → P0 | S2 |
| **FR-B7** | For `isSystemRole` the UI renders no edit, rename or delete control (no disabled look-alikes). An unexpected 409 `RBAC_003` shows "System roles can't be changed" | `RoleResponse.isSystemRole` | P0 → P0 | S1 |

### Group C: users, assign and revoke

| ID | Requirement (testable) | Depends on | Story pri → Proposed | Slice |
|---|---|---|---|---|
| **FR-C1** | Users list (route gated per Q6) shows email, status badge with text, verified, joined date; status filter; "(you)" on the caller's row (from the profile `userId`); PENDING rows marked; exact-email lookup via the submit-mode search field, hint "Enter a full email address". Paged with the cap in N10. Email shown only to `user:directory:read` holders and never logged | `UserDirectoryController.java:88-140, 191-236`; `application.yml:256-264`; `03-design.md:496, 968` | P0 → P0 | S3 |
| **FR-C2** | User access page: header (email, status, "(you)"), Assigned roles table from `GET /users/{id}/roles` (paged), Revoke for `user:role:assign` holders; "Assigned by" only when non-null; info note for locked, disabled, pending users. System badge and role detail need a role join (Q19). Whether assigning to PENDING users is allowed: Q21 | `UserRoleController.java:145-180`; `GET /users/{id}`; N3, N12 | P0 → P0 | S3 |
| **FR-C3** | Assign dialog with searchable role picker; a role is disabled with an inline reason when (a) already held, (b) it carries a permission the caller lacks, (c) it is admin-defining and the caller is not an administrator. Confirm calls `POST /users/{id}/roles`, then toast + propagation message. (b) needs each candidate role's permissions; (c) needs an admin-defining signal (Q16, Q17). Caller needs `role:read` for the picker (Q12, Q19) | `POST` (`UserRoleController.java:89-133`); `RoleController.java:213-242`; N2, N3 | P0 → P0 | S3 |
| **FR-C4** | **Given** the target is the signed-in user and the caller is not an administrator, **then** "Assign role" is disabled with "You can't change your own roles. Ask an administrator." The server's `SELF_ASSIGNMENT` 403 is handled if reached | `RoleAssignmentService` A4; profile | P0 → P0 | S3 |
| **FR-C5** | Revoke opens a `danger` confirmation naming the role, the user and what they will lose (permission summary). **The lockout is not predicted from `memberCount`** (N1). Final behaviour per Q16: either an up-front block using a server-supplied signal, or a clear 409 `RBAC_002` message handled inline. A non-administrator on an admin-defining role gets 403 before any 409 | `RoleAssignmentService.java:400-435`; `03-design.md:303` | P0 → P0 (re-scoped by Q16) | S3 |
| **FR-C6** | Revoking your own admin-defining role requires typing the role name and warns "You will lose access to this page". After success the client refreshes the session and goes to the dashboard; a following 401 `AUTH_003` is expected and handled | typed-confirmation dialog; `auth.interceptor.ts:188-201` | P1 → P1 | S3 |

### Group D: members, impact, lifecycle

| ID | Requirement (testable) | Depends on | Story pri → Proposed | Slice |
|---|---|---|---|---|
| **FR-D1** | Members tab (`audit:read`) from `GET /roles/{id}/holders` (paged, ids only); emails via `GET /users?ids=` (≤ 100 per call, needs `user:directory:read`); without the directory permission show ids only (FR-X5). "Add members" and per-row Revoke follow FR-C3/C5. `assignedBy` shown only when non-null | `AccessReviewController.java:62-108`; `UserDirectoryController.java:82-140` | P1 → P1 | S5 |
| **FR-D2** | Roles list flags custom roles with `memberCount == 0` ("Unused") and gains an "Unused" filter. Over a paged list the filter semantics are decided in Q5 | `RoleResponse.memberCount` | P2 → P2 | S5 |
| **FR-D3** | "Edit details" (PATCH name/description) and "Delete role" on custom roles. Delete is blocked up front while `memberCount > 0` ("Remove all {n} members before deleting this role") and 409 `RBAC_009` shows the same text; typed role name to confirm. A role-subset 403 (caller lacks a permission the role carries) maps via FR-B2 and the spill-over note in 3.3. PATCH has no If-Match | `RoleController.java:447-535` | P1 → P1 | S4 |
| **FR-D4** | Roles list, catalogue and assignments use server paging with a page control. **Not future work:** the endpoints are paged now, so this is a precondition of FR-A2, FR-A3 and FR-C2 | `PageParams.java:17-28` | P1 → **P0** | S1 |

### Group E: access review

| ID | Requirement (testable) | Depends on | Story pri → Proposed | Slice |
|---|---|---|---|---|
| **FR-E1** | User access page gains an Effective permissions tab (`audit:read`): each permission with the granting role names (role ids from the API joined to role names) | `AccessReviewController.java:153-186` | P2 → P2 | S6 |
| **FR-E2** | Each catalogue row has "View holders" (`audit:read`), listing users (emails via directory permission, else ids) and granting roles | `AccessReviewController.java:110-151` | P2 → P2 | S6 |
| **FR-E3** | "Export CSV" on Members and Permission holders: columns `email, role(s), assigned_at, assigned_by`; confirmation notes personal data; cells beginning `=`, `+`, `-`, `@`, tab, CR are prefixed `'`. Retention, audit of the export and whether export exists at all are open (Q20, Q21) | P-28; `03-design.md:496`; **Human** | P2 → P2 (blocked on decision) | S6 |

### Group F: cross-cutting quality

| ID | Requirement (testable) | Depends on | Story pri → Proposed | Slice |
|---|---|---|---|---|
| **FR-F1** | Axe (`wcag2a`, `wcag2aa`) reports zero critical or serious violations on every page and dialog in light and dark themes; unique accessible name per matrix checkbox; no colour-only cues; 3:1 non-text contrast; visible focus; dialogs trap and return focus; polite announcements; reflow at 320 px; reduced motion respected. **Target level (2.1 vs 2.2 AA) is Q26** | `e2e/fixtures/axe.ts` | P0 → P0 | all |
| **FR-F2** | Only `shared/ui` wrappers are used; no `@angular/material` import and no raw hex or px in the feature; component styles within the 4 kB/8 kB budget | ADR 0004 [REPORTED] | P0 → P0 | all |
| **FR-F3** | After any role, permission or assignment change an inline message states when the change takes effect, from **one constant**. Wording, and whether it differs for revoke versus grant and during an outage, is a D4 decision grounded in 3.6 | **Human D4**, 3.6 | P0 → P0 | S2, S3 |
| **FR-F4** | Console calls opt out of the `/access-denied` redirect and render inline messages; an action-level 403 never navigates away from unsaved work | `SKIP_ACCESS_DENIED_REDIRECT` (`api-error.interceptor.ts:73-79`) | P0 → P0 | all |
| **FR-F5** | Every `data.permission` and `*appHasPermission` uses the `Permission` union. Unlabelled permission: raw code + "Unlabelled" + one warn log, code only | `permission.ts:13` | P1 → P1 | S1 |
| **FR-F6** | Per-area disabled-backend state: a 404 `RESOURCE_NOT_FOUND` on an area's list endpoint shows "isn't enabled for your organisation" for that area; a 404 `ROLE_NOT_FOUND`/`USER_NOT_FOUND` is a not-found page. Which areas appear when only some flags are on is Q9 | 3.7 | P1 → P1 | S1 |
| **FR-F7** | Console `LoggerService` calls never include emails, role names, descriptions or search text; only ids, codes and `traceId` | NFR-P1 | P0 → P0 | all |
| **FR-F8** | Lazy chunk, no change to the initial bundle (500 kB warning); a roles list render and filter within a target the story states (200 ms for 500 roles) and role detail interactive within 1 s on the dev stack; no request waterfalls other than those the story names. Because FR-D4, FR-C3 and N3 add calls, the allowed set of calls must be listed per page at design time | story figures; no RPS/p95 in any source (NFR-1) | P1 → P1 | all |

### Group G: resilience, navigation, edge states

| ID | Requirement (testable) | Depends on | Story pri → Proposed | Slice |
|---|---|---|---|---|
| **FR-G1** | Active tab, search text, filters and page number are in query params; Back/Forward restore them; reload keeps them. A directory page beyond the offset cap shows a clear error rather than a blank table | N10 | P1 → P1 | S1 |
| **FR-G2** | Each route sets a `title`, pages show breadcrumbs, focus moves to the page `h1` on navigation | `nx-breadcrumb`; title strategy [REPORTED present] | P0 → P0 | S1 |
| **FR-G3** | Detail pages show "Last updated {relative time}" and a Refresh action. For PUT: 412 means someone else changed the set; the editor tells the user and re-reads (FR-X1). For attach/detach-style conflicts that no longer occur in the PUT flow, "already applied" convergence applies only to **PATCH/DELETE/assign/revoke** (`RBAC_004`, `404 ROLE_ASSIGNMENT_NOT_FOUND`). A role deleted elsewhere: banner and editing disabled | `RoleController.java:281-285` | P1 → P1 (rewritten) | S2 |
| **FR-G4** | Staged changes are kept as a draft in `sessionStorage` keyed by role id (permission ids only); restore offered after re-login; storage access wrapped in try/catch. A restored draft is applied against the **current** ETag, not the old one | `auth.interceptor.ts:193-199` | P1 → P1 | S2 |
| **FR-G5** | Every mutating control shows a loading state and is disabled while in flight; dialogs cannot be confirmed twice. The 429 case re-enables after the `Retry-After` interval | NFR | P0 → P0 | all |
| **FR-G6** | When an action changes the caller's own access (self-revoke; editing a role the caller holds), the console refreshes the session, re-reads the profile, updates nav and affordances, and toasts "Your own access has changed". Because a grant does not bump the epoch (3.6), the profile (live) and `AuthStore` (JWT) can disagree for up to the token TTL; the console treats the **profile** as the source for affordances and `AuthStore` for nav only | `CallerAuthorizationController.java:47`; `03-design.md:574` | P1 → P1 | S3 |
| **FR-G7** | Shell nav shows "Access management" and the dashboard shows a shortcut to users holding the permission(s) decided in Q7 | `nav.config.ts` change | P0 → P0 | S1 |
| **FR-G8** | Long names, descriptions and emails truncate with ellipsis in tables, with the full text available visibly and to assistive technology; detail views wrap | | P1 → P1 | all |
| **FR-G9** | User-authored fields (role names, descriptions, emails) render only via Angular interpolation and bindings; no `innerHTML`, `bypassSecurityTrust*`, `DomSanitizer` in the feature; a CI lint or grep enforces it. A description of `<img src=x onerror=alert(1)>` is stored by the server today (N6) and must render as text | HTML-sink lint rules [REPORTED shipped under US-019 RC-62/P-33] | P0 → P0 | all |
| **FR-G10** | Offline, 5xx and timeouts during a load show `NxErrorState` with retry and `traceId`; a failed save leaves the editor state intact. Nothing spins indefinitely | `api-error.interceptor.ts` | P0 → P0 | all |
| **FR-G11** | Each area has a one-line explainer with a "Learn more" link. The link target does not exist in the sources (N14) | **Human D3**, Q25 | P2 → P2 | S1 |

### Added by this analysis (shipped backend, absent from the story)

| ID | Requirement (testable) | Depends on | Slice |
|---|---|---|---|
| **FR-X1** | **Given** the editor loaded a role's permissions with ETag *E*, **when** another admin changes the set and the user saves, **then** the server answers 412 with no state; the console tells the user the role changed, re-reads the set and keeps the staged diff re-based on it (exact behaviour per D2). A 428 is treated as a client defect: generic message plus `traceId`, never shown to the user as their error. The ETag is read from `GET /roles/{id}/permissions`, not the role | `RoleController.java:206-242, 252-326` | S2 |
| **FR-X2** | **Given** 429 `RBAC_011`, `USER_DIR_001` or `USER_DIR_002`, **then** the console shows a wait message derived from `Retry-After` (capped as the interceptor caps it), does not auto-retry, and re-enables the control afterwards. `RBAC_011` applies only to admin-defining or self targets. Lookup uses submit-mode search so keystrokes are not throttled lookups | `GlobalExceptionHandler.java:120-128`; `api-error.interceptor.ts:111, 150-157` | S2, S3 |
| **FR-X3** | **Given** the cold-start refresh fails with 503 `AUTH_005` or a network error, **or** any console call returns 503 `AUTH_005`, **then** the user sees an "unavailable, retry" view (not a blank shell) with a retry action and the support contact decision of Q4/Q23. The design is a D2 deliverable | `auth.guard.ts:36-41`; `JwtAuthenticationFilter.java:128-131` | S1 |
| **FR-X4** | **Given** the live profile call fails (404 flag off, 401, 5xx, timeout), **then** the console renders no mutating affordance predicted from a guess, shows the area-appropriate state (FR-F6/FR-G10), and still lets read-only pages that need no profile work only if Q8 allows it | `CallerAuthorizationController.java:30-31` | S1 |
| **FR-X5** | **Given** the caller lacks `user:directory:read`, **then** no email is requested or shown; users appear by id with the reason stated, and holders/assignment views still work. **Given** the caller has it, emails are shown with `status` and `emailVerified` beside each | `UserDirectoryController.java:88-140`; `03-design.md:496` | S3, S5 |
| **FR-X6** | **Given** 409 `RBAC_012` on assign or on a permission change, **then** the console retries **exactly once** with a fresh request, shows the error on a second `RBAC_012`, and handles a 403 on the retry. Pending acceptance in Q14 | `03-design.md:304`; `RoleClassificationChangedException.java:10-12` | S2, S3 |

**Totals:** 45 story criteria restated (A 6, B 7, C 6, D 4, E 3, F 8, G 11) + 6 added = **51 requirements**.

## 6. Proposed split into deliverable slices and MVP cut (proposal, not approved)

The story expects a split (its own Risks row, and "unestimated, expected to split"). Proposal, informed by the shipped backend:

| Slice | Contents | Needs | Notes |
|---|---|---|---|
| **S0: human inputs (start now, in parallel)** | D2 designs, D3 content deck, D4 wording, P-28 acknowledgement, Q-N5/Q23 support contact, 503 view design, WCAG level, persona list | owners in section 12 | Longest lead time; blocks S1 to S3 |
| **S1: foundation and read-only console** | FR-A1 to A6 (read mode), B7, D4, F-all, F5, F6, G1, G2, G7, G8 to G10, X3, X4; routes, any-of nav, wire types, fixtures, error map for reads | us015 + us019 on; D2/D3 | Delivers the roles list, role detail, catalogue |
| **S2: role authoring** | FR-B1 to B6, X1, X2, X6, G3, G4, G5; F3 | S1; D3, D4 | Create, edit with staged review and ETag, clone |
| **S3: users and assignment** | FR-C1 to C6, G6, X5 | S1; us012 + us019; Q6, Q12, Q16 | Users, assign, revoke, lockout handling |
| **S4: role lifecycle** | FR-D3 | S2; endpoints shipped | Rename and delete. Small and buildable now |
| **S5: members and unused signal** | FR-D1, D2 | S3; `audit:read`; directory permission for emails | Needs a non-admin `audit:read` persona (Q12) |
| **S6: access review** | FR-E1 to E3 | S5; P-28; Q20, Q21 | E3 export is a policy decision |

**MVP cut (proposal):** S0 + S1 + S2 + S3, which is the story's own P0 set (Groups A to C, F, G) with FR-D4 moved up to P0. Groups D and E are **buildable now** (their endpoints shipped with US-018 M9 and sit behind us015), so the "starts when D/E follow US-018 M9" sequencing in the story is obsolete; they are ordered after the MVP by priority, not by dependency. S4 is the cheapest post-MVP slice and the natural pull-forward candidate if the MVP is large. Slice order within the MVP is a recommendation; sequencing and capacity are for the Tech lead and PM (Q1).

## 7. Non-functional requirements

The source states **no RPS, p95 latency or availability SLO** for this story (NFR-1, gap G1). Figures below marked "proposal" are mine and need sign-off.

**Performance and scale**
- NFR-1: No RPS or p95 target in any source. US-019 adopted "p95 under 200 ms for B1, B3, B4 at dev volume" as a target by delegated decision (`15-delegated-decisions.md` P-23). The console is admin-only, low-RPS, not a hot path as far as the source shows **[CONFIRM]**.
- NFR-2 (story F8): 500-role list renders and filters under 200 ms; role detail interactive under 1 s on the dev stack; lazy chunk with no change to the initial bundle. The 500-role figure assumes the default cap, which is configurable (N5).
- NFR-3: Per-page call budgets are not stated and must be defined at design time (3.9 item 5, FR-F8).
- NFR-4: Directory throttles apply per actor: lookup 30 per 60 s, all directory calls 600 per 60 s (`application.yml:256-264`); denial throttle 5 per 60 s (`:162-166`). Throttle stores fail open (ADR-0016 [REPORTED]).

**Availability**
- NFR-5: No console SLO is stated. The console is only as available as three flags, the database, and Redis for the epoch store; after PT15M of an epoch-store outage all authenticated calls are 503 (3.6).
- NFR-6: The console must not be released where its APIs are off (US-019 design `:1080`); production flag values are unknown to the repo (R-8).

**Security**
- NFR-S1: Frontend gating is UX only; every action is enforced server-side, and every server rejection is handled gracefully even when the UI predicted success (story rule; `PROJECT.md`).
- NFR-S2: The console does not re-implement server rules it cannot see (administrator, admin-defining, last-administrator). Where it must predict, it uses the live profile and treats the server as final.
- NFR-S3: No HTML sinks (FR-G9); `returnUrl` open-redirect resistance is already enforced by `safeReturnUrl` [REPORTED].
- NFR-S4: No tokens, emails or ids in URLs beyond the route ids the story defines; lookups are POST so the email stays out of URLs and access logs.
- NFR-S5: `sessionStorage` drafts hold permission ids only.

**PII**
- NFR-P1: Emails appear only for `user:directory:read` holders, inside their own tenant, and never in client logs, error text, analytics, traces or Playwright reports. Persona addresses in e2e are already allow-listed in a PII scan; new specs must not weaken it (P-21).
- NFR-P2: Legal basis and retention for displaying emails and for any export: **delegated decision P-28 is not a Legal/DPO sign-off** (`15-delegated-decisions.md:24, 33`). It remains open (Q2).

**Accessibility**
- NFR-X1: See FR-F1. Sources conflict: the story says WCAG 2.1 AA; US-019's requirements adopted 2.2 AA as the target (US-019 Q-N4). Q26.
- NFR-X2: Disabled controls that need an explanation keep focus and show visible reason text, not tooltip only (US-019 NFR-X3).

**Observability**
- NFR-O1: Client logs carry ids, codes and `traceId` only (FR-F7). Every error state shows the `traceId`.
- NFR-O2: The story defines no client telemetry or product analytics. None is assumed (gap G9).

**i18n**
- NFR-I1: Out of scope; copy is centralised through the D3 deck.

## 8. Edge cases

**Empty and boundary inputs**
- Tenant with only system roles (empty-state CTA for `role:write` only). Role with zero permissions. Role with 100 permissions (PUT cap 100; catalogue is 9 today).
- Role name: 64 and 65 characters, leading space or symbol, reserved names in other cases (`tenant_admin`), a name differing only by case from an existing one. Description 255 and 256 characters; description containing `<`, quotes, emoji, bidirectional controls (server accepts all but control characters).
- Search text with regex characters, leading/trailing space, empty after trim; exact-email lookup with whitespace or mixed case (service trims, NFC-folds and case-folds).
- `size`, `page` out of range in a hand-edited URL (400, never clamped); directory page beyond offset 10,000 (400); `ids` of 0 or 101 (400).
- Long role names, descriptions, and emails (G8).

**Concurrent updates**
- Two admins editing the same role: second save gets 412 (FR-X1); a rename racing a delete; delete racing an assign (409 `RBAC_009` vs 404).
- Assign racing a permission attach that makes the role admin-defining: 409 `RBAC_012`, retry once, possible 403 on retry (FR-X6).
- Revoke racing another revoke of the last administrator: server decides, UI shows 409 `RBAC_002` or 404 `ROLE_ASSIGNMENT_NOT_FOUND`.
- Two sequential `RBAC_012`: stop after the second.
- Draft restored after the set changed (FR-G4).

**Partial failure**
- PUT is atomic; the role is either updated or not. The post-commit epoch bump or cache eviction can fail after a 200; the console cannot detect it (propagation may exceed the displayed text) **[CONFIRM wording in D4]**.
- Create role succeeds (`POST /roles`) and the following permission `PUT` fails: a role exists with no permissions. The console must say so and offer retry (FR-B1).
- Profile call succeeds but a list call fails, or the reverse.
- Member page loaded but the batch email lookup fails or is throttled: show ids, not a blank row.

**Network and timeouts**
- Offline during load or save, double-click on Save, tab closed mid-save (the request may still complete; on return the editor reads fresh state).
- Reactive 401 replay: after a stale-epoch 401 the interceptor refreshes and replays the original request including a mutating one; the 401 is raised before the handler runs, so a replayed `PUT` keeps its `If-Match` and is not applied twice **[INFERENCE]**.
- Refresh failure mid-edit sends the user to login and loses unsaved work (G4).
- 429 with and without `Retry-After`; `Retry-After` is capped at 300 s client-side.
- 503 `AUTH_005` on any call; cold-start 503 (FR-X3).

**Permission denials**
- Caller holds `role:read` but not `role:write`: read-only; no edit controls, no Create CTA.
- Role manager (no `user:directory:read`) opens a role that carries it: edit actions return 403 (`3.3` spill-over); copy must explain.
- Profile says allowed, server says 403 (stale profile; story scenario 12): inline message, no navigation, state re-fetched.
- `user:read` only (MEMBER): no console entry, deep link goes to `/access-denied`.
- Caller loses `role:read` or `audit:read` while on a page; token goes stale (401, refresh); subsequent calls 403.
- Cross-tenant ids in the URL: same 404 as missing.
- Self-assignment by a non-administrator; self-revoke of the only admin role; editing a role you hold.

**Feature flags**
- Any one of us012, us015, us019 off while the others are on (Q9). Profile 404 means no `isAdministrator`. Directory 404 means no emails but role pages still work.

**Users in unusual states**
- Locked, disabled, pending (unverified, possibly look-alike address); a disabled sole holder of an admin-defining role still counts as a holder for the lockout and for `memberCount`.
- Deleted role still referenced in a user's assignment list (server filters deleted roles) **[REPORTED]**.

## 9. Assumptions

| # | Assumption | Flag |
|---|---|---|
| AS1 | The 45 story criteria remain the intended scope after the corrections in section 4; the product owner's 2026-10-05 approval covers scope, not these corrections | [CONFIRM] |
| AS2 | A fully working console requires us012, us015 and us019 all on in the target environment | [CONFIRM] |
| AS3 | The console is admin-only, low-RPS and not a hot path; no load test is required | [CONFIRM] |
| AS4 | The reserved role names remain `TENANT_ADMIN` and `MEMBER` (a client-side duplicate of a server rule) | [CONFIRM] |
| AS5 | Groups D and E use only shipped endpoints and do not wait on any other story | [CONFIRM] |
| AS6 | The `ROLE_*`/`USER_*` 404 codes are stable enough to drive per-area "not enabled" states | [CONFIRM] |
| AS7 | A grant is effective for the holder only after their token is refreshed (up to the access-token TTL); a revoke on the next request with a healthy store. Derived from code reading, not measured | [CONFIRM, INFERENCE] |
| AS8 | Emails of PENDING (unverified) users are shown with a visible marker, per the US-019 design carry-forward | [CONFIRM] |
| AS9 | The delegated US-019 decisions (P-1 to P-29) hold unless an owner overturns them; they are not Ops, UX, PM or Legal sign-offs | [CONFIRM] |
| AS10 | `Learn more` links, support contact and copy are not available until D3 and Q-N5 deliver them | [CONFIRM] |
| AS11 | The `traceId` shown to users is safe to display (no PII) | [CONFIRM, INFERENCE] |

## 10. Risks

| ID | Severity | Risk | Mitigation (suggestion, not a design) |
|---|---|---|---|
| **R-1** | **High** | Human inputs D2 (designs), D3 (content) and D4 (wording) have no owner, date or sign-off; the delegated US-019 decisions "closed" them without UX/PM approval. Without them S1 to S3 cannot meet their own Definition of Done | Name owners and dates at Gate 1 (Q2 to Q4); start S0 now; treat any copy as provisional until approved |
| **R-2** | **High** | Lockout prediction wrong. C5's rule (`memberCount == 1`) is incorrect in both directions and the server exposes no admin-defining or distinct-admin signal. The UI could block a legitimate revoke, or imply "last administrator" falsely, or allow and then fail on submit | Q16; rely on the server's 409 for the final decision; never state "last administrator" from `memberCount` |
| **R-3** | **High** | UI re-implements server authorization rules it cannot fully see (administrator, admin-defining, sensitive-grant rule). The story's B6 and C3(c) are stricter than the server, so admins are blocked from permitted actions, or the reverse when the profile is stale | Q18, Q17; derive affordances from the live profile only; keep the server final; add "UI predicted allow, server denied" tests |
| **R-4** | **High** | Emails are PII shown to directory holders. P-28 (legal basis, retention) was decided by delegation, not by Legal/DPO; the DPO acknowledgement is a release-checklist item. Self-asserted and look-alike addresses raise misassignment risk | Q2; keep us019 off in production until acknowledged; show `status` and `emailVerified` beside every email; no email in logs |
| **R-5** | **High** | Stored XSS surface: the server accepts `<`, `>` and quotes in role descriptions (N6), and names/emails are rendered in tables and dialogs | FR-G9 plus lint; unit and e2e payload test (scenario 24); security review at Phase 7 |
| **R-6** | **High** | Silent-skip e2e: console specs skip when the backend is down; the full-stack CI job's first run (P-11) and its required-check status (P-9) are not confirmed, so a green pipeline can mean zero console assertions | Q13; make skipped console specs a failure in CI; assert executed-test count; confirm P-9/P-11 before the first console PR |
| **R-7** | **High** | Scope: 51 requirements across 7 areas, unestimated; D2/D3 gates and three flags | Section 6 split; estimate per slice at Gate 1 |
| **R-8** | **High** | Rollout: the console could be released where flags are off, only partly on, or where `nexus.rbac.throttle.require-shared-store` is not set (P-10), so `RBAC_011` is per-instance; production flag values are not visible in the repo | Q9; written per-environment flag plan owned by Ops; F6 per-area states; release checklist items P-7, P-9, P-10 |
| **R-9** | **Medium** | Propagation wording misleads: "about 30 minutes" is an upper bound for revoke and an approximate one for grant; an outage changes both (3.6). Over- or under-promising a security change's effect is the very anti-pattern the story lists | Q3; action-specific wording sourced from config; re-check when TTLs change |
| **R-10** | **Medium** | Platform-wide 503 `AUTH_005` after a Redis epoch-store outage over PT15M (RES-30, SRE/PM acceptance pending) turns every console call into an error; the cold-start path leaves a blank page today | FR-X3; Q4; confirm RES-30 owner |
| **R-11** | **Medium** | Editing a role the caller holds, or revoking one's own admin role, can remove the caller's own access mid-session; JWT-derived nav and the live profile disagree for up to the token TTL | FR-G6, FR-C6; treat the profile as the source for affordances |
| **R-12** | **Medium** | Role-subset spill-over: a role manager cannot edit or delete roles that carry `user:directory:read`; the 403 looks arbitrary without explanation | Copy in D3 (Q2); optional disabled-with-reason using the profile |
| **R-13** | **Medium** | Lost staged work: 412 conflicts, session expiry, and tab close discard edits; draft restore must rebase onto the current ETag | FR-X1, FR-G4; D2 flow for conflict |
| **R-14** | **Medium** | Persona/test gaps: no non-admin `audit:read` persona and no role-reading user manager means key permission combinations (D/E, assign dialog) cannot be e2e-tested | Q12 |
| **R-15** | **Medium** | `RBAC_012` retry-once rule awaits US-020 acceptance (RES-53) and a replayed mutating request could hit a different rule on retry (403) | Q14 |
| **R-16** | **Medium** | The wire types, error-code union and recorded fixtures cover only part of the API (3.8); a backend DTO drift would not fail a test | Extend types and `contracts/api` fixtures for every endpoint the console calls |
| **R-17** | **Low** | Role cap, reserved names and the other limits are duplicated in client copy and validation and can drift from config | Take limits from the server's error, not constants, where possible; copy review in D3 |
| **R-18** | **Low** | Directory throttles (30 per 60 s lookups) can surprise an admin who types quickly; deep lists end at offset 10,000 | FR-X2; submit-mode search; message on the cap |
| **R-19** | **Low** | Any-of nav gating needs a shell model change that touches an area outside the feature folder | Q7 |

No Critical risk is identified; R-1 to R-8 are High.

## 11. Dependencies

- **Shipped and verified:** every endpoint in 3.1; the shell; guards; interceptors; `shared/ui` wrappers; personas; HTML-sink lint rules [REPORTED].
- **Human (blocking):** D2, D3, D4, P-28 acknowledgement, Q-N5, 503 view design.
- **Platform decisions before enabling in an environment:** flags (P-7), shared throttle store (P-10), full-stack CI as a required check (P-9), first CI run (P-11), DPO acknowledgement (P-28).
- **Coordination:** Epic 3 reuses the shell, directory and console patterns (story "Blocks").

## 12. Open questions for Gate 1

All are questions; none is assumed. Each has an owner, a **recommended default (NOT approved)** and the trade-off. Roles in brackets are the addressee.

**Q1 [PM, Tech lead]: Split and MVP cut.** Approve section 6: MVP = S0 to S3 (the story's P0) with FR-D4 moved to P0; S4 (rename/delete) next; S5, S6 later. Alternatives: single delivery (story as written), or MVP = S1 + S2 only. *Recommended default (not approved):* S0 to S3 as the MVP, S4 as first follow-up. *Trade-off:* a smaller MVP ships read and authoring value earlier but leaves assignment to API calls; the full P0 is a long first delivery behind D2/D3.

**Q2 [PM, UX]: D2 wireframes and designs for every page and dialog, including desktop and 320 px, conflict, restore-draft, throttle and 503 states, with accessibility annotations; and D3 content deck (errors per code including the four `RBAC_001` reasons, confirmations, disabled-reason text, empty states, labels for permissions and groups, the sensitive-badge definition, the role-subset explanation).** Owners and dates are not in any source. *Recommended default (not approved):* name a UX owner and a PM reviewer at Gate 1; seed the deck from the benchmark text in `docs/features/US-019/01-requirements.md` section 14 and the strings quoted in the story; the placeholder `PERMISSION_LABELS` stay until approved. *Trade-off:* provisional copy lets build start but risks rework; waiting blocks S1.

**Q3 [PM, Architect]: D4 propagation wording, re-grounded in config (3.6).** Options: (a) keep one sentence "about 30 minutes, or as soon as they sign in again"; (b) two sentences, revoke "takes effect on the user's next request" and grant "within about 15 minutes, or when they sign in again"; (c) (b) plus an outage caveat. *Recommended default (not approved):* (b) from one constant keyed by action type, values computed from config. *Trade-off:* (a) is simplest but overstates revoke lag and is a floor-like claim for a security control; (b) is accurate for the healthy case but more copy; (c) is accurate but alarming. The wording needs Security to confirm the claim, since AS7 is inferred.

**Q4 [PM, UX]: P-20/P-32 cold-start 503 "unavailable, retry" view.** What does the user see when the cold-start refresh fails with 503 or network error, and when any console call returns 503 `AUTH_005`? *Recommended default (not approved):* a full-page unavailable state inside the shell with a Retry action and the `traceId`; the guard navigates to it instead of cancelling. *Trade-off:* needs a design and a guard change; accepting today's blank page is free but leaves the first gated route (the console) with a bad failure mode.

**Q5 [PM, Architect]: Roles list paging versus the story's client-side search, filter and sort.** The endpoint is paged, order `(name, id)`, with no search or filter parameters. Options: (a) client-side search/filter/sort over all pages fetched up front (at most 5 calls at the default cap, more if the cap is raised); (b) search/filter only within the loaded page; (c) a server filter (a backend change, contradicts "no backend changes"). *Recommended default (not approved):* (a), with the "Unused" filter and system-first sort computed client-side after the full load, fetching in the background with a visible count. *Trade-off:* (a) keeps the story's UX with no backend change at the cost of up to 5 requests and stale data between loads; (b) is simplest but surprising; (c) is cleanest but a new backend item.

**Q6 [PM, Security]: Users-area gating after the directory permission.** The Users area needs `user:directory:read` for the list and `user:read` for a user's assignments. Options: (a) the Users routes gate on `user:directory:read`; user detail also requires `user:read` for the roles table and degrades if absent; (b) the Users routes gate on `user:read`; emails appear only when the directory permission is held; (c) gate on both. *Recommended default (not approved):* (a), matching the US-019 design (`03-design.md:302`). *Trade-off:* (a) hides the area from a `user:read`-only holder who has no way to find a user anyway; (b) shows an area that is mostly empty.

**Q7 [Architect, UX]: Any-of nav gating.** The story shows the entry to holders of `role:read` or `user:read`; the shell supports one permission. Options: (a) extend the shell to any-of (and the dashboard card); (b) gate the entry on `role:read` and show Users inside; (c) one nav item per area (Roles, Users). *Recommended default (not approved):* (a), with the any-of set `role:read` or `user:directory:read` rather than `user:read` (row 3). *Trade-off:* (a) changes shared shell code and its contract test; (b) hides Users from user managers without `role:read` (see Q12); (c) multiplies nav items.

**Q8 [PM, Architect]: Behaviour when the live profile cannot be read.** Options: (a) block the whole console with the unavailable/not-enabled state; (b) allow read-only pages that need no profile and disable every mutating control. *Recommended default (not approved):* (b). *Trade-off:* (b) is more useful during a partial outage but needs a clear read-only banner; (a) is simpler and safer.

**Q9 [Ops, PM]: Partial flag enablement and per-environment plan (P-7).** Which combinations are supported (us015 only, us015 + us019, all three)? What does the console show per area when a flag is off? Prod values are not in the repo. *Recommended default (not approved):* only "all three on" is a supported release; partial states render a per-area "isn't enabled" message for QA and staging only. *Trade-off:* simple and safe for production; blocks incremental rollout, and boolean flags cannot do percentage rollout anyway.

**Q10 [Architect, Security]: Does "no backend changes" hold?** It does not for last-administrator prediction, the admin-defining flag, an audited export, a role-reading assignment path, or a role join on a user's assignments (3.9). Decide for each: (a) accept a UI-only degraded behaviour, (b) open a backend follow-up story, (c) amend the story to allow a backend change. *Recommended default (not approved):* (a) for Q16 to Q19 initially, with a named follow-up for each, so the MVP stays frontend-only. *Trade-off:* keeps scope and risk low but ships weaker affordances; (c) is correct but moves the story out of a frontend-only slot.

**Q11 [PM]: Groups D and E timing.** They are buildable now. Pull any of S4 to S6 into the MVP? *Recommended default (not approved):* no; S4 first after the MVP. *Trade-off:* pulling D3 forward completes the role lifecycle but adds scope to an already large MVP.

**Q12 [QA, Security, Tech lead]: E2E persona gaps.** No sign-in persona holds `audit:read` without being an administrator, none holds `role:read` + `user:role:assign` + `user:read` without admin, and `userManager` cannot list roles. Add personas (extends US-019 C1 seeding), or test those combinations at unit/IT level only? *Recommended default (not approved):* add an "auditor" persona (`audit:read`, optionally `user:directory:read`) and a "role-reader user manager"; keep dev-only seeding. *Trade-off:* extra seed and fixture work; otherwise the gating for D/E and C3 is untested end to end.

**Q13 [Architect, Ops]: CI for console e2e.** The full-stack e2e job's first run (P-11) and required-check status (P-9) are unconfirmed. Require them before the first console PR, and make skipped console specs failures? *Recommended default (not approved):* yes to both. *Trade-off:* adds CI time and may delay S1; without it a green build can mean no assertions ran.

**Q14 [Security, PM]: Accept RES-53 (retry `RBAC_012` exactly once)?** Alternatives: no automatic retry, show the error and let the user retry. *Recommended default (not approved):* accept the single automatic retry for permission changes and assigns; never loop. *Trade-off:* better UX versus an automatic re-send of a mutating request whose outcome can legitimately change to 403 (`03-design.md:304`).

**Q15 [UX, Security]: Copy for `RBAC_001` `reason`.** Four values, and `UNSPECIFIED` also covers throttle and unknown cases. Show reason-specific text for each, or generic text plus reference for `UNSPECIFIED`? *Recommended default (not approved):* specific text for `GRANT_EXCEEDS_CALLER`, `SELF_ASSIGNMENT`, `ADMINISTRATOR_REQUIRED`; generic plus `traceId` for `UNSPECIFIED`. *Trade-off:* helpful versus the small disclosure the threat model accepted (RES-47).

**Q16 [Architect, PM]: Last-administrator handling (C5).** `memberCount` is not a valid predictor (N1). Options: (a) no up-front block; always show the confirm dialog and handle 409 `RBAC_002` inline with D3 copy; (b) a conservative up-front warning when the role is inferred admin-defining and has one member, without disabling; (c) a backend signal (distinct admin-defining holder count, or per-role `isAdminDefining`) so an exact up-front block is possible. *Recommended default (not approved):* (a) for the MVP, (c) as a follow-up. *Trade-off:* (a) never lies but finds out on submit, which the story's anti-patterns list; (b) may mislead in either direction; (c) is exact but is a backend change.

**Q17 [Architect]: Admin-defining signal for C3(c) and the review dialog's "affects {n} members".** Infer admin-defining client-side (role's `permissionCount` equals the catalogue `totalElements`), or leave the server to decide and handle 403 `ADMINISTRATOR_REQUIRED`? *Recommended default (not approved):* use the server's `ADMINISTRATOR_REQUIRED` as the authority and use the inference only to show a hint. *Trade-off:* the inference duplicates `RbacAdministrators` logic; relying on the 403 gives a less pre-emptive UI.

**Q18 [Security, Architect]: Which grant restrictions does the UI mirror (B6, C3)?** Server: hold the permission (grant-subset), and administrator-only for `user:directory:read` and for admin-defining role changes. Story: every sensitive permission is administrator-only. *Recommended default (not approved):* mirror the server exactly (hold-it rule for all, administrator-only for `user:directory:read`). *Trade-off:* accurate and unblocks legitimate role-manager work; the story's stricter rule is safer-looking but misstates the model and teaches admins the wrong rule.

**Q19 [Architect, PM]: User access page data (System badge, permission summary, caller's role-read).** `GET /users/{id}/roles` has names and ids only, and the assignment dialog needs `role:read`. Options: (a) join on `GET /roles` (and `GET /roles/{id}/permissions` on demand), requiring `role:read` for those parts and degrading without it; (b) add fields server-side (backend change); (c) require `role:read` for the whole Users area. *Recommended default (not approved):* (a) with explicit degraded states and a recommendation that user-manager roles also carry `role:read`. *Trade-off:* (a) has no backend change but adds calls and permission coupling; (b) is cleanest; (c) is simplest but narrows who can use Users.

**Q20 [Security, Legal]: E3 CSV export.** Does export ship at all? If yes: retention of the file, audit of the export (a client-side file leaves no export audit event; the design says it "is audited"), and who may export. *Recommended default (not approved):* defer E3 (P2) until the audit mechanism is decided; keep the neutralisation rules ready. *Trade-off:* defers a SOC 2 evidence use-case; shipping now risks an unaudited bulk PII extract.

**Q21 [PM, Security]: Assigning roles to PENDING (unverified) users.** The US-019 design leaves it to US-020 or Epic 3 (`03-design.md:496`); the story's C2 allows it with a note. *Recommended default (not approved):* allow, with a visible "unverified email" marker and warning. *Trade-off:* flexibility versus granting access to a self-asserted address; refusing needs a rule the server does not enforce.

**Q22 [Legal, DPO, Security]: P-28 legal basis and retention for showing emails to directory holders.** The delegated decision states a minimisation argument but is not a Legal/DPO sign-off; the DPO acknowledgement is an open release-checklist item. *Recommended default (not approved):* keep the delegated rule (admin-granted permission, own tenant, audited reads, retention follows the audit log) and require DPO acknowledgement before us019 is enabled in production. *Trade-off:* adds a gate to release; skipping it exposes a GDPR/SOC 2 finding.

**Q23 [PM]: Q-N5 support contact for the Access Denied page and the 503 view.** `supportContact` is `null`, so no link shows. *Recommended default (not approved):* keep the link hidden until PM provides a value. *Trade-off:* safe, but the 503 and denial pages then offer no escalation path.

**Q24 [Architect, UX]: How does the page "Refresh" and "Last updated" (G3) relate to the profile and ETag?** Re-read the role, the permission set (new ETag) and the profile together or independently? *Recommended default (not approved):* re-read role and set together; profile only after own-access events (G6). *Trade-off:* fewer calls versus a possibly stale affordance.

**Q25 [PM, UX]: G11 "Learn more" target.** No developer or admin guide is named in any source. *Recommended default (not approved):* defer G11 until a target exists, or link to a placeholder page. *Trade-off:* a dead link harms trust; omitting loses discoverability.

**Q26 [PM, UX, Accessibility]: WCAG level.** The story says 2.1 AA; US-019 adopted 2.2 AA (Q-N4). *Recommended default (not approved):* 2.2 AA, which adds target size and focus-not-obscured (sticky review footer and header). *Trade-off:* a few extra criteria and manual checks, since axe may not cover them.

**Q27 [Story owner]: Confirm the risk tier.** Discovery proposes high-risk. *Recommended default (not approved):* high-risk, with a Gate 2 threat model and Phase 7 audit. *Trade-off:* more review effort for a frontend-only change, justified by the PII and authorization surface.

**Q28 [Architect, Security]: Which limits and rules may the client hard-code?** Reserved names, name pattern, description length, 500-role cap, 100-id cap, `Retry-After` cap. *Recommended default (not approved):* hard-code only the validation that mirrors `CreateRoleRequest`/`UpdateRoleRequest`, and derive everything else from server responses; no "500" in copy. *Trade-off:* a few more error paths versus drift when config changes.

**Q29 [PM, Ops]: Telemetry.** Is any client telemetry or product analytics (e.g. which errors users hit) wanted? None is in the story. *Recommended default (not approved):* none beyond error logging with ids and codes. *Trade-off:* no adoption data versus no privacy review.

## 12a. Gate 1 decisions (2026-10-23)

**Delegated by:** Md Nisar Ahmed (story owner and approver): "Resolve all by yourself ... Name of approver Md Nisar Ahmed". **Taken by:** Claude. These are the recommended defaults of section 12, confirmed or adjusted below. They are not sign-offs by UX, PM, Legal, DPO, Security or Ops; the owner named in each can overturn one, and the effect is stated. Research was limited: web search returned usable vendor material only for CSV injection (OWASP) and the general least-privilege model (AWS IAM Access Analyzer, Okta custom admin roles). It returned nothing usable on Entra propagation limits or GitHub's last-owner rule, so Q3 and Q16 rest on this repo's code, not on a vendor benchmark. WCAG 2.2 criteria are cited from knowledge.

| Q | Decision | Why | If overturned |
|---|---|---|---|
| Q1 | MVP = S0 to S3 with FR-D4 (server paging) as P0. S4 (rename/delete) is the first follow-up; S5, S6 later | The story's own P0 set; paging is already shipped | Re-slice 04-tasks only |
| Q2 | D2 and D3 are produced by Claude as **provisional** artefacts at Gate 2 (annotated page and dialog specs in text, and a content deck in one copy file), marked "not UX/PM approved". Build may proceed on them; all copy lives in one module so approved text swaps in. UX and PM review stays an open release item | Blocking S1 on a human deliverable with no owner or date stalls the story; one copy module bounds the rework | Replace the copy module and revisit layouts |
| Q3 | Option (b), one constant keyed by action. Grant or add: "takes effect within about 15 minutes, or when the person signs in again". Revoke or remove: "takes effect on the person's next request, and in every case within about 30 minutes". Values derive from `permission-cache-ttl-seconds` and `access-token-ttl-seconds`. The Gate 2 threat model must confirm the revoke claim (AS7 is inferred) | Accurate in the healthy case, with the old 30-minute bound kept as the ceiling for a control that must not be overstated | Edit the constant |
| Q4 | Full-page "unavailable, retry" view inside the signed-in layout with a Retry action and the `traceId`. `authGuard` navigates to it on a cold-start 503 `AUTH_005` or network error instead of cancelling; a mid-session 503 uses the same view for page loads and a toast for actions. Gate 2 designs it | The console is the first gated route, so a blank page is a worse failure than before | Revert the guard change (US-019 behaviour) |
| Q5 | (a): fetch all pages of roles up front, then search, filter and sort client-side (system roles first); show a loading count. No backend change | Keeps the story's UX; at most 5 requests at the default cap | Add a server filter as a backend story |
| Q6 | (a): Users routes gate on `user:directory:read`; a user's page also needs `user:read` for the assignments table and degrades without it | Matches the US-019 design; without the directory permission there is no way to find a user | Gate on `user:read` |
| Q7 | (a): the shell supports any-of permissions. The console entry and the dashboard card show for `role:read` or `user:directory:read` | One entry point as the story wants, using the permission that actually opens the Users area | Per-area nav items |
| Q8 | (b): with the profile unreadable, read-only pages work and every mutating control is disabled under a banner | More useful in a partial outage; the server stays the authority | Block the console |
| Q9 | Only "all three flags on" is a supported release. Partial states show a per-area "isn't enabled" message and are for QA and staging only | Simple and safe; boolean flags cannot do a percentage rollout anyway | Add supported combinations |
| Q10 | (a) for Q16 to Q19: the MVP stays frontend-only with degraded behaviour, and each gap gets a named follow-up backend item in `14-pending-items.md`: F-1 distinct administrator count or per-role `isAdminDefining`; F-2 role fields on a user's assignments; F-3 audited export | Keeps scope and risk low | Amend the story to allow backend work |
| Q11 | No: Groups D and E stay after the MVP, S4 first | The MVP is already large | Pull S4 forward |
| Q12 | Add dev-only personas: an auditor (`audit:read`, optionally `user:directory:read`) and a role-reader user manager (`role:read`, `user:read`, `user:role:assign`, not an administrator). Seeding stays dev-only | Gating for D, E and C3 is untestable end to end otherwise | Cover at unit level only |
| Q13 | Yes to both: the full-stack e2e job (P-9, P-11) must have run green once before the first console PR merges, and a skipped console spec fails the job | A green build with no assertions run protects nothing | None |
| Q14 | Accept RES-53: retry `RBAC_012` exactly once, for permission replace and assign only; never retry a 403, 412 or 429 | The one case the server says is retryable | Show the error and let the user retry |
| Q15 | Specific text for `GRANT_EXCEEDS_CALLER`, `SELF_ASSIGNMENT` and `ADMINISTRATOR_REQUIRED`; generic text plus `traceId` for `UNSPECIFIED` | Matches the disclosure the threat model accepted (RES-47) | Use generic text throughout |
| Q16 | (a) for the MVP: no up-front last-administrator block. The revoke dialog always warns about administrator roles and the console handles 409 `RBAC_002` inline. The exact block waits for F-1. `memberCount == 1` is never used as the predictor | It would be wrong in both directions (N1); never showing a false "safe" or false "blocked" is the honest option | Add the follow-up first |
| Q17 | The server is the authority (`ADMINISTRATOR_REQUIRED`). The client may show a hint inferred from `permissionCount` equal to the catalogue total, worded as a hint, never as a block | Avoids duplicating `RbacAdministrators` logic as a gate | Remove the hint |
| Q18 | Mirror the server exactly: hold-it rule for every permission, administrator-only for `user:directory:read` and for admin-defining role changes. The Sensitive badge stays informational only; the story's "sensitive means administrator-only" rule is dropped | The story's rule misstates the model and would teach administrators the wrong rule | Stricter UI rule |
| Q19 | (a): join `GET /users/{id}/roles` with `GET /roles` for the System badge, and fetch role permissions on demand; parts that need `role:read` degrade visibly without it; document that user-manager roles should carry `role:read` | No backend change | Backend fields (F-2) |
| Q20 | Defer E3 (CSV export). Keep the neutralisation rule ready: prefix `'` to any cell starting with `=`, `+`, `-`, `@`, tab or CR (OWASP CSV Injection), as defence in depth since OWASP notes no universal sanitiser exists | An unaudited bulk PII extract is worse than a missing P2 feature | Ship with an audit mechanism (F-3) |
| Q21 | Allow assigning to PENDING users with an "unverified email" marker and a warning | The server permits it; refusing needs a rule it does not enforce | Refuse in the UI |
| Q22 | Keep the US-019 delegated rule (administrator-granted permission, own tenant, audited reads, retention follows the audit log). DPO acknowledgement stays a release-checklist item and **blocks enabling us019 in production**. Claude cannot supply that sign-off | A legal basis is not Claude's to decide | Narrow the grant or hide the email |
| Q23 | Keep `supportContact` null; the 503 and denial views show no link | A wrong contact is worse than none | Set the value in `environment.ts` |
| Q24 | Refresh re-reads the role and its permission set (and ETag) together; the profile is re-read only after own-access events (G6) | Fewer calls | Re-read the profile too |
| Q25 | Defer the G11 "Learn more" link until a guide exists; show the one-line explainers without a link | A dead link harms trust | Link a placeholder |
| Q26 | WCAG 2.2 AA, as US-019 adopted (adds target size 2.5.8 and focus-not-obscured 2.4.11 for the sticky review footer). Axe covers part of it; the rest is a manual checklist in the test plan | Consistency with US-019 | 2.1 AA |
| Q27 | High-risk tier confirmed: full Gate 2 threat model and Phase 7 audit | PII, authorization prediction, stored-XSS surface | None |
| Q28 | Hard-code only validation mirroring `CreateRoleRequest` and `UpdateRoleRequest`; derive caps and limits from server responses; no "500" in copy | Avoids drift when config changes | Hard-code more |
| Q29 | No product analytics; error logging with ids, codes and `traceId` only | No privacy review exists | Add after a review |

Still open by nature: UX and PM approval of D2 and D3; DPO acknowledgement (Q22); first green run of the full-stack e2e job (P-11); the three backend follow-ups F-1 to F-3.

## 13. Gaps (missing from the source entirely)

- G1: No RPS, p95 latency or availability SLO for the console, and no data-volume statement beyond "up to 500 roles".
- G2: No owner or date for D2 (designs), D3 (content), D4 (wording) or Q-N5 (support contact).
- G3: No legal basis or retention rule signed by Legal/DPO for showing emails or for CSV export (P-28 is a delegated decision only).
- G4: No decision on whether `user:read`-only holders have any console role, or on any-of nav gating.
- G5: No admin-defining, distinct-administrator or system-role signal on user-facing DTOs, and no statement of how the UI should predict lockout without it.
- G6: No statement of what the console shows when only some of the three flags are on, or when the profile is unreadable.
- G7: No error-copy deck; no copy for 412, 428, 429 variants, 503 or the four `RBAC_001` reasons.
- G8: No definition of per-page request budgets for F8 ("no waterfalls") now that lists are paged and a join is needed.
- G9: No acceptance criterion for observability or client telemetry.
- G10: No persona for a non-admin `audit:read` holder or for a role-reading user manager.
- G11: No rollback or kill-switch statement for the console (disabling a flag removes the API, not the UI); no front-end feature toggle (the story says none, "Gate 1 may add").
- G12: No guidance for assigning roles to PENDING users, for CSV audit, or for retention of drafts in `sessionStorage` beyond "ids only".
- G13: No target for "Learn more" (G11).
- G14: No mapping of the story's "five areas" to the route table (Access review has no route) (N13).
- G15: No wire types or fixtures for assignments, holders, effective permissions, create/update requests and several error codes (3.8).

## 14. Stakeholder map

| Stakeholder | Cares about | Needs from this story |
|---|---|---|
| Story owner (approver) | Scope, split, risk tier, release gating | Gate 1 decisions Q1, Q9, Q10, Q27 |
| Product Owner / PM | Schedule, MVP, copy and wording, support contact | Q1, Q2 to Q4, Q11, Q21, Q23, Q25, Q29 |
| UX / Design | Pages, dialogs, conflict and 503 flows, copy, a11y annotations | D2, D3, Q2, Q4, Q15, Q25, Q26 |
| Tenant administrators | See and change access safely, honest messages | S1 to S3; accurate propagation text and lockout handling |
| Role managers and user managers (non-admin) | Do their job without admin rights; understand a 403 | Q6, Q12, Q18, Q19; spill-over copy |
| Auditors / reviewers | Who holds what; evidence | S5, S6; Q20 |
| Security / Privacy | PII surface, XSS, disclosure, enumeration, lockout correctness | Q14, Q15, Q16, Q18, Q20 to Q22, threat model |
| Legal / DPO | Lawful basis and retention for emails and exports | Q20, Q22 |
| Architect | Shell any-of, error map, flag handling, backend-change decisions | Q5, Q7, Q8, Q10, Q13, Q16, Q17, Q19, Q24, Q28 |
| Frontend engineers | Types, fixtures, guard and shell changes | Section 3.8; Q7 |
| Backend engineers | Only if Q10 opens follow-ups | Q10, Q16, Q17, Q19 |
| QA | Personas, CI that cannot silently skip, error-code coverage | Q12, Q13 |
| Ops / Release / SRE | Flag values, shared throttle store, Redis outage behaviour | Q9, R-8, R-10; P-7, P-9, P-10 |
| Accessibility specialist | WCAG level, dialogs, matrix | Q26, FR-F1 |
| Support | What users see on denial, unavailable, propagation | D3, Q4, Q23 |

## 15. Success metrics

Measured after rollout; targets are proposals to confirm because no source gives any (gap G1).

- **Task completion:** an administrator can create a custom role, assign it, and revoke it entirely in the console. Verified by the MVP e2e suite on a real backend with zero skipped console specs.
- **Honesty of affordances:** share of console 403 and 409 responses that the UI predicted is tracked in tests (scenario 12 and 16); the number of generic "no permission" messages shown falls once `reason`-specific copy ships. Lockout events: zero tenants left without an administrator through the console (backend zero-admin indicator stays healthy).
- **Safety:** zero emails in client logs, error text or Playwright artefacts (PII scan stays green); the XSS payload test (scenario 24) renders as text; no `innerHTML`/`bypassSecurityTrust*` in the feature (CI check).
- **Accuracy of copy:** propagation text matches measured behaviour (revoke next request; grant within the token TTL) in a staging check once, and is re-checked when TTL config changes.
- **Quality gates:** `npm run test:ci`, `npm run lint && npm run format:check` green; axe zero critical/serious on every page and dialog in both themes; lazy chunk size within budget.
- **Operations:** console-related 5xx and 503 `AUTH_005` rate (from existing backend metrics); throttle responses `RBAC_011`/`USER_DIR_001/002` per week; flag values for all three recorded per environment before release.
- **Governance:** D2, D3, D4 approvals and the DPO acknowledgement (Q22) recorded before the console is enabled in production.

## 16. Test scenarios affected by the corrections (story QA table)

| Story scenario | Change |
|---|---|
| 2 (MEMBER sees Users only) | Wrong: MEMBER lacks the directory permission and sees no entry; deep link goes to `/access-denied` (row 3) |
| 7 (sequential save, 2nd of 3 fails) | Replaced by: PUT atomic; 412 rebase; 428 defect; 403 before 412; no-op 200 (FR-B4, FR-X1) |
| 12 (stale profile, server 403) | Keep; add the `reason` copy and the case where the profile is correct but the server throttles with 429 |
| 16 (revoke last admin via `memberCount` 1) | Replaced by Q16's outcome: 409 `RBAC_002` handled inline; no "last administrator" claim from `memberCount` |
| 18 (concurrent attach "already applied") | Applies only to assign/revoke (`RBAC_004`, `ROLE_ASSIGNMENT_NOT_FOUND`); for PUT it is a 412 |
| 22 (backend flags off) | Per-area, by `code` (FR-F6); also profile 404 (FR-X4) |
| 23 (every error code) | List extended per 3.2; includes 412, 428, 429 variants, 503 |
| New | `RBAC_012` retry-once; `Retry-After` handling; directory throttle; role manager without the directory permission on a role that carries it; cold-start 503 view |
