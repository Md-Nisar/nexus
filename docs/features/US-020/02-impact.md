# US-020 — Impact Analysis (Phase 2)

**Story:** RBAC Access Management console for tenant administrators
**Epic:** EPIC-002 — RBAC Foundation
**Gate 1 basis:** `docs/features/US-020/01-requirements.md` §12a "Gate 1 decisions (2026-10-23)". These decisions are binding and are not reopened here: MVP = S0 to S3 with FR-D4 as P0 (Q1); provisional D2/D3 in one copy module (Q2); propagation copy keyed by action (Q3); a full-page "unavailable, retry" view and an `authGuard` that navigates to it (Q4); fetch all role pages, then search, filter and sort on the client (Q5); Users routes gated on `user:directory:read` (Q6); any-of nav and dashboard card for `role:read` or `user:directory:read` (Q7); read-only console when the profile is unreadable (Q8); only "all three flags on" is a supported release (Q9); frontend-only MVP with follow-ups F-1 to F-3 (Q10); auditor and role-reader user-manager personas, seeded in dev only (Q12); full-stack e2e green once before the first console PR, and a skipped console spec fails the job (Q13); retry `RBAC_012` exactly once (Q14); no up-front last-administrator block (Q16); the server decides admin-defining, the client shows a hint only (Q17); the client mirrors the server's grant rules exactly (Q18); join for the user page with visible degradation (Q19); CSV export deferred (Q20); WCAG 2.2 AA (Q26); high-risk tier (Q27); hard-code only validation that mirrors the request DTOs (Q28); no analytics (Q29).
**Method:** I checked every claim against the code on `feature/US-020` (base `main` @ `adda702`). **[VERIFIED]** = re-read in code or config for this document. **[REPORTED]** = taken from `00-discovery.md` / `01-requirements.md` and not re-read. **[INFERENCE]** = my reading, not stated in code or a source. Paths under `nexus-frontend/src/app/` are written `app/…`; paths under `nexus-backend/src/main/java/com/example/nexus/` are written `…/`.
**Precedent followed:** `docs/features/US-019/02-impact.md` (structure, evidence tags, scope guard).
**Scope guard:** this is impact analysis, not design. Options are listed as design questions (§15, DQ-1 to DQ-28). No class designs and no templates.
**No PII.** People are referred to by role. Persona addresses and the dev password are not repeated.

---

## 0. Executive summary

| Question | Answer |
|---|---|
| Frontend modules | **New:** `app/features/access-management/**` (routes, API services, profile state, pages, dialogs, copy module, pure utilities). **Changed shared code:** `app/app.routes.ts`, `app/core/layout/nav.config.ts` (+ spec), `app/core/layout/shell/shell.spec.ts`, `app/core/guards/auth.guard.ts` (+ spec), `app/core/routing/cold-start-routing.spec.ts`, `app/app.routes.spec.ts`, `app/features/dashboard/dashboard.component.ts` (+ spec), `app/shared/types/api/rbac.ts` (+ new wire types), `app/shared/types/api/api-contract.spec.ts`, possibly `app/shared/ui/*` (gaps §6.4), `app/core/logging/logger.service.ts` (DQ-22), `app/core/config/app-config.ts` + `src/environments/*` (DQ-23), `eslint.config.js` (DQ-21), `nexus-frontend/nginx.conf` (DQ-5) |
| Backend production code | **None required for the MVP** (§8). Read-only consumer of 19 shipped endpoints behind three flags |
| Backend non-production code | **Test and dev-seed only:** `ApiContractFixturesTest` (new fixtures; the frontend cannot add a fixture alone, §5.3), `DevDataInitializer` and its tests (two or more new dev-only personas, §7.1) |
| Flyway / DB | **None.** Highest migration unchanged; no DDL, no data migration, no grants change |
| API contract | **No change.** No new endpoint, no field, no version bump. The console is a consumer only |
| New dependencies | **None** expected. Relative time uses `Intl.RelativeTimeFormat`; axe tooling exists |
| ADRs | Next free number is **0028** (`docs/adr/` holds up to 0027) **[VERIFIED]**. A frontend authorization-affordance ADR is optional (DQ-6). ADR-0027 (ETag) needs a deployment note about proxies weakening tags (DQ-5) |
| **Largest finding** | **The editor's save may fail with 428 behind the shipped nginx, and no CI job would catch it.** `nginx.conf:28-30` gzips `application/json` responses of 1 kB or more. nginx turns a strong `ETag` into a weak `W/"…"` when it compresses **[INFERENCE: documented nginx behaviour, not tested here]**. The backend rejects a weak `If-Match` with 428 (`RoleController.java:295`, `IfMatchHeader.java:11`). A 9-permission set is above 1 kB **[INFERENCE: size estimate]**. The full-stack e2e job does not start the nginx `frontend` service (`e2e-full-stack.yml:41-48`), so it cannot see this (§10.1, R-1) |

### Re-trace of claims the requirements left open or mis-stated

| Claim (requirements, discovery) | Result | Evidence |
|---|---|---|
| `contracts/api/` has a fixture for the permission catalogue (`GET /permissions`) | **WRONG.** `permission-catalogue.json` is the **unpaged** `PermissionListResponse` (`{data}`), the shape of `GET /roles/{id}/permissions`. `GET /permissions` returns `PermissionPageResponse` (`data, page, links`) | `ApiContractFixturesTest.java:95`; `PermissionController.java:70-80`; `dto/PermissionPageResponse.java:11-12`. The frontend type `PermissionListResponse` (`app/shared/types/api/rbac.ts:41-43`) has no `page`, so a catalogue reader typed with it would drop paging |
| Q4: the unavailable view is "inside the signed-in layout" | **Not buildable as worded.** The signed-in layout *is* the `authGuard` route (`app.routes.ts:112-115`). A child of it re-runs the failing guard, and the guard runs only on that ancestor, not on children (`canActivateChild` is banned, `app.routes.spec.ts:123`). The view must live outside the shell, and the public layout's children are pinned to exactly three (`app.routes.spec.ts:118-120`) | §3.3, DQ-4 |
| Q12: role-reader user manager = `role:read`, `user:read`, `user:role:assign` | **Insufficient under Q6.** Without `user:directory:read` this persona cannot open any Users route, so it cannot reach the assign dialog it exists to test | §7.1, DQ-18 |
| Q12: auditor = `audit:read` (optionally `user:directory:read`) | **Insufficient.** The Members tab (FR-D1) sits on role detail, which is gated on `role:read` (§3.1 of the requirements). An `audit:read`-only persona cannot reach it | §7.1, DQ-18 |
| FR-G1 puts the active tab in query params (`?tab=`) | **Conflicts with the wrapper.** `NxTabs` is routable by **path** (`routerLinkActive`; US-019 design §12.4 row `nx-tabs`) | DQ-25 |
| "Interceptor retries nothing" vs Q14 retry-once | **Doc conflict.** `rbac.ts:75-78` says `RBAC_012` gets "no automatic retry"; `app-error.ts:102-103` says nothing retries on `Retry-After`. Q14 adds one retry for `RBAC_012` only | §12 docs |
| FR-G9 "no `DomSanitizer` in the feature, CI-enforced" | **Partly enforced.** ESLint bans `bypassSecurityTrust*`, HTML-sink members and `[innerHTML]` bindings (`eslint.config.js:44-103, 125-139`). It does not ban importing or injecting `DomSanitizer` | DQ-21 |
| FR-F7 "no emails in client logs" | **Not defended in depth.** `LoggerService` redacts keys matching `password|token|secret|authorization|cookie|apiKey|session` only (`logger.service.ts:25`). A context key named `email` is logged as is | DQ-22 |

### Top 3 risks (full list §13)

1. **Weak ETag behind nginx makes every save a 428, and CI is blind to it** (§10.1). The cause is config in a frontend-owned file (`nginx.conf:28-30`). The CI e2e path bypasses nginx. Any CDN or load balancer in front of production can do the same thing, and the repo cannot show whether one exists.
2. **The cold-start "unavailable" view changes two pinned shell contracts** (§3.3). These are `authGuard`'s "never navigate on 503" (US-019 §12.10, `auth.guard.ts:23-24, 41`) and the public-route allow-list (`app.routes.spec.ts:118-120`, RC-63(i)). A wrong placement either loops through the guard or adds a second `POST /refresh`, which is a refresh-token reuse and logs the user out (RC-65).
3. **E2E on directory pages and mutating flows is brittle against the PII scan and shared personas** (§7.2). Every Users-list page renders persona addresses in the DOM. A trace recorded on a retry then fails `scan-pii.mjs`, so a flaky pass becomes a red job with no artifacts. Assign and revoke specs that target sign-in personas change other workers' permissions mid-run.

---

## 1. Slice map (from requirements §6, Q1)

| Slice | Items | Code? | Hard upstream | Sections here |
|---|---|---|---|---|
| **S0** Human and provisional inputs | D2 and D3 provisional (Q2), D4 copy (Q3), unavailable-view spec (Q4), personas (Q12), P-9 and P-11 first green run (Q13) | No (except personas) | none | §7, §11 |
| **S1** Foundation and read-only console | Routes, any-of nav, dashboard card, `authGuard` change, wire types and fixtures, profile state, error map for reads, roles list, role detail (read), catalogue, F6, X3, X4 | Yes | S0 copy; us015 + us019 on | §3, §4, §5, §6 |
| **S2** Role authoring | Create, staged edit with Review, ETag/412/428, retry-once, drafts, clone | Yes | S1; DQ-5 resolved | §4.3, §10 |
| **S3** Users and assignment | Users list and lookup, user page join, assign, revoke, self-revoke, own-access refresh | Yes | S1; us012 + us019; new personas | §4.4, §7 |
| S4 to S6 | Rename and delete; Members and Unused; access review (E3 deferred) | Later | MVP | §8.2 |

---

## 2. Cross-cutting state of the frontend at `adda702` [VERIFIED]

| Area | Current state | Evidence |
|---|---|---|
| Route tree | Home redirect, then `PublicLayout` (`auth`, `design-system`, `access-denied`), then `Shell` with `canActivate: [authGuard]` and children `dashboard` and `**` | `app.routes.ts:37, 46-100, 112-130` |
| Guard contract | Every `permissionGuard` route has `data.permission` in `PERMISSIONS` and an `authGuard` ancestor; same-array composition is forbidden; no `canActivateChild` with `authGuard`; public children pinned to three paths | `app.routes.spec.ts:58-98, 118-120, 123-135`; `permission-guard-contract.spec.ts` |
| `permissionGuard` | Single `data.permission`; fails open on a missing or empty value; denies a name outside the union; reads the JWT-derived `AuthStore.permissions()` | `permission.guard.ts:49-84` |
| `authGuard` | One silent refresh on cold start; 503 `AUTH_005` or `NETWORK_ERROR` returns `false`; any other failure redirects to login with `returnUrl` | `auth.guard.ts:7-10, 29-45` |
| Nav | `NavItem.permission: Permission \| null`; `NAV_ITEMS` = Dashboard only; `NAV_ITEMS_TOKEN` lets specs inject gated items; `visibleNavItems` tests one permission | `nav.config.ts:5-38`; `shell.ts:58, 65-67`; `shell.spec.ts:20-22, 38` |
| Nav pin spec | Flattens `children` only (lazy `loadChildren` skipped) and asserts `item.permission === route.data.permission` | `nav.config.spec.ts:6-17, 33-39` |
| Dashboard | A bare `section` + `h1`, `data-testid="dashboard-root"` (used by e2e) | `dashboard.component.ts:11-19`; `e2e/access-management/cold-start.spec.ts:9, 12` |
| Interceptor order | correlation-id, then api-error, then auth (api-error sees errors after the auth replay) | `app.config.ts:37, 134` |
| 401 replay | Refresh, then replay with the same headers (an `If-Match` survives); refresh failure clears the session and goes to `/auth/login` **without** `returnUrl` | `auth.interceptor.ts:188-200` |
| 403 redirect | `RBAC_001` navigates to `/access-denied` unless `SKIP_ACCESS_DENIED_REDIRECT` | `api-error.interceptor.ts:73-79` |
| 503 | One toast per `Retry-After` window (capped at 300 s); never navigates; `NxToast` loaded lazily to keep it out of the initial bundle | `service-availability-notifier.ts:19-39` |
| Error logging | Logs `operation` = method + URL, the code and the status, never the body | `api-error.interceptor.ts:42-71` |
| Structural directive | `*appHasPermission` reads `AuthStore.permissions()` (JWT), not the live profile | `shared/directives/has-permission.directive.ts:44, 55, 66` |
| Config | `AppConfig { production, apiBaseUrl, logLevel, supportContact }`; two environment files | `core/config/app-config.ts:44-84`; `src/environments/` |
| Budgets | initial 500 kB warn / 1 MB error; any component style 4 kB / 8 kB; no lazy-chunk budget | `angular.json:42-53` |

---

## 3. Shell, routing and guards (S1)

### 3.1 `app/app.routes.ts`

- **Add one shell child** for the console (story paths `/admin/access`, `/admin/access/{roles,roles/new,roles/:roleId,permissions,users,users/:userId}`, `US-020.md:54-78, 136-141`), lazy through `loadChildren` into `features/access-management/access-management.routes.ts`. The pattern is `AUTH_ROUTES` (`app.routes.ts:55-58`).
- **Inheritance trap.** A componentless parent's `data` is inherited by its children (Angular `paramsInheritanceStrategy: 'emptyOnly'`) **[REPORTED framework behaviour; the access-denied constraint at `app.routes.ts:81-86` relies on it]**. A parent that carries `data.permission` would gate every child on that single permission and lock out a user manager who lacks `role:read`. Any-of gating at the parent is therefore DQ-2.
- `roles/new` must be declared before `roles/:roleId` **[INFERENCE: router matches in order]**.
- **Every leaf needs a `title`** (`app.routes.spec.ts:153-176`). Route `title` values become `document.title`, which lands in browser history. Role names and emails must not appear there (DQ-26).
- **Contract specs walk lazy children.** `childrenOf` awaits `loadChildren` (`app.routes.spec.ts:28-30`), so the console's routes fall under the `data.permission`, ancestor and title checks with no spec change. That is the intended outcome.

### 3.2 Nav model, any-of (Q7)

| File | Change | Why |
|---|---|---|
| `app/core/layout/nav.config.ts:13, 33-38` | `NavItem.permission: Permission \| null` must express "any of" (`role:read` or `user:directory:read`); `visibleNavItems` changes to an any-of test; `NAV_ITEMS` gains "Access management" | Q7; shape in DQ-1 |
| `app/core/layout/nav.config.spec.ts:33-39` | The pin "`item.permission` equals `route.data.permission`" no longer holds for an any-of item. The rule must pin the item to whatever the parent route gates on (DQ-2), and still catch a mismatch | Stops the menu misleading (`nav.config.ts:19-21`) |
| `app/core/layout/shell/shell.spec.ts:20-22, 93-99` | `GATED_NAV` fixture and persona cases gain an any-of item (held through the first permission, through the second, through neither) | Unit proof of filtering (comment `:68-73`) |
| `NAV_ITEMS_TOKEN` (`nav.config.ts:28-30`) | Unchanged; specs keep injecting fixtures | — |
| `e2e/access-management/shell.spec.ts:10-19` | `NAV_LABELS`: `admin`, `admin2`, `roleManager`, `userManager` and the new personas gain "Access management"; `member` keeps Dashboard only. This makes the e2e nav map able to catch a filtering bug for the first time (P-27 note) | Story scenario 5 |
| `docs/DEVELOPMENT_GUIDE.md:256` | "Add a nav item" rule rewritten for any-of | §12 |

**Breaking for shared code:** the `NavItem` shape is a shell contract that Epic 3 will reuse (requirements §11 "Coordination"). The change is source-level only, and the only producer today is `NAV_ITEMS`.

### 3.3 `authGuard` cold-start 503 (Q4, FR-X3)

| File | Today | Change implied by Q4 |
|---|---|---|
| `app/core/guards/auth.guard.ts:23-24, 36-43` | `AUTH_005` / `NETWORK_ERROR` → `of(false)` | Return a `UrlTree` to the unavailable view; other failures unchanged (login + `returnUrl`) |
| `app/core/guards/auth.guard.spec.ts:85-96` | `it.each` over 503 and network error expects `false` | Expects the unavailable `UrlTree` (and keeps "no login redirect") |
| `app/core/routing/cold-start-routing.spec.ts:96-158` | Entitled, unentitled, refresh failure, exactly one refresh | Add: cold-start 503 lands on the view; still **exactly one** `POST /refresh`; Retry produces one more refresh, never two concurrent ones |
| `app/app.routes.spec.ts:100-121` | Public children pinned to `auth`, `access-denied`, `design-system` | If the view goes under `PublicLayout` (DQ-4), the pin gains one path. This is a deliberate change to the RC-63(i) route-hygiene control and needs threat-model sign-off |
| `e2e/access-management/cold-start.spec.ts:29-35` | Comment "a network error does not [redirect]" | New e2e: intercept `POST /auth/refresh` with a 503 and assert the view and Retry |
| `docs/features/US-019/09-technical.md:103`, `03-design.md` §12.10 | "cancels navigation (`false`)", "never a navigation" | Superseded for the guard only; the interceptor's toast-only rule for actions stays |

**Constraints the design must respect:**
- The view cannot be a shell child (Re-trace table).
- It must make no HTTP call on render, so it cannot trigger a refresh loop.
- `traceId` must not go into the URL (`app-error.ts:44`: "Do not persist or expose in public URLs").
- Retry must re-enter through the shell exactly once.
- A 429 on the retried refresh is treated as "redirect to login" by today's guard (`auth.guard.ts:42`; the nginx auth zone allows 10 r/min per IP, `nginx.conf:9, 35-37`), so Retry needs a cool-down. See DQ-4.
- A mid-session 503 on a console page load renders the same state inline. Actions keep the toast (Q4).

### 3.4 `permissionGuard`

- **Code unchanged** for single-permission children: `roles`, `roles/:roleId` and `permissions` use `role:read`; `roles/new` uses `role:write`; `users` and `users/:userId` use `user:directory:read` (Q6). Tabs that need `audit:read` (S5, S6) come later.
- **Any-of** at the console root is not supported by `permissionGuard` (`permission.guard.ts:58-68`). Either a sibling guard reading `data.anyOf` or a redirect-only root is needed (DQ-2). A new guard needs its own contract-spec coverage, equivalent to `app.routes.spec.ts:58-98`.
- **P-27** (unentitled user lands on `/access-denied`, e2e) becomes testable: `member` deep-links to `/admin/access/roles` (`docs/features/US-019/14-pending-items.md:31`).

### 3.5 Dashboard card (FR-G7)

`app/features/dashboard/dashboard.component.ts:11-19` gains a card (`NxCard`, `NxButton`) visible for the same any-of set as the nav item. It must keep `data-testid="dashboard-root"` and the single `h1`. `dashboard.component.spec.ts` gains visible and hidden cases. The card is **UX only**, and it reads `AuthStore` like the nav does (FR-G6). Adding `NxCard` (MatCard) to the dashboard's lazy chunk does not touch the initial bundle **[INFERENCE: the dashboard is `loadComponent`, `app.routes.ts:120-121`]**.

---

## 4. Feature folder `app/features/access-management/` (new)

### 4.1 Responsibilities to place (design decides names and shape; DQ-28)

| Concern | Create | Notes |
|---|---|---|
| Routes | `access-management.routes.ts` | Lazy; titles static; `permissionGuard` per child |
| API clients | RBAC client (roles, permissions, assignments, holders, effective), directory client (list, `ids=`, get, lookup) | `HttpClient` + `APP_CONFIG.apiBaseUrl` pattern (`features/auth/auth.service.ts:53, 193`). Every console request sets `SKIP_ACCESS_DENIED_REDIRECT` (FR-F4) |
| ETag handling | Read `ETag` from `GET /roles/{id}/permissions` with `observe: 'response'`; send `If-Match` on `PUT` | CORS already exposes `ETag` and allows `If-Match` (`config/SecurityConfig.java:209-216`) **[VERIFIED]** |
| Live profile | `AuthorizationProfileService` (signals) over `GET /users/me/authorization` | Source of affordances (FR-G6); nav and guards keep `AuthStore` (DQ-6, DQ-7) |
| Catalogue | Session cache of `GET /permissions?size=100` | 9 rows today; `totalElements` feeds the Q17 hint (DQ-13) |
| Roles fetch-all | Page 0, then remaining pages | At most 5 calls at the default cap of 500; cap is configurable (DQ-12) |
| Copy module | One module for all text: errors per code and reason, confirmations, disabled reasons, empty states, propagation constant (Q3), labels | Q2: approved copy swaps in later |
| Error map | Exhaustive over a typed code union, including the four `RBAC_001` reasons | FR-B2; DQ-14 |
| Pure utilities | `diffPermissions`, admin-defining hint, `Retry-After` countdown, CSV neutraliser (kept ready, Q20) | Unit-tested, no Angular |
| Drafts | `sessionStorage` adapter, try/catch, ids only | FR-G4; DQ-17 |
| Pages | Roles list, role detail (read, edit), create, catalogue, users list, user page, unavailable state (shared with §3.3) | Native `<table>` for the matrix (FR-A6); `NxTable` for lists |
| Dialogs | Review changes, assign, revoke, typed self-revoke | `NxDialog.openTemplate` and `confirmTyped` (§6.4, DQ-8) |

### 4.2 Read flows and call counts (S1; input to FR-F8, DQ-11)

| Page | Calls (cold) | Permission | Flag |
|---|---|---|---|
| Any console entry | `GET /users/me/authorization` ×1 | authenticated | us019 |
| Roles list | `GET /roles?size=100&page=n` × ⌈roles/100⌉ (≤ 5 at the default cap) | `role:read` | us015 |
| Role detail | `GET /roles/{id}` + `GET /roles/{id}/permissions` (ETag) + catalogue (cached) | `role:read` | us015 |
| Catalogue | `GET /permissions?size=100` ×1 | `role:read` | us015 |
| Users list | `GET /users?page&size&status` ×1; lookup `POST /users/lookup` on submit | `user:directory:read` | us019 |
| User page | `GET /users/{id}` + `GET /users/{id}/roles` (paged; `user:read`) + roles fetch-all for the System badge (`role:read`, Q19) | mixed, degrades | us019, us012, us015 |

### 4.3 Write flows (S2, S3)

| Flow | Calls | Notes |
|---|---|---|
| Create role | `POST /roles` (201), then `GET /roles/{id}/permissions` (for an ETag), then `PUT …/permissions` | Three calls. Partial failure leaves a role with no permissions (requirements §8 "Partial failure") |
| Save permissions | `PUT /roles/{id}/permissions` + `If-Match` | One retry on `RBAC_012` (Q14). The `If-Match` stays valid because a 409 applied nothing **[INFERENCE from the outcome order, `RoleController.java:246-248`]**. 412: re-read and rebase (DQ-16). 428: client defect |
| Assign | `POST /users/{id}/roles` `{roleId}` | One retry on `RBAC_012`. 429 `RBAC_011` only for admin-defining or self targets |
| Assign dialog, rule C3(b) | Per candidate `GET /roles/{id}/permissions` | **N+1 risk:** up to 500 calls if evaluated for every candidate (DQ-10) |
| Revoke | `DELETE /users/{id}/roles/{roleId}` | 403 before 409 `RBAC_002` (`RoleAssignmentService.java:400-435`, REPORTED). Permission summary needs one `GET /roles/{id}/permissions` (`role:read`) |

---

## 5. Shared types, error codes and contract fixtures

### 5.1 `app/shared/types/permission.ts`

- `Permission` union (`:13-22`) and `PERMISSIONS` (`:25-35`): **no new member** (9 match the backend catalogue, `ApiContractFixturesTest.java:114-125`).
- `PERMISSION_LABELS` (`:44-54`) and `PERMISSION_GROUP_LABELS` (`:57-62`): placeholder copy is replaced by provisional D3 text (Q2). The text is either moved into or referenced from the copy module, so there is one source (DQ-14). `permission-catalogue.spec.ts` keeps the union, labels and fixture in step.
- `permissionResource` (`:65-67`): reused for grouping (FR-A3).

### 5.2 `app/shared/types/api/rbac.ts` and `user-directory.ts`

| Item | State | Needed |
|---|---|---|
| `RoleResponse`, `RoleListResponse`, `PermissionResponse`, `CallerAuthorizationResponse`, `ReplaceRolePermissionsRequest` | Exist (`rbac.ts:18-59`) | Reuse |
| `PermissionListResponse` (`{data}`) | Exists (`rbac.ts:41-43`); correct for `GET /roles/{id}/permissions` only | Doc comment must say so |
| `PermissionPageResponse` (`data, page, links`) | **Missing** | For `GET /permissions` (`dto/PermissionPageResponse.java:11-12`) |
| `RoleAssignmentResponse` (`userId, roleId, roleName, assignedAt, assignedBy: string \| null`) + list page | Missing | `dto/RoleAssignmentResponse.java:13-14`, `RoleAssignmentListResponse.java:10-11` |
| `AssignRoleRequest` (`roleId`) | Missing | `dto/AssignRoleRequest.java:20-25` |
| `CreateRoleRequest` (`name, description`) | Missing | `dto/CreateRoleRequest.java:24-33` |
| `UpdateRoleRequest` | Missing (S4) | `dto/UpdateRoleRequest.java:18-32` |
| `RoleHolderResponse` (`userId, assignmentId, assignedAt, assignedBy`) + page | Missing (S5) | `dto/RoleHolderResponse.java:10-11` |
| `PermissionHolderResponse` (`userId, viaRoleIds`) + page; `EffectivePermissionsResponse` (`userId, permissions[]`) | Missing (S6) | `dto/PermissionHolderResponse.java:6`, `EffectivePermissionsResponse.java:10-11` |
| `RbacErrorCode` | `RBAC_001, 003, 004, 005, 010, 011, 012` (`rbac.ts:79-80`) | Add `RBAC_002`, `RBAC_006` to `RBAC_009`. A directory union `USER_DIR_001`, `USER_DIR_002`. The generic codes the map handles: `VALIDATION_FAILED`, `PRECONDITION_FAILED`, `PRECONDITION_REQUIRED`, `RESOURCE_NOT_FOUND`, `ROLE_NOT_FOUND`, `USER_NOT_FOUND`, `PERMISSION_NOT_FOUND`, `ROLE_ASSIGNMENT_NOT_FOUND`, `ACCESS_DENIED`, `AUTH_005`, `NETWORK_ERROR`, `HTTP_ERROR`, `UNEXPECTED_ERROR` (`api-error.interceptor.ts:114-126`) |
| JSDoc `rbac.ts:75-78` ("no automatic retry" for `RBAC_012`) | Contradicts Q14 | Reword: the interceptor never retries; the console's write services retry once |

Widening a string union is **non-breaking** for existing code. No exhaustive `switch` over `RbacErrorCode` exists outside the contract spec **[VERIFIED by grep: the only consumer is `api-contract.spec.ts:138-153`]**.

### 5.3 `contracts/api/*.json` and the two contract tests

- **Twelve fixtures today** (`contracts/api/`). They are written by the backend test `ApiContractFixturesTest` (`-Dcontracts.update=true`, `:41, 64-67`) and read by `app/shared/types/api/api-contract.spec.ts`.
- **Lockstep is enforced in both directions:** `should_haveNoFixtureWithoutARecord_when_theDirectoryIsListed` (`ApiContractFixturesTest.java:76-82`) fails the backend build if a JSON file exists without a record. **A frontend-only PR cannot add a fixture.** Every new fixture is a change to `nexus-backend/src/test/java/com/example/nexus/contracts/ApiContractFixturesTest.java` (test code, not production; §8.1).
- Fixtures to add, at minimum: permission page; assignment list page (with `assignedBy` null and non-null); create-role request; assign request; problem bodies for `RBAC_002`, `RBAC_006`, `RBAC_008`, `RBAC_009`, `RBAC_011` (status 429), `PRECONDITION_FAILED`, `PRECONDITION_REQUIRED`, `USER_DIR_001`. Holders and effective permissions arrive with S5 and S6.
- The PII rule stays: only `example.test` addresses (`ApiContractFixturesTest.java:85-89`; `api-contract.spec.ts:155-158`).
- **Naming hazard:** keep the existing `permission-catalogue` key (renaming touches both tests and the US-019 catalogue spec). Add the paged shape under a new key and fix the misleading name in docs only (DQ-14).

### 5.4 `app/core/http/api-error.interceptor.ts`

- **No code change required.** It already maps `reason` (`:109-110`) and `Retry-After` (`:111, 150-157`), and it honours the skip token (`:73-79`).
- `appError.details` is passed through for `VALIDATION_FAILED` (`:102`), which FR-B2 uses per field.
- **PII check:** it logs `req.url` (`:44, 52`). Console URLs carry only role and user ids. `ids=` batches are ids; lookups are a POST body. This is acceptable under FR-F7 **[VERIFIED]**.

---

## 6. `shared/ui` reuse and gaps

### 6.1 Reuse as is [VERIFIED in `app/shared/ui/index.ts:112-165`]

`NxAnnouncer`, `NxBadge`, `NxButton` (`loading`), `NxCard`, `NxBreadcrumb`, `NxCheckbox` (tri-state, `disabledReason`), `NxChip`, `NxIcon`, `NxInput`, `NxSearchField` (`mode="submit"` for lookup), `NxPageHeader` (the page `h1`), `NxSelect`, `NxSkeleton`, `NxTabs` (routable), `NxTable` (`totalCount`, `pageable`, `pageChange`, custom cells, caption, sticky header; `table.ts:288-411`), `NxDialog` (`open`, `confirmTyped`, `openTemplate`; `dialog.ts:404, 420, 528`), `NxMenu`, `NxTooltip` (supplementary only), `NxToast`, `NxEmptyState`, `NxErrorState` (`retry`).

### 6.2 Feature-local, no wrapper needed

- The permission matrix is a native `<table>` with group header rows (FR-A6). `NxTable` has no row groups, and a native table needs no Material import.
- Relative time uses `Intl.RelativeTimeFormat` in a pure function.

### 6.3 Constraints from ADR-0004 enforcement

ESLint forbids `@angular/material*` and `@angular/cdk*` imports outside `src/app/shared/ui/**` (`eslint.config.js:106-124`). Consequences:
- A dialog **component** (as opposed to a template) needs `MAT_DIALOG_DATA` or `MatDialogRef` from `@angular/material/dialog`, which is banned in the feature. `openTemplate` returns a `MatDialogRef` the feature may use without importing the type.
- Breakpoints are CSS only (no CDK `BreakpointObserver`), as the shell already does (US-019 design §12.3).

### 6.4 Gaps for the design to decide (DQ-8, DQ-9)

| Need | Story item | Today | Options |
|---|---|---|---|
| Multi-line description with a live character count | FR-B1 | `NxInput` has no `textarea` or counter (`input.ts:112-183`) | Add a `multiline` and `maxLength` counter to `NxInput`, or add `nx-textarea` |
| Inline banner (system role, read-only, conflict, not enabled, role limit) | FR-A5, Q8, FR-X1, FR-F6, FR-B2 | None; `NxErrorState` is a full error block | New `nx-banner` (`role=status` or `alert`; variants) |
| Component dialog with injected data | Review, Assign | Template dialogs only | Use `openTemplate` with host-owned state (no new API), or add `openComponent` + an `NX_DIALOG_DATA` token |
| Sticky Review footer, WCAG 2.4.11 | FR-B3, Q26 | None | Feature CSS with tokens; manual check |

Any new wrapper follows the `design-system` skill: spec, barrel, preview card in `design-system.html`, unit axe, 4 kB style budget.

---

## 7. E2E impact

### 7.1 Personas (Q12) and dev seeding

| File | Change |
|---|---|
| `…/identity/infrastructure/seed/DevDataInitializer.java:79-99` | Add the new personas through the existing `rbacSeeder.ensureRole` and `persona(...)` helpers. `assigned_by` = the seeded administrator, never self (RC-63(g), `:24-27`). **Existing personas unchanged**, so US-019 specs keep their expectations |
| `…/identity/infrastructure/seed/DevUserSeeder.java` | New address constants (dev-only; synthetic) |
| `DevDataInitializerTest`, `DevPersonaSeedIT` (`:41-138`), `DevSeedProfileGuardTest` | New personas in the lists; the no-email-in-log assertion (`DevPersonaSeedIT.java:128`) covers them automatically; the profile guard is unchanged |
| `nexus-frontend/e2e/fixtures/personas.ts:5-41` | New `PersonaKey` members and entries; `SIGN_IN_PERSONAS` extended. `scan-pii.mjs:165-172` imports `PERSONAS`, so new addresses are scanned with no tool change **[VERIFIED]** |
| `docs/DEVELOPMENT_GUIDE.md:250` | Persona list |

**Persona sets the e2e needs** (fixes the Re-trace rows; final sets in DQ-18):
- **Auditor:** `role:read` + `audit:read`, **without** `user:directory:read`. Used post-MVP (S5, S6); it exercises the ids-only path of FR-X5.
- **Role-reader user manager:** `role:read`, `user:read`, `user:role:assign`, **`user:directory:read`**, not an administrator. Used to test C3 and C4 in the MVP.
- **Assignment targets:** one or more ACTIVE users that no spec signs in as, used only as assign and revoke targets (§7.2). An unverified PENDING target already exists for Q21.
- Seeding stays `dev & !break-glass & !prod` (`DevDataInitializer.java:34`). The `test` profile never seeds.

### 7.2 Fixtures, PII and data hygiene

| Constraint | Source | Effect on console specs |
|---|---|---|
| Per-worker persona contexts; no two pages of one persona at once | `e2e/fixtures/test.ts:26-42`; US-019 design §13.2 | Unchanged; dialogs and pages are serial within a test |
| `enterAddress` keeps addresses out of step titles | `e2e/fixtures/secret-input.ts:3-17` | **Mandatory** for the exact-email lookup. `locator.fill(email)` would fail the scan |
| Persona addresses must not appear in reports, traces or the backend log | `e2e-full-stack.yml:102-112`; `scan-pii.mjs:5, 165-172` | Any Users-list page renders persona addresses in the DOM. (a) Assertions must not quote emails; `toHaveText(email)` puts the value in the report on failure. (b) A trace recorded on retry (`playwright.config.ts:16, 20`) holds DOM snapshots and fails the scan. Precedent: `test.use({ trace: 'off' })` in `e2e/auth/logout.spec.ts:36-38` (P-21). (c) CI screenshots are off already (`playwright.config.ts:21-23`) |
| Specs that mutate create their own data | US-019 design §13.2 "Data hygiene" | Roles: per-worker unique names, cleaned up through the API. Assignments: **never** target a sign-in persona, because that changes another worker's nav and permissions mid-run. Use dedicated targets (§7.1) |
| Role cap | `RoleManagementService.java:179` (REPORTED) | CI's database is fresh per run (`e2e-full-stack.yml:127-129`). A local dev database keeps roles from earlier runs, so cleanup matters locally |
| Backend required | `e2e/fixtures/backend.ts:12-27` | With `E2E_REQUIRE_BACKEND=1` an unreachable backend throws |

### 7.3 CI job and the skipped-spec rule (Q13)

- `assert-executed.mjs` already fails on **any** skipped test and on fewer than `--min` executed (`e2e/tools/assert-executed.mjs:3, 26, 36-45`). Q13 needs no new tool. It does need:
  1. `E2E_MIN_TESTS` raised from `31` (`e2e-full-stack.yml:25-27`) in the same PR that adds console specs.
  2. **P-11:** the job has never run end to end (`docs/features/US-019/14-pending-items.md:29`). It must run green once before the first console PR merges.
  3. **P-9:** the job is a required check (`14-pending-items.md:21`). This is an Ops action.
- The job starts `backend` and `mailhog`, not the nginx `frontend` (`e2e-full-stack.yml:41-48`). The SPA is served by the dev server cross-origin, so CORS for `If-Match` and `ETag` is exercised, but nginx's gzip is **not** (§10.1).
- `frontend-ci.yml:61-106` runs `npm run e2e` with no backend. Console specs skip there, and that job uploads its report with no PII scan. Skipped tests produce no PII, so this is acceptable. The job is a smoke test, not the gate.

### 7.4 Specs to add (names are design's)

- **P-27:** `member` deep-links to a console route and lands on `/access-denied`.
- Per-persona nav (§3.2) and dashboard card.
- Cold-start 503 → unavailable view → Retry (route interception of refresh).
- Read pages with axe in both themes (FR-F1).
- MVP flows: create, edit, review and save (including a 412 provoked by a second API write), assign and revoke against a dedicated target, the self-assignment block, 409 `RBAC_002` inline, and the XSS payload description rendering as text (scenario 24).

---

## 8. Backend

### 8.1 Confirmation: no production backend change for the MVP

Every endpoint, header, CORS entry and error code the MVP uses exists at `adda702` (table §8.2). No DTO, controller, migration or config change is required. The only backend files touched are **test and dev-seed code**: `ApiContractFixturesTest` (§5.3) and the dev seeders and their tests (§7.1). These are outside the production artifact's behaviour, except the `dev`-profile seeder, which is excluded under `prod` and `break-glass` (`DevDataInitializer.java:34`). ArchUnit imports main classes only (`HexagonalArchitectureTest.java:69`, `ImportOption.DoNotIncludeTests`), so the test changes cannot trip it. The seeder already calls `rbac.application.port.out` ports from `identity.infrastructure`, so it adds no new dependency direction.

### 8.2 Read-only dependencies by endpoint [VERIFIED `@RequiresPermission` and `@ConditionalOnProperty` lines]

| Endpoint | Permission | Flag | Slice | Code |
|---|---|---|---|---|
| `GET /api/v1/users/me/authorization` | authenticated | us019 | S1 | `CallerAuthorizationController.java:31, 47` |
| `GET /roles` · `GET /roles/{id}` · `GET /roles/{id}/permissions` (ETag) | `role:read` | us015 | S1 | `RoleController.java:78, 142-143, 179-180, 213-214` |
| `GET /permissions` (paged) | `role:read` | us015 | S1 | `PermissionController.java:36, 56-57` |
| `POST /roles` | `role:write` | us015 | S2 | `RoleController.java:101-103` |
| `PUT /roles/{id}/permissions` (`If-Match`) | `role:write` (+ `role:read` live) | us015 | S2 | `RoleController.java:252-253, 270` |
| `GET /users` · `GET /users/{id}` · `POST /users/lookup` | `user:directory:read` | us019 | S3 | `UserDirectoryController.java:56, 88-89, 147-148, 191-192` |
| `GET /users/{id}/roles` | `user:read` | us012 | S3 | `UserRoleController.java:63, 145-146` |
| `POST /users/{id}/roles` · `DELETE /users/{id}/roles/{roleId}` | `user:role:assign` | us012 | S3 | `UserRoleController.java:89-91, 190-192` |
| `PATCH /roles/{id}` · `DELETE /roles/{id}` | `role:write` | us015 | S4 | `RoleController.java:455-456, 503-505` |
| `GET /roles/{id}/holders` · `GET /permissions/{id}/holders` · `GET /users/{id}/effective-permissions` | `audit:read` | us015 | S5, S6 | `AccessReviewController.java:50, 66-67, 111-112, 154-155` |
| `POST`/`DELETE /roles/{id}/permissions[/{pid}]` (attach, detach) | `role:write` | us015 | **not used** (PUT replaces them) | `RoleController.java:359-361, 408-410` |

Flags: `feature.nexus-us012-…`, `…-us015-…`, `…-us019-user-directory` default `false` in base and true in dev and test (requirements §3.1, REPORTED line numbers). A disabled controller answers 404 `RESOURCE_NOT_FOUND`, which is distinct from the entity 404 codes (requirements §3.7).

### 8.3 Follow-ups F-1 to F-3 (Q10; to record in `docs/features/US-020/14-pending-items.md`)

| ID | Gap | MVP behaviour without it | Backend shape (for the follow-up story, not designed here) |
|---|---|---|---|
| **F-1** | No distinct-administrator count and no per-role `isAdminDefining` | No up-front lockout block; revoke dialog warns on administrator roles; 409 `RBAC_002` handled inline (Q16). Admin-defining shown as a hint from `permissionCount` vs the catalogue total (Q17) | Additive field on `RoleResponse` and/or a count on the profile or role |
| **F-2** | `GET /users/{id}/roles` has no `isSystemRole` and no permissions | Join on roles fetch-all; on-demand `GET /roles/{id}/permissions`; visible degradation without `role:read` (Q19) | Additive fields on `RoleAssignmentResponse` |
| **F-3** | No audited export | E3 deferred (Q20) | Server-side export endpoint with an audit event |

---

## 9. Reuse vs create

| Reuse unchanged | Extend | Create |
|---|---|---|
| `permissionGuard`, `safeReturnUrl`, `SKIP_ACCESS_DENIED_REDIRECT`, `apiErrorInterceptor`, `authInterceptor` (401 replay keeps `If-Match`), `ServiceAvailabilityNotifier`, `AuthStore`, `LoggerService` API, `NexusTitleStrategy`, route focus, `NxTable`/`NxDialog`/`NxCheckbox` and the rest of §6.1, `Permission` union, `permissionResource`, e2e `personaContext`, `enterAddress`, `expectNoSeriousA11yViolations`, `requireBackend`, `assert-executed.mjs`, `scan-pii.mjs`, `Shell` component code | `NavItem` + `visibleNavItems` + `NAV_ITEMS` (any-of), `nav.config.spec`, `shell.spec`, `authGuard` (+ spec, cold-start spec), `app.routes.ts` (+ spec pin if DQ-4 uses the public layout), dashboard (+ spec), `rbac.ts` types and error union, `api-contract.spec.ts`, `ApiContractFixturesTest` + fixtures, `PERMISSION_LABELS` copy, `personas.ts`, `DevDataInitializer` (+ tests), shell e2e `NAV_LABELS`, `E2E_MIN_TESTS`, possibly `NxInput`, `LoggerService.SENSITIVE_KEYS`, `AppConfig`, ESLint, `nginx.conf` | `features/access-management/**` (§4.1), unavailable view (§3.3), any-of root guard or redirect (DQ-2), possibly `nx-banner` and `nx-textarea` (§6.4), console e2e specs (§7.4), `docs/features/US-020/14-pending-items.md` |

---

## 10. Contracts, config and breaking changes

### 10.1 ETag through proxies (new finding)

- **Facts [VERIFIED]:** the backend sends a strong tag (`ResponseEntity.ok().eTag(set.version())`, `RoleController.java:343-345`). `If-Match` must be "exactly one strong entity tag", and a weak tag is 428 (`RoleController.java:257, 295`; `IfMatchHeader.java:11`). `nginx.conf:28-30` sets `gzip on; gzip_types … application/json; gzip_min_length 1024`, and `location /api/` proxies with no `gzip off` (`:45-51`).
- **Inference:** nginx compresses JSON responses over 1 kB from the proxied backend and weakens the `ETag` (`W/"…"`) when it does. The SPA echoes the weak tag and receives 428 on every save of a set whose JSON exceeds 1 kB. That is about 7 or more permissions at today's description lengths **[INFERENCE]**.
- **Detection:** the backend counter `COUNTER_PERMISSION_REPLACE` with outcome `precondition_required` (`RoleController.java:309-315`). A non-zero rate in an nginx-fronted environment is the signature.
- **Not caught by CI:** the full-stack job does not run nginx (§7.3). Design decides the fix (DQ-5). The candidate is a frontend-owned file, so it stays inside "frontend only".

### 10.2 Breaking or behaviour changes

| Change | Who is affected | Kind |
|---|---|---|
| `authGuard` navigates to the unavailable view instead of `false` on cold-start 503 or network error | Every signed-in deep link, not only the console | **Behaviour change of a shared guard** (supersedes US-019 §12.10 for the guard) |
| Public-layout children pin (if DQ-4 picks it) | `app.routes.spec.ts:118-120`; RC-63(i) route hygiene | **Contract-test change**; needs threat-model sign-off |
| `NavItem.permission` shape (any-of) | `nav.config.ts`, its spec, `shell.spec.ts`, DEVELOPMENT_GUIDE rule; Epic 3 consumers | **Shell API change** (source-level) |
| Shell e2e `NAV_LABELS` | Four existing personas gain an entry | Test expectation change |
| `RbacErrorCode` widened; new types | None | Additive |
| New fixtures | Backend test and frontend spec, in one PR | Additive, lockstep |
| New personas | Dev and CI databases only | Additive |
| `nginx.conf` gzip for `/api/` (if DQ-5 picks it) | All API responses through nginx: larger payloads, no compression | Ops-visible behaviour change |
| `AppConfig` field (if DQ-23 picks it) | Both environment files and any test `APP_CONFIG` stubs (e.g. `shell.spec.ts:41`) | Additive; stubs must add the field (TypeScript excess and required property) |
| HTTP API | — | **None** |

### 10.3 Data and DB

**None.** No Flyway migration, no DDL, no data migration, no `nexus_app` grant change, no cache key or epoch change, no Redis use from the client. The only data written is by the dev-profile seeder (§7.1) and by e2e specs at runtime.

### 10.4 Config and flags

- **Backend flags:** unchanged; the release rule is "all three on" (Q9). Production values are not visible in the repo (P-7).
- **Frontend:** no runtime flag exists. With production flags off today, deploying the console would show admins a nav entry whose every area says "isn't enabled" (FR-F6). This is the G11 kill-switch gap (DQ-23).
- **CI:** `E2E_MIN_TESTS` (§7.3). Rate-limit overrides for CI live in `docker-compose.e2e.yml` and should not need raising **[INFERENCE: logins are per worker per persona; two more personas add two logins per worker]**.

---

## 11. Security-relevant surfaces (input to the Gate 2 threat model)

| Surface | Fact | Exposure | What the design must state |
|---|---|---|---|
| **Stored XSS** | Descriptions accept `<`, `>`, quotes and Unicode format characters; only `\p{Cntrl}`, U+2028 and U+2029 are rejected (`CreateRoleRequest.java:29-33`, `UpdateRoleRequest.java:22-26`). Names are ASCII by pattern (`:27`). Emails are self-asserted | Rendered in tables, dialogs, toasts, breadcrumbs and titles | Interpolation only; lint already bans sinks (`eslint.config.js:44-103, 132-138`); extend to `DomSanitizer` (DQ-21). **Bidi spoofing:** U+202E and similar are `\p{Cf}` and pass the pattern, so a description can visually reorder text. Isolate user text (`dir="auto"` / `unicode-bidi: isolate`) **[INFERENCE]**. Toasts and `aria-live` announcements must take text, never HTML |
| **ETag / 412 / 428** | Strong tag only; 412 has no body state; 403 precedes 412 (`RoleController.java:246-248`) | Weak tags via proxy (§10.1); a stale draft applied with an old tag | Re-read on 412, never resubmit automatically; restored drafts use the current ETag (FR-G4); 428 = defect path with `traceId` |
| **401 replay of a mutating request** | Replay keeps headers (`auth.interceptor.ts:188-191`) | Duplicate application | The 401 is raised before the handler runs, so the replay is the first execution **[REPORTED requirements §8]**; the threat model confirms |
| **Retry-once `RBAC_012`** | 409 means not applied | Automatic re-send of a mutating request that may now be 403 | Exactly one retry, only `PUT` permissions and `POST` assign; never on 403, 412, 429; in the feature service, not the interceptor (DQ-15) |
| **PII in logs** | Interceptor logs URLs (ids only); `LoggerService` redaction lacks `email` (`logger.service.ts:25`); `GlobalErrorHandler` falls back to `JSON.stringify(error)` (`global-error-handler.ts:65`) | An email in a log context or an unhandled `AppError` | Never put emails or search text in log contexts (FR-F7); add `email` to redaction (DQ-22); handle every console error so none reaches the global handler |
| **PII in reports** | §7.2 | CI artifacts | Trace off for directory specs; `enterAddress`; no email text assertions |
| **Stale profile** | Grants do not bump the epoch; the JWT lags up to 900 s (requirements §3.6) | Nav (JWT) and affordances (profile) disagree | Profile drives mutating affordances; any 403 on a predicted-allowed action re-reads the profile (DQ-6, DQ-7) |
| **`sessionStorage` drafts** | Per tab, survives a re-login in the same tab | User B in the same tab restores user A's draft and could apply it with B's rights | Key by user id and role id; clear on logout; ids only; restore only after re-reading the current set (DQ-17) |
| **Unavailable view and `returnUrl`** | `safeReturnUrl` exists (`core/routing/safe-return-url.ts`) | Open redirect via a new query parameter | Reuse `safeReturnUrl`; no `traceId` in the URL; no HTTP call on render (DQ-4) |
| **Enumeration** | Cross-tenant and missing ids return the same 404 (requirements §3.2) | — | The console must show the same "not found" for both |
| **Framing and CSP** | `frame-ancestors 'none'`, `connect-src 'self'` (`nginx.conf:26`) | — | Unchanged; the console adds no third-party origin |
| **Client gating is UX only** | `PROJECT.md` Key Constraints; `permission.guard.ts:43-45` | — | Every server rejection handled inline even when predicted allowed |

---

## 12. Docs to update

| Doc | Change |
|---|---|
| `docs/DEVELOPMENT_GUIDE.md:248-256` | Personas (new ones); "Add a nav item" any-of rule; the unavailable view; directory-spec PII rules (trace off, `enterAddress`) |
| `docs/features/US-019/14-pending-items.md:31, 50, 69` | P-27 closed by the US-020 e2e; P-20/P-32 superseded by Q4 |
| `docs/features/US-019/09-technical.md:103` | `authGuard` 503 behaviour (pointer to US-020) |
| `docs/features/US-020/14-pending-items.md` (new) | F-1 to F-3; UX and PM approval of D2 and D3; DPO acknowledgement; P-9, P-11 |
| `docs/adr/0027-role-permission-set-optimistic-concurrency.md` | Note: proxies must not weaken the `ETag` (DQ-5) |
| `app/shared/types/api/rbac.ts:1-4, 41, 75-78`; `app/shared/types/app-error.ts:102-103` | JSDoc: fixture coverage, `PermissionListResponse` scope, retry-once ownership |
| `app/shared/ui/preview/design-system.html` | Preview cards for any new wrapper |
| `docs/features/US-020/09-technical.md` (Phase 7) | Console architecture, call budgets, error map |

---

## 13. Risks

| # | Risk | Severity | Verification |
|---|---|---|---|
| **1** | **Weak ETag via nginx gzip → 428 on save; CI cannot see it; unknown production proxies** (§10.1) | **High** | Compose-level check through nginx (curl a large set and assert a strong `ETag`), or an e2e run against `frontend`; backend 428 counter in staging; Ops confirmation of production proxies |
| **2** | **Unavailable view breaks the guard and route contracts**: guard loop, second refresh (RC-65), public-route allow-list widened (§3.3) | **High** | Real-Router cold-start spec: exactly one refresh, Retry adds one; route-contract spec updated deliberately; threat-model sign-off |
| **3** | **E2E brittleness**: PII scan fails on retry traces for directory pages; shared-persona mutation interferes across workers; `E2E_MIN_TESTS` not raised hides dropped specs; P-11 still unproven (§7) | **High** | Trace off for directory specs; dedicated targets; floor raised in the same PR; one green full-stack run before merge |
| 4 | Stale profile vs JWT mispredicts affordances (requirements R-3, R-11) | High | Unit tests "predicted allow, server 403" re-read the profile; e2e for self-revoke |
| 5 | Lockout and admin-defining prediction wrong (requirements R-2; F-1 open) | High | No `memberCount` predictor (lint or grep in review); 409 `RBAC_002` inline test |
| 6 | Stored XSS and bidi spoofing in descriptions and emails (§11) | High | Scenario 24 e2e; unit render test with `<img onerror>` and U+202E; lint |
| 7 | N+1 in the assign dialog (C3(b)) and the user page join (§4.3) | Medium | Call-count unit tests per page (DQ-11) |
| 8 | Shell API change (`NavItem`) and the guard change ripple to Epic 3 | Medium | Specs updated in the same PR; DEVELOPMENT_GUIDE |
| 9 | Contract fixtures need a backend test PR (§5.3); drift if skipped | Medium | Both contract tests in CI |
| 10 | Release with production flags off shows a dead console (§10.4) | Medium | DQ-23; release checklist P-7 |
| 11 | Draft leakage across users in one tab (§11) | Medium | Unit test: logout clears drafts; key includes user id |
| 12 | Persona sets in Q12 cannot reach the pages they test (Re-trace) | Medium | DQ-18; `DevPersonaSeedIT` asserts the sets |
| 13 | Copy and limits drift from config (role cap, propagation TTLs) (requirements R-17) | Low | Q28 rule; copy module review |
| 14 | Lazy chunk grows unnoticed (no chunk budget) | Low | DQ-24 |

---

## 14. Performance, caching and observability

- **Hot paths:** none. The console is admin-only and low-RPS (AS3). The client-side costs are:
  - Roles fetch-all: ≤ 5 calls at the default cap.
  - Assign dialog: up to N role-permission reads if done naively.
  - User page: roles join.
  - Members email batch: one `ids=` call per page of ≤ 100.
- **Throttles the console can hit:** lookup 30 per 60 s, and all directory calls together 600 per 60 s per actor (requirements §3.2). A rapid paging user is far below this.
- **Caching:** client memory only. The catalogue for the session; the profile per console entry, re-read after own-access events (Q24); roles list with a re-read after any mutation. No HTTP caching (`GET /roles/{id}/permissions` is "not cacheable", `RoleController.java:219`). **No Redis** involvement from the client.
- **Observability:** client logs carry ids, codes and `traceId` only (FR-F7, Q29). There are no new backend metrics. Existing signals cover the console: permission-replace outcome counter (428 and 412 rates), `RBAC_011` throttle, directory audit and throttle, 503 `AUTH_005`. A dashboard sketch, if wanted, uses these existing series.
- **Bundle:** the console is lazy. Today the initial bundle is affected only by `authGuard` (eager) and nav config. Neither may import `shared/ui` eagerly; the pattern to follow is `service-availability-notifier.ts:16-18, 36-38`.

---

## 15. Open design questions (DQ-1 to DQ-28)

Each has a recommendation. None is decided here.

**Shell and routing**
- **DQ-1 `NavItem` any-of shape.** *Recommend:* replace `permission: Permission | null` with `anyOf: readonly Permission[] | null` (null = every signed-in user); `visibleNavItems` tests `some`; the spec pins `anyOf` to the target route's gate data. This is one shape for single and any-of, and nothing else consumes the type today.
- **DQ-2 Console root gating.** *Recommend:* a componentless `admin/access` parent with `data.anyOf` and a small any-of guard (contract-spec covered like `permissionGuard`). Each child keeps `permissionGuard` with its own `data.permission`, and the `''` child redirects through a function to the first area the user may open. Avoid `data.permission` on the parent (inheritance, §3.1).
- **DQ-3 Paths.** *Recommend:* keep the story's `/admin/access/...` paths, with `roles/new` before `roles/:roleId`.
- **DQ-4 Unavailable view placement and guard behaviour.** *Recommend:* route `unavailable` under `PublicLayout` (unguarded, no `data`, no HTTP on render). The guard returns `createUrlTree(['/unavailable'], { queryParams: { returnUrl } })`, keeps the `traceId` in an in-memory holder, and Retry goes to `safeReturnUrl(returnUrl)` after a `Retry-After` cool-down. Update the public-path pin deliberately with threat-model sign-off. Mid-session page-load 503s render the same component inline, without navigating.
- **DQ-25 Tabs.** *Recommend:* role-detail and user-page tabs as child routes (routable `NxTabs`), not `?tab=`. Back and Forward work, and later tabs get their own `permissionGuard` (`audit:read`).
- **DQ-26 Titles.** *Recommend:* static route titles only; no role names or emails in `document.title`.

**Data, state and calls**
- **DQ-5 ETag through proxies.** *Recommend:* `gzip off` inside `location /api/` in `nginx.conf` (frontend-owned), plus a compose-level check that `GET /roles/{id}/permissions` through nginx returns a strong `ETag`. Ops confirms no production CDN or load balancer re-encodes `/api/`. Reject client-side `W/` stripping: it misrepresents the tag. Reject relaxing the server: that is a backend change.
- **DQ-6 Affordance source.** *Recommend:* a feature `AuthorizationProfileService` (signals: permissions, `isAdministrator`, status) drives every mutating control; `*appHasPermission` and `AuthStore` stay for nav and guards only. Optional ADR-0028 records "profile for affordances, server final".
- **DQ-7 Profile lifecycle.** *Recommend:* load once on console entry; re-read after own-access events and after any 403 on a predicted-allowed action; no polling; on failure, read-only mode (Q8).
- **DQ-10 C3(b) without N+1.** *Recommend:* list candidates from roles fetch-all; evaluate "carries a permission you lack" only for the selected role (one cached `GET /roles/{id}/permissions`); keep `GRANT_EXCEEDS_CALLER` authoritative; admin-defining as a hint (Q17).
- **DQ-11 Call budgets.** *Recommend:* adopt §4.2 and §4.3 as the per-page budget (FR-F8, NFR-3), with unit tests that count requests per page.
- **DQ-12 Roles fetch-all.** *Recommend:* `size=100`; page 0 first, then the remaining pages in parallel (known from `totalPages`); a hard upper bound (for example 20 pages) with a visible "showing first N" notice; re-read after a mutation.
- **DQ-13 Catalogue cache.** *Recommend:* one `GET /permissions?size=100` per console session; typed as the new `PermissionPageResponse`; no invalidation (static per deploy).
- **DQ-14 Error map and copy module.** *Recommend:* one copy module in the feature keyed by code (and `reason` for `RBAC_001`); a `ConsoleErrorCode` union composed from the extended `RbacErrorCode`, a new `DirectoryErrorCode` and the generic codes in §5.2; a spec that enumerates every code in requirements §3.2. `PERMISSION_LABELS` stays in `shared/types` (compile-time completeness) with provisional D3 text.
- **DQ-15 Retry-once placement.** *Recommend:* in the feature's write service for `PUT` permissions and `POST` assign only; one fresh request with the same `If-Match`; never in an interceptor; update the JSDoc in §5.2.
- **DQ-16 412 rebase.** *Recommend:* on 412, re-read the set and `ETag`, re-apply the user's staged adds and removes onto it, show what changed underneath, and require a new explicit Save.
- **DQ-17 Drafts.** *Recommend:* key `nexus.access.draft.<userId>.<roleId>`; store `{add[], remove[], baseEtag, savedAt}` ids only; clear on save, discard and logout; offer restore only after re-reading the current set; ignore drafts older than the session.
- **DQ-27 Propagation constant.** *Recommend:* constants in the copy module with a comment naming `nexus.jwt.access-token-ttl-seconds` and `nexus.rbac.permission-cache-ttl-seconds`; a review checklist item when either changes. The client cannot read backend config.

**Design system**
- **DQ-8 Dialogs.** *Recommend:* `openTemplate` with host-owned state for Review and Assign, and `confirmTyped` for self-revoke and delete. Add `openComponent` only if a dialog must outlive its host.
- **DQ-9 Wrapper gaps.** *Recommend:* add `nx-banner` (status and alert variants) and a `multiline` and `maxLength` counter on `NxInput` (or `nx-textarea`), each with spec, preview card and unit axe.

**Testing**
- **DQ-18 Persona sets.** *Recommend:* auditor = `role:read` + `audit:read` (no directory permission; post-MVP); role-reader user manager = `role:read`, `user:read`, `user:role:assign`, `user:directory:read`; plus two non-sign-in ACTIVE assignment targets. Existing personas unchanged.
- **DQ-19 Mutation targets and cleanup.** *Recommend:* assign and revoke only against dedicated targets; per-worker unique role names; `afterAll` cleanup through the API (revoke, then delete the role).
- **DQ-20 E2E and PII.** *Recommend:* `test.use({ trace: 'off' })` for every spec that renders the directory; assert emails by test id and count, never by text; `enterAddress` for lookups; no allow-listing in `scan-pii.mjs`.
- **DQ-24 Chunk budget.** *Recommend:* record the console chunk size in the PR (build output) and add no new budget type; the existing initial budget protects the main concern.

**Hardening**
- **DQ-21 Lint.** *Recommend:* add `DomSanitizer` to `no-restricted-imports` for `src/app/features/**` (with a `lint-rules.spec.ts` case), and isolate user text against bidi reordering in the console's templates.
- **DQ-22 Logger redaction.** *Recommend:* add `email` (and `query`/`search`) to `SENSITIVE_KEYS` in `logger.service.ts:25` with a spec; one line, defence in depth for FR-F7.
- **DQ-23 Kill switch and release order.** *Recommend:* an `AppConfig.accessConsoleEnabled` boolean, `false` in the production environment file until P-7 confirms all three flags, `true` in development. When false it hides the nav entry and dashboard card and leaves the routes guarded as usual. Alternative: release the frontend only after the flags are on, with no code.
- **DQ-28 Feature folder layout.** *Recommend:* `features/access-management/{access-management.routes.ts, data/ (API clients, profile, catalogue), copy/, util/ (diff, hint, csv), roles/, role-detail/, role-editor/, catalogue/, users/, user-detail/, dialogs/}`. Specs are colocated, and the feature imports only from `shared/*` and `core/*`.

---

## 16. Not verified

- nginx weakening a strong `ETag` on gzip, and the response size of a 9-permission set: framework behaviour and an estimate; not tested here (§10.1).
- Whether production has a CDN or load balancer in front of `/api/` (outside the repo).
- Angular `data` inheritance for componentless parents is taken from the framework and the existing comment at `app.routes.ts:81-86`, not re-tested.
- Line numbers of flags and throttles in `application*.yml` are carried from requirements §3 (REPORTED).
- That the 401 is always raised before a mutating handler runs (requirements §8, INFERENCE there).
