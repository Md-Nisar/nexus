# Impact Analysis — US-013: Implement Angular Permission Guard and Directive

**Epic:** EPIC-002 (RBAC Foundation) | **Story points:** 3 | **Phase:** 2 (impact) | **Input:** `docs/features/US-013/01-requirements.md` (Gate 1 approved)

**Files read for this analysis:** `nexus-frontend/src/app/{shared/types/auth.ts, shared/types/app-error.ts, core/auth/auth.store.ts, core/auth/auth.store.spec.ts, core/guards/auth.guard.ts, core/guards/auth.guard.spec.ts, core/http/api-error.interceptor.ts, core/http/api-error.interceptor.spec.ts, core/http/auth.interceptor.spec.ts, features/auth/auth.service.ts, features/auth/auth.service.spec.ts, features/dashboard/dashboard.component.ts, shared/ui/error-state/error-state.ts, shared/ui/error-state/error-state.spec.ts, shared/ui/index.ts, app.routes.ts, app.config.ts, app.ts, app.html, features/auth/auth.routes.ts}`, `nexus-frontend/{package.json, tsconfig.json, eslint.config.js, vitest.config.ts, angular.json}`, `nexus-frontend/e2e/auth/registration.spec.ts`, `nexus-backend/src/main/java/com/example/nexus/{identity/interfaces/rest/dto/MeResponse.java, common/web/GlobalExceptionHandler.java}`, `docs/{DEVELOPMENT_GUIDE.md, ARCHITECTURE.md, README.md}`.

Resolved Gate 1 decisions are treated as fixed inputs and are not re-litigated here.

---

## 0. Environment corrections (affect the design doc)

| Claim | Verified reality |
|---|---|
| CLAUDE.md / mission brief: "Angular 21, TypeScript 5.9" | `nexus-frontend/package.json` pins **`@angular/core` 22.0.4** and **`typescript ~6.0.3`**. Design snippets must target Angular 22 APIs (`@Service()`, `input()`, `output()`). |
| `shared/ui/index.ts` JSDoc uses `import { NxButton } from '@shared/ui'` | `tsconfig.json` declares **no `paths` aliases**. Real code uses relative imports (`dashboard.component.ts:7` → `'../../shared/ui'`). All new imports must be relative. |

---

## 1. Modules affected

### 1.1 Shared types — 2 files modified

| File | Change | Lines |
|---|---|---|
| `nexus-frontend/src/app/shared/types/auth.ts` | Add `readonly permissions: readonly string[]` to `AuthUser`, after `roles` | insert after `:37`; interface spans `:8–47` |
| `nexus-frontend/src/app/shared/types/app-error.ts` | Add `readonly requiredPermission?: string` to `AppError` | insert after `:64`; interface spans `:15–65` |

Notes:
- `permissions` is **required** (not optional), per resolved decision 3 (`readonly string[]`, mirroring `roles`). This is the only source-breaking change in the story — see §4.
- The new doc comment must **not** repeat the pre-existing defect on `roles` (`auth.ts:33` says "Comma-delimited RBAC roles" while the type is `readonly string[]`) — requirements §8 already flags this.
- `AuthUser`'s header comment (`auth.ts:1–7`) says values are "Extracted from the JWT access token". Factually the frontend populates them from `GET /v1/users/me`, never by decoding the JWT (`auth.service.ts:191–195`). Pre-existing inaccuracy; harmless to leave, cheap to correct while editing the same file.
- `AppError.requiredPermission` is optional and therefore **non-breaking** (§4).

### 1.2 Store — 1 file modified

| File | Change |
|---|---|
| `nexus-frontend/src/app/core/auth/auth.store.ts` | Add a `permissions` computed signal alongside `currentUser` (`:33`) and `accessToken` (`:38`) |

- Shape: `readonly permissions = computed<readonly string[]>(() => this._session()?.user.permissions ?? NO_PERMISSIONS);`
- Use a module-level `const NO_PERMISSIONS: readonly string[] = []` rather than an inline `?? []` so the "no session" case returns a stable reference. `computed` memoises, so this is a purity/OnPush hygiene point rather than a measurable perf issue — but it costs nothing and prevents identity churn if the value is ever fed into another `computed`/`effect`.
- **Explicitly out of scope:** a symmetric `roles` computed. `AuthUser.roles` exists but no store accessor does; adding one is scope creep with no AC behind it. Name it as a deliberate non-change so it doesn't get smuggled in at review.

### 1.3 Auth service — 1 file modified

| File | Change | Lines |
|---|---|---|
| `nexus-frontend/src/app/features/auth/auth.service.ts` | `MeApiResponse` gains `permissions: string[]`; `buildSession()` maps it | `:21–27` and `:206–220` |

- Defensive default required: map `permissions: me.permissions ?? []`. The backend guarantees non-null (`MeResponse.java:13–16` runs `List.copyOf(permissions)`), but a new frontend bundle served against an older backend would produce `undefined`, and **AC-4 forbids throwing on absent permissions**. The default belongs here (one place) rather than in both the guard and the directive.

### 1.4 Guards — 2 files created

| File | Status |
|---|---|
| `nexus-frontend/src/app/core/guards/permission.guard.ts` | **new** |
| `nexus-frontend/src/app/core/guards/permission.guard.spec.ts` | **new** |

Constraints discovered by reading the existing guard and tsconfig:
- Mirror `auth.guard.ts` exactly in shape: module-scope `export const …: CanActivateFn = (route, state) => {…}`, `inject()` for deps, returns `true | UrlTree`. Unlike `authGuard` it needs **no RxJS** — the signal read is synchronous.
- **Naming reconciliation required.** The story and requirements call it `PermissionGuard` (PascalCase); the repo's only functional-guard precedent is `authGuard` (camelCase const, `auth.guard.ts:20`). The design doc must pick one and the AC-6 developer-guide entry must match, or the documentation is wrong on day one. Recommendation: `permissionGuard` in `permission.guard.ts`, with the doc referring to "`permissionGuard` (the `PermissionGuard` in US-013)".
- **`tsconfig.json:8` sets `noPropertyAccessFromIndexSignature: true`** → `route.data.permission` will not compile. Bracket access (`route.data['permission']`) is mandatory. The value's static type is `any` via the router's `Data` index signature, so narrow with `typeof p === 'string'` before use — `@typescript-eslint/no-explicit-any` is `"error"` (`eslint.config.js:34`) and an unguarded `as string` cast invites review pushback.
- Fail-open path (resolved decision) is exactly the `typeof p !== 'string'` branch returning `true`.
- **Guard composition is a real correctness constraint, not a nicety.** Angular evaluates a route's `canActivate` array sequentially and short-circuits on the first non-`true` result, so `canActivate: [authGuard, permissionGuard]` is safe: `authGuard` completes its silent `refresh()` (which calls `fetchMe` → `setSession`, `auth.service.ts:171–182`) before `permissionGuard` reads the store. But `permissionGuard` used **alone** on a route will, on a cold start (page reload, session `null`), see `[]` and redirect an entitled user to `/access-denied` instead of `/auth/login`. This is the implementation-level manifestation of requirements R-4. The design doc and the AC-6 guide entry must state the ordering requirement explicitly.

### 1.5 Directives — new folder, 2–3 files created

`nexus-frontend/src/app/shared/directives/` **does not exist**; there is no `@Directive` anywhere in `src/app` (verified across all 62 `.ts` files).

| File | Status |
|---|---|
| `nexus-frontend/src/app/shared/directives/has-permission.directive.ts` | **new** |
| `nexus-frontend/src/app/shared/directives/has-permission.directive.spec.ts` | **new** |
| `nexus-frontend/src/app/shared/directives/index.ts` | **new, optional** (barrel, mirroring `shared/ui/index.ts`) |

- **No ESLint change needed.** `eslint.config.js:18–25` already configures `@angular-eslint/directive-selector` with `prefix: ["nx", "app"]`, `style: "camelCase"`, `type: "attribute"` → selector `[appHasPermission]` passes as-is. Worth recording, because it looks like it would need a config change and doesn't.
- **First `app`-prefixed selector in the codebase.** Everything shared today is `nx`-prefixed (`nx-error-state`, `nx-button`, …); `app` is configured but unused. AC-3 mandates `*appHasPermission`, so accept the mixed prefix and note it, or the next reviewer will file it as an inconsistency.
- **File-naming convention decision.** `shared/ui/` uses suffix-less files (`button.ts`, `error-state.ts`); `core/` uses type suffixes (`auth.guard.ts`, `api-error.interceptor.ts`, `logger.service.ts`); `features/` uses `.component.ts`. `has-permission.directive.ts` follows the `core/` convention and is the clearer choice for a non-visual shared primitive, but it is a new precedent inside `shared/` and should be stated.
- **`tsconfig.json:22` sets `strictTemplates: true`** → the microsyntax input name is derived from the selector, so the primary input must be named `appHasPermission`. The codebase convention is signal `input()` (e.g. `error-state.ts:157–190`); combining a signal input with `ViewContainerRef`-driven template creation has **no prior art here**, which is the highest-uncertainty item in the story (see §9 item 2).
- Registration model: Angular standalone components declare their own `imports: [...]` arrays (`dashboard.component.ts:37`, `error-state.ts:119`). There is **no global shared imports barrel that components pull wholesale**, so no such barrel needs updating — each consuming component adds `HasPermissionDirective` to its own `imports`. The AC-6 guide entry must say so explicitly.
- `shared/ui/index.ts` (`:112–137`) must **not** export the directive: that barrel is documented as the UI component library and its JSDoc component-category list would become misleading.

### 1.6 Pages — new folder, 2–3 files created

`nexus-frontend/src/app/shared/pages/` **does not exist** (resolved decision creates it).

| File | Status |
|---|---|
| `nexus-frontend/src/app/shared/pages/access-denied/access-denied.component.ts` | **new** |
| `nexus-frontend/src/app/shared/pages/access-denied/access-denied.component.spec.ts` | **new** |
| `nexus-frontend/src/app/shared/pages/access-denied/access-denied.component.scss` | **new, only if inline styles are insufficient** |

Findings that constrain the component:
- **The app shell provides no `<h1>` and no `<main>`.** `app.html:1–18` renders only `<header>` (wordmark `<a>` + theme-toggle `<button>`) and `<router-outlet />`. `DashboardComponent` (`dashboard.component.ts:40–41`) sets the precedent: the *page* owns `<main>` and `<h1>`. The Access Denied page must do the same to satisfy AC-5's heading hierarchy.
- **`NxErrorState` cannot supply the heading.** `error-state.ts:123` renders `title()` inside `<p class="nx-error-state__title">`, not a heading element. Two options:
  - **(a) Recommended — zero ripple:** the page renders its own `<h1>Access denied</h1>` and uses `<nx-error-state [showRetry]="false" message="…">` with the two CTAs projected through the existing `<ng-content />` slot (`error-state.ts:137`), exactly as the component's own "Access denied" JSDoc example demonstrates (`error-state.ts:56–67`).
  - **(b) Not recommended:** add a `headingLevel` input to `NxErrorState`. Ripples to `error-state.spec.ts`, `features/design-system/design-system-preview.component.html:407–427`, the `shared/ui/index.ts` JSDoc, and every current/future consumer — disproportionate for a 3-point story, and would need an ADR-0004 (design system governance) touch.
- `NxErrorState`'s root carries `role="alert"` (`error-state.ts:121`). Mounting an alert region on route entry is acceptable, but it intersects the unaddressed focus-management gap (requirements §3). The design doc should state whether focus moves to the `<h1>` on activation; the cheapest defensible answer is `tabindex="-1"` on the `<h1>` plus a documented follow-up.
- CTA targets verified: `routerLink="/dashboard"` resolves (`app.routes.ts:120–125`); the `mailto:support@yourcompany.example` placeholder needs an inline `TODO(PM)` comment per resolved decision 1.
- Component-file naming: `access-denied.component.ts` matches the `features/` convention and the "page" semantics; `shared/ui/` suffix-less style would be inconsistent for a routed page. State the choice.

### 1.7 Routing — 1 file modified

| File | Change |
|---|---|
| `nexus-frontend/src/app/app.routes.ts` | Add `{ path: 'access-denied', loadComponent: () => import('./shared/pages/access-denied/access-denied.component').then(m => m.AccessDeniedComponent) }` |

- **This route registration is mandatory and is NOT covered by the "infrastructure only, no route gated" decision.** There is **no wildcard `path: '**'` route** — `app.routes.ts:127–140` is a comment recommending one be added "in a future enhancement". Therefore `router.createUrlTree(['/access-denied'])` against an unregistered path produces an Angular router failure rather than a graceful fallback. The guard is inert without this route.
- Precedent to copy: `/design-system` (`app.routes.ts:81–87`) — top-level path, lazy `loadComponent`, **no guard**. `/access-denied` should likewise be unguarded (requirements Assumption 3: directly viewable).
- No existing route gains `data: { permission: … }` in this story. `data` route metadata is a **new pattern** in this file.
- Adding a wildcard route is **out of scope** — tempting while in the file, but it changes behaviour for every unmatched URL and belongs in its own ticket.

### 1.8 HTTP interceptor — 1 file modified

| File | Change | Lines |
|---|---|---|
| `nexus-frontend/src/app/core/http/api-error.interceptor.ts` | `ProblemDocument` gains `readonly requiredPermission?: string`; `toAppError` threads it into the returned `AppError` | `:93–98` and `:66–74` |

- Field name is **`requiredPermission` (camelCase)** — verified at `GlobalExceptionHandler.java:150` and `:161`. The story draft's `required_permission` is wrong (requirements Correction #1).
- **Two distinct 403 codes exist and only one carries the field:**
  - `RBAC_001` from `InsufficientPermissionException` — carries `requiredPermission` (`GlobalExceptionHandler.java:146–163`).
  - `ACCESS_DENIED` from Spring Security's `AccessDeniedException` — carries **no** `requiredPermission` (`GlobalExceptionHandler.java:165–170`).
  The frontend must therefore tolerate `requiredPermission === undefined` on a 403. Do not key any logic on "status is 403 ⇒ field present".
- The backend's `reason`, `userId`, `tenantId` for RBAC denials are **log-only** (`extraFields`, `:148–153`) and are **not** in the response body. Do not design for them.
- **Recommend keeping the 403 log level unchanged** (the shared `debug` branch at `:50–53`). Requirements FR-10 asks only that `AppError` be able to *surface* the field; changing log levels adds diff surface and would need a corresponding assertion change in `api-error.interceptor.spec.ts`. Smallest correct change = type + mapping only.
- Minor semantics note: `toAppError` builds its object literal unconditionally (`:67–73`), so adding `requiredPermission: body.requiredPermission` sets the key to `undefined` on every problem-document error. `exactOptionalPropertyTypes` is **not** enabled (`tsconfig.json:5–17`), so this compiles; and `toEqual` treats `undefined`-valued keys as equal to absent keys, so no existing assertion breaks.
- **Security constraint carried from requirements §3:** `requiredPermission` must never reach a user-visible surface (EPIC-002 §UX). Nothing mechanically enforces this — flag it for `03b-threat-model.md` and the code-review checklist.

### 1.9 Documentation — 1 file modified, 1 optional

| File | Change |
|---|---|
| `docs/DEVELOPMENT_GUIDE.md` | New subsection under the existing `## Frontend (nexus-frontend/)` heading (`:55`), placed after `### Adding a feature` (`:73–75`) |
| `docs/ARCHITECTURE.md` (optional) | Extend the frontend tree (`:71–78`) to mention `shared/directives/` and `shared/pages/` |

The AC-6 entry must contain, at minimum:
1. `permissionGuard` usage with `data: { permission: 'resource:action' }`.
2. `*appHasPermission` usage, including that each standalone component imports the directive itself.
3. **"UX only — not a security boundary"** in plain language (AC-6, mitigates R-1).
4. The fail-open behaviour on missing `data.permission`, so it is discoverable rather than silent (mitigates R-2).
5. The `permissionGuard`-must-follow-`authGuard` ordering rule (§1.4).
6. `requiredPermission` camelCase, if the 403 field is mentioned at all.

`docs/ARCHITECTURE.md` Non-negotiable #9 tension is discussed in §5.3.

### 1.10 Tests

**Existing specs that MUST be modified (compile-breaking):**

| File | Literal | Line |
|---|---|---|
| `nexus-frontend/src/app/core/auth/auth.store.spec.ts` | `const TEST_SESSION: AuthSession` | `:16–28` (user object `:21–27`) |
| `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts` | `const TEST_SESSION: AuthSession` | `:13–25` (user object `:18–24`) |
| `nexus-frontend/src/app/features/auth/auth.service.spec.ts` | `const ME_RESPONSE` (untyped) | `:223–229` |
| `nexus-frontend/src/app/features/auth/auth.service.spec.ts` | `const EXPECTED_SESSION … satisfies AuthSession` | `:232–244` |

**New specs:**

| File | Purpose |
|---|---|
| `nexus-frontend/src/app/core/guards/permission.guard.spec.ts` | Unit: allow / deny→UrlTree / fail-open on missing `data.permission` / empty & `undefined` permissions. Plus a second `describe` block for the **router-integration test** (resolved decision 4): `provideRouter([{ path: 'test-gated', canActivate: [permissionGuard], data: { permission: 'x:y' }, component: … }, { path: 'access-denied', component: … }])` + `RouterTestingHarness`, asserting the resolved URL. Keeping it in the same file avoids inventing a new file-suffix convention. |
| `nexus-frontend/src/app/shared/directives/has-permission.directive.spec.ts` | AC-3 present/absent in DOM; AC-4 undefined/empty → hidden, no thrown error and no `console.error`. Needs a tiny inline host component — **first structural-directive harness in the repo (R-6)**. |
| `nexus-frontend/src/app/shared/pages/access-denied/access-denied.component.spec.ts` | AC-5 structural assertions: exactly one `<h1>` with text "Access denied", `<main>` landmark present, `routerLink="/dashboard"` anchor, `mailto:` anchor with descriptive text (not "click here"). |
| `nexus-frontend/e2e/access-denied.spec.ts` | **Recommended, cheap.** axe scan mirroring `e2e/auth/registration.spec.ts:62–73` (`AxeBuilder({page}).withTags(['wcag2a','wcag2aa'])`, filter `impact === 'critical'`). `/access-denied` is unguarded and makes no backend call, so this needs **no backend and no login** — the cheapest available AC-5 evidence. |

Test-infrastructure facts verified:
- `vitest.config.ts` sets only `testTimeout: 20000` — **no coverage thresholds**. `angular.json`'s `test` target (`:85–87`) is bare `@angular/build:unit-test` with no coverage config. `npm run test:ci` passes `--coverage` but there is **no threshold gate to trip**, so new files cannot fail a coverage gate. The gate that *will* fail is "Vitest + Playwright: all green" — the 4 fixture updates in §1.10 are therefore build-blocking.
- Existing spec conventions to mirror: explicit `vitest` imports (`describe, it, expect, beforeEach, vi`), `TestBed.configureTestingModule`, `By.css('[data-testid=…]')` selection (`error-state.spec.ts:1–50`), `TestBed.runInInjectionContext` for functional guards (`auth.guard.spec.ts:35–37`), and a fake `Router` whose `createUrlTree` returns `{ _commands }` for assertion (`auth.guard.spec.ts:47–53`).
- `eslint.config.js:38–43` restricts `no-console: "off"` to `logger.service.ts` and `main.ts` only. AC-4's "must not log a console error" is therefore already structurally supported: any diagnostic must go through `LoggerService`, never `console.*`.

### 1.11 Files verified as NOT affected

- **All backend files.** `MeResponse.java` already returns `permissions` (`:10`); `GlobalExceptionHandler` already returns the 403 shape (`:146–163`). Zero backend diff.
- `nexus-frontend/src/app/app.config.ts` — no new provider. `permissionGuard` is a function (no DI registration); `AuthStore`/`AuthService` use `@Service()` self-registration; the directive is imported per-component.
- `nexus-frontend/src/app/core/http/auth.interceptor.ts` — unchanged (only its spec's fixture changes).
- `nexus-frontend/src/app/shared/ui/**` — unchanged under recommendation (a) in §1.6.
- `nexus-frontend/src/app/shared/types/view-state.ts` — `ViewState<T>` references `AppError` by type only; an added optional field is transparent.
- `nexus-frontend/angular.json` — no new global style entry needed. Note the `anyComponentStyle` 4 kB warning budget (`:49–50`) — keep any new `.scss` small.
- `nexus-frontend/eslint.config.js` — no change (§1.5).
- `nexus-frontend/e2e/auth/{session-refresh,logout,registration}.spec.ts` — verified: these mock `/api/v1/users/me` only with **error** bodies (`session-refresh.spec.ts:109–115`), never a success payload. No E2E fixture needs a `permissions` field.
- `nexus-frontend/src/app/features/**` — no feature component gains `*appHasPermission` in this story (infrastructure-only decision).

---

## 2. Database changes

**None. Zero.**

- No Flyway migration. `nexus-backend/src/main/resources/db/migration` is untouched; the append-only `V<N>__*.sql` rule (ADR 0003) is not engaged.
- No JPA entity, repository, column, index, or constraint change. `ddl-auto=validate` cannot fail as a result of this story.
- No non-additive change ⇒ **no expand/contract plan required**.
- No data migration ⇒ **N/A**.
- The `permissions` list consumed by the frontend is already derived server-side from the existing RBAC tables shipped by US-010/US-011 under ADR 0013. This story reads an already-populated response field.

---

## 3. API changes

**None. Zero.** No new endpoint, no changed endpoint, no request/response shape change, no status-code change, no versioning event. This story is a pure **consumer** of two already-shipped contracts.

### 3.1 Consumed: `GET /api/v1/users/me` → 200

Source of truth: `nexus-backend/.../identity/interfaces/rest/dto/MeResponse.java:5–17`.

| Field | Type | Notes |
|---|---|---|
| `userId` | string | |
| `emailVerified` | boolean | |
| `tenantId` | string | |
| `roles` | `string[]` | `List.copyOf` → never null |
| **`permissions`** | **`string[]`** | **already shipped**; `List.copyOf` → never null; `resource:action` lowercase-colon convention (EPIC-002 §BA) |
| `tokenVersion` | number | |

Called by the frontend as `GET ${APP_CONFIG.apiBaseUrl}/v1/users/me` with an explicit `Authorization: <tokenType> <token>` header (`auth.service.ts:191–195`).

### 3.2 Consumed: 403 problem document

RFC 7807 body, produced by the `problem()` helper (`GlobalExceptionHandler.java:229–234` → always sets `code` and `traceId`).

| Trigger | `code` | `detail` | `requiredPermission` |
|---|---|---|---|
| `InsufficientPermissionException` (`@RequiresPermission`), `:146–163` | `RBAC_001` | `"You do not have permission to perform this action"` | **present** (camelCase) |
| Spring Security `AccessDeniedException`, `:165–170` | `ACCESS_DENIED` | `"You do not have access to this resource."` | **absent** |

`reason`, `userId`, `tenantId` are attached to the **log record only**, not the response body. The frontend `ProblemDocument` type must not model them.

### 3.3 Breaking-change assessment for APIs

None. Additive-only consumption. Older frontend bundles already ignore the `permissions` key; the backend is unchanged, so no client anywhere is affected.

---

## 4. Backward compatibility & breaking changes

### 4.1 Summary

| Change | Breaking? | Surface | Detected by |
|---|---|---|---|
| `AuthUser.permissions` — **required** field added | **Yes, compile-time** | 3 spec files, 4 object literals | `tsc` via `npm run test:ci` / `npm run build` |
| `MeApiResponse.permissions` — required field added | Indirect (see 4.3) | 1 spec file, 1 literal + 1 deep-equality assertion | Vitest assertion + `satisfies` check |
| `AppError.requiredPermission?` — **optional** field added | **No** | none | — |
| `AuthStore.permissions` computed added | **No** (compile) / latent (runtime) | test doubles, see 4.4 | runtime only |
| `/access-denied` route added | **No** | previously unmatched path | — |
| New directive / new page / new guard | **No** — additive, unreferenced by existing code | — | — |

### 4.2 `AuthUser.permissions` — exact fixture fan-out (grep-verified)

Searched the whole frontend for `emailVerified` (the discriminating field of every `AuthUser`-shaped literal). Exactly **4 literals in 3 spec files**, all of which break:

1. `core/auth/auth.store.spec.ts:16–28` — `const TEST_SESSION: AuthSession = { … user: { … } }` → **explicit annotation**, missing property is a hard `tsc` error.
2. `core/http/auth.interceptor.spec.ts:13–25` — `const TEST_SESSION: AuthSession = { … }` → same, hard error.
3. `features/auth/auth.service.spec.ts:223–229` — `const ME_RESPONSE = { … }` → **untyped**, so no direct compile error, but see 4.3.
4. `features/auth/auth.service.spec.ts:232–244` — `const EXPECTED_SESSION = { … } satisfies AuthSession` → **`satisfies`** check fails without `permissions`.

Fix cost: 4 single-line insertions (`permissions: ['users:read']` or `[]`). No logic changes.

**Alternative considered and rejected:** declaring `permissions?: readonly string[]` (optional) would eliminate all four edits. Rejected because (a) it contradicts resolved decision 3's "mirrors `roles`'s existing convention" (`roles` is non-optional), (b) it makes AC-4's "no permissions" state permanently representable at the type level, which weakens every downstream consumer, and (c) the saving is four lines. Required field + fixture updates is correct.

### 4.3 `MeApiResponse` / `buildSession` deep-equality trap

`auth.service.spec.ts:285` and `:328` both assert `expect(result).toEqual(EXPECTED_SESSION)` and `expect(mockAuthStore.setSession).toHaveBeenCalledWith(EXPECTED_SESSION)`. `ME_RESPONSE` is the flushed HTTP body; `EXPECTED_SESSION` is the expected `buildSession` output. If only one of the two gains `permissions`, the failure mode depends on the defensive default:

- `ME_RESPONSE` updated, `EXPECTED_SESSION` not → `satisfies AuthSession` fails first (compile).
- `EXPECTED_SESSION` updated, `ME_RESPONSE` not → with `me.permissions ?? []`, actual is `[]` vs expected `['users:read']` → **runtime assertion failure that looks unrelated to the change**.

The task breakdown must specify both fixtures **and the exact expected value** in one task so this is not discovered as a mystery red test.

### 4.4 `AuthStore` test doubles — latent, not compile-time

Two specs replace `AuthStore` with a plain object via `{ provide: AuthStore, useValue: mockAuthStore }`:

- `features/auth/auth.service.spec.ts:207–214` + `:247–254` — 6 mocked members, none is `permissions`.
- `core/guards/auth.guard.spec.ts:24` + `:40` — `{ isAuthenticated: vi.fn(…) }` only.

`useValue` is not structurally type-checked against the token's class, so **neither breaks**. But this means a missing `permissions` on any *future* `AuthStore` mock fails at **runtime** (`authStore.permissions is not a function`) and only in specs that exercise the new code path. `permission.guard.spec.ts`'s own mock must include it.

### 4.5 Runtime / wire compatibility

- **Old frontend ↔ current backend:** already fine — the extra `permissions` JSON key is ignored.
- **New frontend ↔ hypothetical older backend:** `me.permissions === undefined` → the `?? []` default in `buildSession` (§1.3) keeps AC-4 satisfied. This is why the default is a requirement, not a nicety.
- **No public component API changes, no route path changes, no HTTP contract changes ⇒ zero user-visible backward-compatibility risk.** The only observable behaviour delta for an existing user is that `/access-denied` becomes a valid URL.

---

## 5. Cross-cutting concerns & ripple effects

### 5.1 Duplicated `AuthSession` fixture — the real ripple

The same `AuthSession` literal is copy-pasted verbatim in three spec files (§4.2) with **no shared test-fixture module anywhere in the frontend**. This story is the third time the shape has been touched and the first time it forces a multi-file edit. Recommend introducing a single fixture helper (e.g. `nexus-frontend/src/app/shared/testing/auth.fixtures.ts` exporting `createAuthUser(overrides?)` / `createAuthSession(overrides?)` and a `createAuthStoreMock()`), so the **next** `AuthUser` field change is a one-file edit. This is a small, high-leverage addition; if the design doc declines it, the decline should be explicit, because the fixture count only grows.

### 5.2 Conventions this story establishes (all will be copied)

Every item below has **no prior art** in the repo, so whatever US-013 ships becomes the de facto standard for Epic 3 onward. Each needs an explicit statement in `03-design.md`:

1. First `@Directive` of any kind.
2. First **structural** directive + its Vitest harness pattern (requirements R-6).
3. First `shared/directives/` folder and its file-naming convention.
4. First `shared/pages/` folder and its file-naming convention.
5. First `data: {}` route-metadata usage in `app.routes.ts`.
6. First `app`-prefixed selector (everything shared is `nx`-prefixed today).
7. First guard that reads `ActivatedRouteSnapshot.data`, and the first guard router-integration test.
8. First multi-guard composition ordering rule (`authGuard` then `permissionGuard`).

### 5.3 Architectural tension with ARCHITECTURE.md Non-negotiable #9 — clarification needed

`docs/ARCHITECTURE.md:120` states: *"No `any` in TypeScript; modern control flow (`@if`/`@for`), not `*ngIf`/`*ngFor`. (ESLint-enforced)"*.

`*appHasPermission` is structural-directive microsyntax. It is **not** `*ngIf`/`*ngFor`, is **not** blocked by any ESLint rule in `eslint.config.js`, and custom structural directives remain fully supported in Angular 22. But a reviewer applying #9 literally will read `*`-syntax as prohibited, and AC-3 mandates exactly that selector.

Resolution options, cheapest first:
- **(a) Recommended:** one clarifying clause in the AC-6 developer-guide entry plus a parenthetical in `ARCHITECTURE.md:120` ("built-in control flow only; custom structural directives are permitted"). Cost: two sentences.
- (b) A short ADR if the architect wants the rationale for choosing a directive over a `@if (canDo('x'))` signal-helper recorded formally.

Do **not** ship the directive without one of these; otherwise R-1's process-only mitigation is joined by an unresolved standards contradiction.

### 5.4 Observability — no requirement exists; propose the minimum

Requirements §3 and §8 both record that **no frontend telemetry requirement is stated**, in contrast to the backend's `nexus.rbac.permission_denied` counter (`GlobalExceptionHandler.java:154–158`).

- `permissionGuard` denial → `logger.debug('permission_denied_client', { context: { permission, route } })` via the existing `LoggerService`, matching the structured `event`/`outcome`/`context` field convention already used by `api-error.interceptor.ts:24–36`.
- **Must** go through `LoggerService`: `no-console` is an ESLint **error** everywhere except `logger.service.ts` and `main.ts` (`eslint.config.js:38–43`). This also happens to be what makes AC-4's "no console error" mechanically enforceable.
- Do **not** log the directive suppression path — it can fire many times per render and would be pure noise.
- No new metric, dashboard, or trace needed. The backend already counts the authoritative denials.

### 5.5 Bundle / performance ripple

- The Access Denied page is lazy (`loadComponent`) → **initial bundle unaffected**; budgets `initial` 500 kB warn / 1 MB error (`angular.json:42–47`) are not at risk.
- The directive is tree-shaken into whichever feature chunk imports it; nothing imports it in this story, so **net bundle delta ≈ the new lazy chunk only**.
- `permissionGuard` performs a synchronous signal read plus one `Array.prototype.includes` over a set capped at ~20 entries (EPIC-002 JWT-size analysis) → no measurable latency. No HTTP call, no N+1 analogue, no cache touch. Frontend-only ⇒ **no query plans, no hot backend paths, no cache invalidation** in scope.

### 5.6 Cosmetic divergence to note (no action required)

`features/design-system/design-system-preview.component.html:407–427` already showcases an "access denied" `<nx-error-state>` with the message *"You don't have permission to view this workspace."* The real page's approved copy is *"You don't have permission to view this resource…"* (resolved decision 1). Harmless divergence; aligning the showcase in the same PR is a one-word edit if the reviewer wants consistency, otherwise leave it.

### 5.7 Integration impact (upstream/downstream services)

**None.** No upstream or downstream service is touched. No new HTTP call is introduced — the `permissions` field rides the existing `/users/me` fetch already performed by `login()` and `refresh()` (`auth.service.ts:103–114`, `:171–182`) and by `DashboardComponent`'s priming `httpResource` (`dashboard.component.ts:73`). No message broker, no event, no contract test to update.

---

## 6. Dependency changes

**None.** No new runtime or dev dependency; no version bump; no license review required.

Everything needed is already installed and already in use:

| Capability | Already available |
|---|---|
| `@angular/core` `Directive`, `TemplateRef`, `ViewContainerRef`, `computed`, `effect`, `input` | `@angular/core@22.0.4` |
| `CanActivateFn`, `ActivatedRouteSnapshot`, `RouterTestingHarness`, `provideRouter` | `@angular/router@22.0.4` |
| Vitest + coverage | `vitest@^4.0.8`, `@vitest/coverage-v8@^4.1.8` |
| axe a11y scan | `@axe-core/playwright@^4.10.0` (**already a devDependency**, precedent at `e2e/auth/registration.spec.ts:2, 62–73`) |

Guard against a false need: `@angular/localize` is **not** required — resolved decision defers i18n (requirements Assumption 6).

---

## 7. Security impact

Full STRIDE analysis belongs in `03b-threat-model.md`; the impact-level surface is:

- **New attack surface: effectively none.** No new endpoint, no new HTTP call, no new stored data, no new authn/authz decision point on the server. The guard and directive are client-side UX; the authoritative check remains `@RequiresPermission` (US-011).
- **AuthN/AuthZ changes: none.** `authGuard` behaviour is untouched. `permissionGuard` never grants access to data — the API still 403s regardless of what the client rendered.
- **New client-side data:** `permissions[]` now lives in the in-memory `AuthStore` session alongside `roles[]`. Same exposure class as existing data, same lifetime, not persisted to `localStorage`/`sessionStorage` (`auth.store.ts:15`, in-memory `signal` only). No new PII.
- **Information disclosure to watch:** `AppError.requiredPermission` gives components a machine-readable permission name. EPIC-002 §UX forbids surfacing it to end users and **nothing enforces that**. Flag as a security-review checklist item, not a blocker.
- **The R-1 risk is unchanged and unmitigated by anything mechanical.** The backend has ArchUnit; the frontend has documentation only. §5.3's clarifying note is the strongest cheap mitigation available; an ESLint/template-lint rule forbidding `permissionGuard`-without-`authGuard` is technically possible but disproportionate for 3 points — record as a follow-up if Security wants it.
- **Fail-open on missing `data.permission`** is an accepted, settled decision. Correct given the guard is not a security boundary; the failure mode is silent, and the AC-6 doc entry is the mitigation.

---

## 8. Effort / complexity signal (input to `04-tasks.md`)

| Area | Blast radius | Files | Complexity | Notes |
|---|---|---|---|---|
| Shared types (`auth.ts`, `app-error.ts`) | Small | 2 mod | Trivial | 2 field additions; triggers §4.2 fan-out |
| Existing spec fixtures | Small | 3 mod (4 literals) | Trivial | Mechanical; must land in the same commit as the type change or CI is red |
| `AuthStore` computed | Small | 1 mod | Trivial | Copy `currentUser`'s shape |
| `AuthService` (`MeApiResponse` + `buildSession`) | Small | 1 mod | Trivial | Remember `?? []` |
| `permissionGuard` + spec | Medium | 2 new | Low–Medium | Bracket access; fail-open branch; guard-ordering doc; router-integration test is the novel part |
| `HasPermissionDirective` + spec | Medium | 2–3 new | **Medium–High** | **Highest-uncertainty item.** First `@Directive`; signal `input()` + `ViewContainerRef` has no prior art; test harness must be invented |
| `AccessDeniedComponent` + spec (+ scss) | Medium | 2–3 new | Low–Medium | Straightforward, but AC-5 needs the `<h1>`/`<main>` decision and focus management is an open gap |
| `app.routes.ts` route registration | Small | 1 mod | Trivial | **Mandatory** — no wildcard route exists |
| `api-error.interceptor.ts` | Small | 1 mod | Trivial | 2 lines if the log level is left alone |
| `docs/DEVELOPMENT_GUIDE.md` (+ optional `ARCHITECTURE.md`) | Small | 1–2 mod | Low | 6 required content points |
| Optional: shared test fixtures | Medium | 1 new, 3 mod | Low | Pays for itself on the next `AuthUser` change |
| Optional: `e2e/access-denied.spec.ts` | Small | 1 new | Trivial | Backend-free axe scan; cheapest AC-5 evidence |
| Backend | None | 0 | — | Verified: zero diff |
| Database | None | 0 | — | No migration |

**Overall: MEDIUM.** File count is modest (≈8 new, ≈8 modified) and every individual change is small, but the story establishes **eight new conventions** (§5.2) and contains one genuinely novel implementation (the signal-driven structural directive). Complexity is concentrated in *decisions* — naming, directive render mechanism, heading ownership, guard composition — not in lines of code. The 3-point estimate is defensible **only if `03-design.md` resolves those decisions precisely**; if the engineer has to make them, expect rework.

---

## 9. Open items the design doc (Phase 3) must close

1. Guard export naming: `permissionGuard` vs `PermissionGuard`; the AC-6 doc must match (§1.4).
2. Directive render mechanism: `effect()`-driven `ViewContainerRef` create/clear, with the exact signal-input declaration (§1.5) — the single highest-risk detail.
3. File-naming conventions for `shared/directives/` and `shared/pages/` (§1.5, §1.6).
4. `<h1>` ownership on the Access Denied page: option (a) page-owned vs (b) `NxErrorState.headingLevel` (§1.6). Recommendation: (a).
5. Focus management on route entry into `/access-denied` (requirements §3 gap).
6. Guard composition rule: `permissionGuard` must follow `authGuard` or sit under an `authGuard`-protected parent (§1.4) — this is the actionable half of requirements R-4.
7. ARCHITECTURE.md #9 clarification (§5.3).
8. Whether to introduce shared auth test fixtures now (§5.1) — decide explicitly either way.
9. Whether `03-design.md` adopts the proposed one-line guard-denial `logger.debug` (§5.4).
10. Whether the optional `e2e/access-denied.spec.ts` axe scan is in scope (recommended: yes, it is nearly free and is the only AC-5 evidence that runs in CI).

No caching is involved (frontend-only, no Redis). A feature flag is unnecessary because the story ships inert infrastructure that no existing route or component references — the first real behaviour change lands in Epic 3.

---

## Summary

### Modules affected

**Modified (8):**
- `nexus-frontend/src/app/shared/types/auth.ts` — `AuthUser.permissions: readonly string[]` (after `:37`)
- `nexus-frontend/src/app/shared/types/app-error.ts` — `AppError.requiredPermission?: string` (after `:64`)
- `nexus-frontend/src/app/core/auth/auth.store.ts` — new `permissions` computed
- `nexus-frontend/src/app/features/auth/auth.service.ts` — `MeApiResponse` (`:21–27`) + `buildSession` (`:206–220`), with `?? []`
- `nexus-frontend/src/app/core/http/api-error.interceptor.ts` — `ProblemDocument` (`:93–98`) + `toAppError` (`:66–74`)
- `nexus-frontend/src/app/app.routes.ts` — register `/access-denied`
- `docs/DEVELOPMENT_GUIDE.md` — new subsection under `## Frontend` (`:55`)
- `docs/ARCHITECTURE.md` (optional) — frontend tree + Non-negotiable #9 clarification

**Created (8–10):** `core/guards/permission.guard.ts` + `.spec.ts`; `shared/directives/has-permission.directive.ts` + `.spec.ts` (+ optional `index.ts`) — new folder; `shared/pages/access-denied/access-denied.component.ts` + `.spec.ts` (+ optional `.scss`) — new folder; optional `e2e/access-denied.spec.ts`; optional `shared/testing/auth.fixtures.ts`.

**Fixture-only updates (3 files, 4 literals):** `core/auth/auth.store.spec.ts:16–28`; `core/http/auth.interceptor.spec.ts:13–25`; `features/auth/auth.service.spec.ts:223–229` and `:232–244`.

**Verified zero diff:** all backend files, `app.config.ts`, `auth.interceptor.ts`, `shared/ui/**`, `view-state.ts`, `eslint.config.js`, `angular.json`, all existing e2e specs.

### DB changes

**None.** Frontend-only. No Flyway migration, no entity/column/index/constraint change, `ddl-auto=validate` unaffected. `MeResponse.permissions` already ships from existing RBAC tables (ADR 0013).

### Breaking changes found

- **One real break:** required `AuthUser.permissions` fails compilation in exactly 3 spec files / 4 object literals — fix is 4 one-line insertions.
- **`AppError.requiredPermission?` is non-breaking** — no `AppError`-typed object literal exists anywhere in the frontend.
- **`AuthStore.permissions` is non-breaking at compile time but latent at runtime** — two type-unchecked `useValue` test doubles would fail only if a future spec exercises the new path without updating the mock.
- No API, route-path, or user-visible behaviour break. No backend break.

### Top 3 risks (implementation-impact lens)

1. **Signal-based structural directive with zero prior art (High).** First `@Directive` in the repo; combining `input()` with `ViewContainerRef` create/clear, plus inventing the test harness, is the only genuinely novel code and the likeliest source of rework.
2. **`/access-denied` route registration is mandatory and easy to skip (Medium–High).** No wildcard route exists; a guard whose `createUrlTree(['/access-denied'])` resolves to nothing is a real risk if the route registration is treated as optional. Compounding this: `NxErrorState` renders `title` as a `<p>`, so naive reuse silently fails AC-5's heading hierarchy.
3. **`AuthUser` fixture fan-out plus latent mock coupling (Medium).** The `AuthSession` literal is copy-pasted across 3 spec files with no shared fixture module, and `AuthStore` mocks are type-unchecked.

Runner-up worth surfacing at Gate 2: **`permissionGuard` used without `authGuard` misroutes cold-start users to `/access-denied` instead of `/auth/login`**. Angular short-circuits `canActivate` arrays, so `[authGuard, permissionGuard]` is safe — but the ordering requirement must be documented, not left implicit.
