# Task Breakdown — US-013: Implement Angular Permission Guard and Directive

**Inputs:** `docs/features/US-013/03-design.md` (approved) · `docs/features/US-013/03b-threat-model.md` (approved, verdict PASS WITH REQUIRED FOLLOW-UPS — 6 required mitigations folded into the relevant tasks below and marked **[TM]**)

**Scope:** frontend only. No database work, no backend work — both groups are explicitly empty (zero diff, already shipped under US-009/US-010/US-011).

Each task is implemented **test-first**: write the failing spec, then the implementation, per this project's operating model (`docs/DEVELOPMENT_GUIDE.md`).

---

## Epic: US-013

```
Epic: US-013
├─ Database (migrations / schema)         — NONE (frontend-only story)
├─ Backend                                — NONE (backend already ships everything consumed)
│   ├─ Domain
│   ├─ Application
│   ├─ Infrastructure
│   └─ Interfaces (controllers)
├─ Frontend
│   ├─ Services / state                   — T-001, T-002, T-003, T-004, T-005, T-012
│   └─ Components / routes                — T-006, T-007, T-008, T-009, T-010
├─ Cross-cutting (security mitigations, feature flag, observability)
│   — Feature flag: NONE (design §10 — inert infrastructure, no flag needed)
│   — Observability: folded into T-006 (guard denial log)
│   — Security mitigations: folded into T-006, T-007, T-008, T-012, T-013 (marked [TM] below)
├─ Tests (load scenarios, e2e)            — T-011 (no load-test scenario applies; frontend-only, no new endpoint)
└─ Documentation                          — T-013, T-014
```

---

## T-001 — Add `permissions` field to `AuthUser` type

**Description:** Add `readonly permissions: readonly string[]` to the `AuthUser` interface, documented per design §4.1. While in the file, correct two pre-existing doc-comment inaccuracies this story would otherwise propagate: the header comment's "Extracted from the JWT access token" (factually wrong — populated from `/users/me`), and **[TM low]** `shared/types/auth.ts:52–54`'s `@security` comment, which the threat model found falsely implies the session may be persisted to `sessionStorage`.

**Dependencies:** none.

**Files impacted:** `nexus-frontend/src/app/shared/types/auth.ts`

**Files created:** none

**Complexity:** S

**Risks:** Making `permissions` a required (non-optional) field is a deliberate breaking change to every existing `AuthUser`-shaped literal — resolved and scoped in T-004. Do not land this task without immediately following it with T-004, or `npm run build` / `npm run test:ci` goes red.

**Testing requirements:** No new test in this task (type-only change); existing specs intentionally go red here and are fixed in T-004. Do not merge T-001 alone.

**Definition of Done:**
- `AuthUser.permissions: readonly string[]` added, documented per design §4.1's exact doc comment (including the `@security` UX-only note).
- Header comment corrected to describe the `/users/me` origin, not JWT decoding.
- The `sessionStorage` inaccuracy at `:52–54` corrected to state the session is in-memory only.
- `npm run lint` passes on the file (red build from downstream fixtures is expected and resolved by T-004).

---

## T-002 — Add `permissions` to `MeApiResponse` and `buildSession()`'s defensive default

**Description:** Add `permissions: string[]` to the local `MeApiResponse` interface in `auth.service.ts`, and map it into `buildSession()`'s constructed `AuthUser` with the wire-defensive default `me.permissions ?? []`, exactly as specified in design §4.3 (including the inline comment explaining why the `??` is intentional, not dead code).

**Dependencies:** T-001

**Files impacted:** `nexus-frontend/src/app/features/auth/auth.service.ts`

**Files created:** none

**Complexity:** S

**Risks:** If the `?? []` default is "simplified away" by a future reviewer (it looks redundant since the backend always sends the field), AC-4 (no throw on absent permissions) silently regresses against an older backend. The inline comment from design §4.3 must ship verbatim to prevent this.

**Testing requirements:** Covered by T-004 (existing `auth.service.spec.ts` fixtures updated in the same task family). No new spec file in this task.

**Definition of Done:**
- `MeApiResponse.permissions: string[]` added.
- `buildSession()`'s `user` literal includes `permissions: me.permissions ?? []` with the mandatory inline comment from design §4.3.
- `npm run lint` passes.

---

## T-003 — Create shared auth test fixtures module

**Description:** Create `shared/testing/auth.fixtures.ts` exporting `createAuthUser(overrides?)`, `createAuthSession(overrides?)`, and `createAuthStoreStub(init?)` exactly per design §4.10. This is the single source of truth for the `AuthUser`/`AuthSession` test shape going forward, and `createAuthStoreStub` is what makes the directive's reactive-update test (T-008) possible (real `WritableSignal`s, not `vi.fn()`s).

**Dependencies:** T-001 (needs `AuthUser.permissions` to exist, since the factory's return type is checked with excess-property rules against the interface)

**Files impacted:** none

**Files created:** `nexus-frontend/src/app/shared/testing/auth.fixtures.ts`

**Complexity:** S

**Risks:** **Hard constraint (design §4.10):** this file must **not** import from `vitest`. `tsconfig.app.json` type-checks all non-`.spec.ts` files under `src/**`, so a `vitest` import here breaks `npm run build`, not just tests. Verify with a clean `npm run build` after adding the file, not just `npm run test:ci`.

**Testing requirements:** No dedicated spec for a test-fixture module; it is exercised transitively by every spec that consumes it (T-004, T-006, T-007, T-008).

**Definition of Done:**
- All three exports implemented per design §4.10's exact code.
- No `vitest` (or any test-framework) import anywhere in the file.
- `npm run build` succeeds (proves the type-check constraint above).
- `npm run lint` passes.

---

## T-004 — Migrate existing spec fixtures for the `permissions` field (must land as one commit)

**Description:** Update every existing object literal that constructs an `AuthUser`/`AuthSession`/`MeApiResponse`-shaped value so the codebase compiles and existing assertions stay correct, per design §7.2–§7.3:
1. `core/auth/auth.store.spec.ts:16–28` — migrate `TEST_SESSION` to `createAuthSession(...)`/`createAuthUser(...)` (design §4.10), adding `permissions: ['users:read']`.
2. `core/http/auth.interceptor.spec.ts:13–25` — same migration.
3. `features/auth/auth.service.spec.ts:223–229` (`ME_RESPONSE`) **and** `:232–244` (`EXPECTED_SESSION … satisfies AuthSession`) — **do not migrate to the factory** (design §4.10 explicitly keeps these as a paired literal so the wire-mapping assertion stays legible). Add `permissions: ['users:read']` to **both**, with the **identical value**, in this same task.

**Dependencies:** T-002, T-003

**Files impacted:** `nexus-frontend/src/app/core/auth/auth.store.spec.ts`, `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts`, `nexus-frontend/src/app/features/auth/auth.service.spec.ts`

**Files created:** none

**Complexity:** S

**Risks:** **This is the change the design doc calls out by name as a trap (§7.3):** if `ME_RESPONSE` and `EXPECTED_SESSION` are updated with different values (or only one is updated), the failure is a confusing runtime `toEqual` mismatch that looks unrelated to this story, not a clear compile error. Update both literals to the exact same value, in this one task, and run `auth.service.spec.ts` locally before considering this task done.

**Testing requirements:** This task *is* the test fix. Run `npm run test:ci` and confirm all four previously-red specs (and everything else) pass.

**Definition of Done:**
- `npm run test:ci` is fully green.
- `npm run build` succeeds.
- `auth.store.spec.ts` and `auth.interceptor.spec.ts` use the T-003 factories; `auth.service.spec.ts`'s paired literals are updated in place with matching values.

---

## T-005 — Add `permissions` computed signal to `AuthStore`

**Description:** Add the module-level `NO_PERMISSIONS` frozen constant and the `permissions` computed signal to `AuthStore`, exactly per design §4.2. This is the single read-only projection every consumer (guard, directive) reads — it is what guarantees "no session" and "empty permissions" both surface as `[]`, never `undefined`, satisfying AC-4 by construction rather than by defensive checks scattered across consumers.

**Dependencies:** T-001

**Files impacted:** `nexus-frontend/src/app/core/auth/auth.store.ts`

**Files created:** none

**Complexity:** S

**Risks:** Design §4.2 explicitly calls out a **deliberate non-change**: do not add a symmetric `roles` computed signal in this task — it's scope creep with no AC behind it. Flag it in review if it appears.

**Testing requirements:** Unit test added to `auth.store.spec.ts` (already touched in T-004 — add the new assertions in that same file as part of this task, or as a small follow-on edit to it): `permissions()` returns the session's permissions when authenticated; returns `[]` (the frozen `NO_PERMISSIONS` instance, assert with `toBe` for reference stability) when `_session()` is `null`.

**Definition of Done:**
- `AuthStore.permissions` computed added per design §4.2, including the `@security` JSDoc.
- `auth.store.spec.ts` covers both the populated and null-session cases.
- No `roles` computed added.
- `npm run test:ci` and `npm run lint` pass.

---

## T-006 — Implement `permissionGuard` (with denial logging)

**Description:** Create `core/guards/permission.guard.ts` implementing the functional `CanActivateFn` exactly per design §4.4: bracket-access read of `route.data['permission']`, fail-open on missing/non-string/empty-string, permission check against `AuthStore.permissions()`, and — **[TM required, finding T-06]** — the denial-path `logger.debug('permission_denied_client', ...)` call **with the query string stripped from `state.url` before logging** (the threat model found the design's original `context.route: state.url` would log an unbounded, future-controlled query string; log only the path, e.g. via `new URL(state.url, 'http://localhost').pathname` or an equivalent split-on-`?`).

Write the unit spec first (`permission.guard.spec.ts`), covering: allow when permission held; deny → `UrlTree(['/access-denied'])` when permission missing; fail-open (`true`) when `data.permission` is absent, non-string, or empty string; `logger.debug` called exactly once on denial with the documented field shape, and **not** called on allow or fail-open.

**Dependencies:** T-005 (needs `AuthStore.permissions`), T-003 (test uses `createAuthStoreStub`)

**Files impacted:** none

**Files created:** `nexus-frontend/src/app/core/guards/permission.guard.ts`, `nexus-frontend/src/app/core/guards/permission.guard.spec.ts`

**Complexity:** M

**Risks:** `tsconfig.json`'s `noPropertyAccessFromIndexSignature: true` means `route.data.permission` will not compile — bracket access is mandatory (design §4.4). The value must be typed `unknown` and narrowed with `typeof`, not cast with `as string` (ESLint `no-explicit-any` doesn't cover this, but an unguarded cast defeats the fail-open safety net).

**Testing requirements:**
- Unit: harness per design §12.2 (`TestBed.runInInjectionContext`, mocked `Router.createUrlTree` returning `{ _commands }`, `createAuthStoreStub`, mocked `LoggerService`).
- All cases from the coverage matrix (design §12.1) rows tagged "AC-1", "AC-1/AC-2", "AC-1 fail-open", "AC-4 analogue (guard)", "Observability".

**Definition of Done:**
- Guard implemented per design §4.4, with the T-06 query-string-stripping amendment applied to the log call.
- All unit test cases pass.
- `npm run lint` passes (bracket access, no `any`).

---

## T-007 — Route-table contract spec (mechanical misconfiguration + composition-order check) **[TM required, finding T-03]**

**Description:** The threat model's highest-value required mitigation: replace the two documentation-only invariants — (a) a route using `permissionGuard` must always declare a non-empty string `data.permission`, and (b) `permissionGuard` must always be composed *after* `authGuard` in the same `canActivate` array (or sit under an `authGuard`-protected ancestor) — with one small, mechanical, table-driven spec that iterates `app.routes.ts`'s actual route table and asserts both invariants for every route that uses `permissionGuard`. This is deliberately **not** an ESLint rule (the threat model explicitly declined that as disproportionate and trivially defeated by aliasing); it is a Vitest spec that is vacuously green today (no route uses the guard yet, per the infrastructure-only decision) and becomes load-bearing the moment Epic 3 adds its first gated route.

Also include, in the same file, the **router-integration test** from design §12.2's second `describe` block: a synthetic in-spec route configured with `permissionGuard` + `RouterTestingHarness`, asserting the resolved URL for both the allow and deny cases — plus the **cold-start composition case**: `permissionGuard` used *alone* (no `authGuard`) on a synthetic route, with an empty/null session, resolving to `/access-denied` instead of `/auth/login` — demonstrating *why* the ordering rule in T-006's guard JSDoc and the developer guide (T-013) exists, not just asserting it.

**Dependencies:** T-006

**Files impacted:** none

**Files created:** `nexus-frontend/src/app/core/guards/permission-guard-contract.spec.ts` (or as a second `describe` block appended to `permission.guard.spec.ts` — either is acceptable per design §12.2's "avoids inventing a new file-suffix convention" guidance; prefer appending to keep all guard-behavior tests in one file)

**Complexity:** M

**Risks:** This spec's value depends entirely on it actually iterating the real `app.routes.ts` array (imported directly), not a hand-copied stand-in route table — a stand-in would silently stop protecting anything the moment the real file diverges from it.

**Testing requirements:** This task *is* a test-authoring task. No further sub-tests needed beyond what's specified above.

**Definition of Done:**
- Spec imports and iterates the real exported `routes` from `app.routes.ts`.
- Asserts, for every route (recursively, including children) whose `canActivate` includes `permissionGuard`: `data.permission` is a non-empty string, and `permissionGuard`'s index in `canActivate` is after `authGuard`'s (or `authGuard` is absent and an ancestor route is documented/asserted to carry it — acceptable to scope this to the direct-array case only if ancestor-guard detection proves disproportionate; if scoped down, say so explicitly in the spec's own comment).
- Router-integration allow/deny/cold-start-composition cases pass per design §12.2.
- Spec passes today with zero real routes matching (vacuous but present).

---

## T-008 — Implement `HasPermissionDirective`

**Description:** Create `shared/directives/has-permission.directive.ts` exactly per design §4.5 — the highest-complexity item in this story and the first `@Directive` in the codebase: `input.required<string>()` named `appHasPermission`, a private `granted` `computed()`, an `effect()` in the constructor driving `ViewContainerRef.createEmbeddedView`/`.clear()`, guarded by a plain `hasView` boolean.

Write the spec first (`has-permission.directive.spec.ts`), establishing the repo's first structural-directive test harness per design §12.3: an inline host component with a signal field, `createAuthStoreStub` with a **real `WritableSignal`** for `permissions` (not a static mock — required to prove reactivity), covering: element present when permission held; absent when not; absent (not thrown, no `console.error`) when `permissions()` is `[]`; reactive appearance/disappearance when the stub's `permissions` signal is mutated after initial render; and the "no redundant DOM churn" assertion (re-setting `permissions` to a new array with identical contents does not recreate the embedded view — assert `nativeElement` reference stability).

**Dependencies:** T-005, T-003

**Files impacted:** none

**Files created:** `nexus-frontend/src/app/shared/directives/has-permission.directive.ts`, `nexus-frontend/src/app/shared/directives/has-permission.directive.spec.ts`

**Complexity:** L

**Risks:** The single highest-uncertainty item in the story (design §8, §12.1) — no prior art in this codebase for combining a signal `input()` with `ViewContainerRef`-driven view creation. Reading `input.required()` inside the constructor body (rather than inside the `effect()`) throws; this must be caught by the spec, not discovered in a browser. Do not skip the "no churn" test — it is the only proof that the `computed()` short-circuit and `hasView` guard are both doing their job, and its absence would let a regression (e.g., recreating the view on every unrelated permission-set change) ship silently.

**Testing requirements:** All five cases listed in the description above, per design §12.1/§12.3's coverage matrix rows "AC-3", "AC-4", "Reactive update", "No redundant DOM churn".

**Definition of Done:**
- Directive implemented per design §4.5 verbatim (selector `[appHasPermission]`, `standalone: true`).
- All five spec cases pass, including the reference-stability "no churn" assertion.
- `npm run lint` passes (directive-selector rule already permits `app`-prefix attribute selectors — confirm no config change was needed, per design §4.5's note that this looks like it needs one and doesn't).
- Directive is **not** exported from `shared/ui/index.ts`.

---

## T-009 — Implement `AccessDeniedComponent` and register its route

**Description:** Create the `shared/pages/access-denied/` page exactly per design §4.6–§4.7: `access-denied.component.ts` (standalone, `OnPush`, owning its own `<main>` + visually-hidden, focus-managed `<h1>`, reusing unmodified `NxErrorState` for the visible headline/message, two plain `<a>` CTAs — `routerLink="/dashboard"` and the `mailto:` placeholder with its `TODO(PM)` comment) and `access-denied.component.scss` (visually-hidden heading utility, action layout, focus-visible outline). Then register the route in `app.routes.ts` per design §4.8 — **this registration is mandatory, not optional**: there is no wildcard route in this app, so `permissionGuard`'s redirect resolves to nothing without it.

Write the spec first (`access-denied.component.spec.ts`) per design §12.4: exactly one `<h1>` with text "Access denied"; a `<main>` landmark; the `routerLink="/dashboard"` anchor; the `mailto:` anchor with descriptive (non-"click here") text; and the focus assertion (`document.activeElement` is the `<h1>` after `fixture.detectChanges(); await fixture.whenStable();` — fall back to `TestBed.tick()` if `afterNextRender` doesn't flush in the harness, per design §12.4's note; do not switch to `ngAfterViewInit` just to make the test easier).

**Dependencies:** none (no dependency on the RBAC signal chain — this page is static and unguarded by design)

**Files impacted:** `nexus-frontend/src/app/app.routes.ts`

**Files created:** `nexus-frontend/src/app/shared/pages/access-denied/access-denied.component.ts`, `nexus-frontend/src/app/shared/pages/access-denied/access-denied.component.scss`, `nexus-frontend/src/app/shared/pages/access-denied/access-denied.component.spec.ts`

**Complexity:** M

**Risks:** `NxButton` cannot wrap an `<a>` (design §0.2 finding — its selector is the element `nx-button`, not an attribute, so `<a nx-button>` from other components' JSDoc examples does not actually work). Use plain semantic `<a>` elements, styled locally, as specified — do not attempt to reuse `NxButton` for the CTAs. Do not add the `mailto:` address as a real support contact; ship the RFC 2606 placeholder with its `TODO(PM)` marker as designed, and flag it on the PR for a release-checklist follow-up.

**Testing requirements:** All cases in design §12.4, listed above.

**Definition of Done:**
- Page renders per design §4.6–§4.7 exactly (including the `TODO(PM)` comment on the `mailto:` link).
- `/access-denied` registered in `app.routes.ts`, unguarded, lazy-loaded, with the JSDoc block from design §4.8.
- All spec cases pass, including the focus-on-entry assertion.
- No wildcard (`path: '**'`) route added — explicitly out of scope for this task.

---

## T-010 — E2E accessibility scan for the Access Denied page

**Description:** Add `e2e/access-denied.spec.ts` exactly per design §12.5, mirroring `e2e/auth/registration.spec.ts`'s existing backend-free `@axe-core/playwright` pattern: navigate to `/access-denied`, run `AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa'])`, assert zero violations with `impact === 'critical'`. This is the only CI-enforced evidence for AC-5's WCAG 2.1 AA requirement and needs no backend, no login, and no new dependency (`@axe-core/playwright` is already a devDependency).

**Dependencies:** T-009

**Files impacted:** none

**Files created:** `nexus-frontend/e2e/access-denied.spec.ts`

**Complexity:** S

**Risks:** None material — this is a direct copy of an existing, working pattern.

**Testing requirements:** This task *is* the test.

**Definition of Done:**
- `npx playwright test e2e/access-denied.spec.ts` passes with zero critical violations.
- Test requires no backend and no authentication to run.

---

## T-011 — Surface `requiredPermission` through `AppError` and the HTTP interceptor

**Description:** Add `readonly requiredPermission?: string` to `AppError` (per design §4.9's exact doc comment, including the `@security` note that it must never be rendered to end users), and thread it through `api-error.interceptor.ts`'s `ProblemDocument` interface and `toAppError()` mapping — an unconditional pass-through, no branching on `code`, since `RBAC_001` carries the field and `ACCESS_DENIED` does not, and consumers must tolerate either.

**[TM required, finding T-05 — documentation-only mitigation, not a code change]:** add a short `@remarks` note to `AppError`'s JSDoc (or to `GlobalErrorHandler`, whichever reads more naturally in context) flagging that `AppError` objects reaching an *unhandled* path hit `GlobalErrorHandler.getErrorMessage`'s `JSON.stringify` fallback, which is logged at a level enabled in production — so this field (and the rest of `AppError`) must be treated as **not safe to send to a future remote error-tracking sink** (e.g. Sentry) without an explicit serializer/scrubber, since `app.config.ts` already documents an intent to wire one to this exact handler. File this as a one-line backlog note in the PR description as well; no `GlobalErrorHandler` behavior changes in this task.

**[TM required, finding T-04 — Low]:** when copying `body.requiredPermission` into the `AppError`, guard with a `typeof` check rather than a bare pass-through, since `isProblemDocument` validates only `code` and the field is otherwise asserted, not runtime-validated.

**Dependencies:** none (independent of the guard/directive work)

**Files impacted:** `nexus-frontend/src/app/shared/types/app-error.ts`, `nexus-frontend/src/app/core/http/api-error.interceptor.ts`, `nexus-frontend/src/app/core/http/api-error.interceptor.spec.ts`

**Files created:** none

**Complexity:** S

**Risks:** Do not change the existing 403 log level while making this change (design §4.9) — it's out of scope and would require an unrelated assertion update elsewhere in the same spec file.

**Testing requirements:** Extend `api-error.interceptor.spec.ts` with two cases mirroring the existing 404 test: a `RBAC_001` body with `requiredPermission` set → `AppError.requiredPermission` equals that value; an `ACCESS_DENIED` body with no such field → `AppError.requiredPermission` is `undefined`. Add a case for a non-string `requiredPermission` value (malformed body) → the guarded copy results in `undefined`, not a passthrough of the bad value.

**Definition of Done:**
- `AppError.requiredPermission?` added with the exact doc comment from design §4.9, including the `@remarks` addition from T-05's mitigation.
- Interceptor changes are a pure additive pass-through with a `typeof` guard, no `code`-based branching, no log-level change.
- All three new spec cases pass; existing 403/404 assertions remain green.

---

## T-012 — Developer guide content (AC-6)

**Description:** Insert the developer-guide subsection into `docs/DEVELOPMENT_GUIDE.md` under `## Frontend (nexus-frontend/)`, immediately after `### Adding a feature`, using the content drafted in design §11 **verbatim**, with one addition required by the threat model:

**[TM required, finding T-02 — Medium, the single most important content addition]:** promote the directive's "never use this to hide data that is already in the browser" warning from JSDoc-only to an explicit, prominent statement in this guide section — worded so it cannot be trimmed as boilerplate in a future edit (e.g. its own subheading or a callout, not buried in a paragraph). This is the one realistic path from this story to a genuine information-disclosure bug, and the requirements doc already lists "permission-based field hiding within a component" as **future** scope — meaning a future engineer is likely to reach for this exact directive to do exactly the wrong thing unless the warning is unmissable.

**Dependencies:** T-006, T-008, T-011 (content must reflect the real, shipped names/behavior of `permissionGuard`, `HasPermissionDirective`, and `AppError.requiredPermission`)

**Files impacted:** `docs/DEVELOPMENT_GUIDE.md`

**Files created:** none

**Complexity:** M

**Risks:** If this task lands before T-006/T-008/T-011, the guide will document an aspirational API that may drift from what actually shipped. Sequence it last among the implementation tasks.

**Testing requirements:** None (documentation). Manual review: confirm every code sample in the inserted section actually compiles against the real files (copy-paste-check, don't just eyeball it).

**Definition of Done:**
- Section inserted per design §11, plus the T-02 mitigation's elevated warning.
- All six required content points from impact analysis §1.9 present: `permissionGuard` usage with `data.permission`; `*appHasPermission` usage including per-component `imports`; "UX only — not a security boundary" statement; the fail-open behavior; the `authGuard`-then-`permissionGuard` ordering rule; `requiredPermission` camelCase note.
- Code samples verified against the real, shipped files.

---

## T-013 — `docs/ARCHITECTURE.md` clarification edits

**Description:** Two small edits per design §13.2: (1) **required** — replace the Non-negotiable #9 line at `:120` with the version from design §13.2 (inserting "built-in" and appending the custom-structural-directive carve-out), so `*appHasPermission` doesn't read as violating the "no `*ngIf`/`*ngFor`" rule on a literal reading; (2) **recommended** — update the frontend tree diagram at `:71–78` to mention `shared/directives/`, `shared/pages/`, `shared/testing/` and state the new `shared/` may depend on `core/` layering rule from design §1.2.

**Dependencies:** none (can run any time; sequenced last only for review convenience alongside T-012)

**Files impacted:** `docs/ARCHITECTURE.md`

**Files created:** none

**Complexity:** S

**Risks:** None. This is confirmed by the design's own ADR-necessity assessment (§14) to be a clarification, not a deviation — no ADR required, architect sign-off on the PR is sufficient.

**Testing requirements:** None (documentation).

**Definition of Done:**
- Non-negotiable #9 edited exactly per design §13.2 (required half).
- Frontend tree diagram updated (recommended half) — acceptable to skip with a one-line reason in the PR if the reviewer prefers to defer it, since design §13.2 marks this half as recommended, not required.

---

## Sequencing summary

```
T-001 ─┬─▶ T-002 ─┬─▶ T-004 (bundled fixture fix, must be one commit)
       │          │
       ├─▶ T-003 ─┘
       │
       └─▶ T-005 ─┬─▶ T-006 ─▶ T-007
                  │
                  └─▶ T-008

T-009 (independent) ─▶ T-010

T-011 (independent)

T-006, T-008, T-011 ─▶ T-012 (guide content — sequence last)

T-013 (independent)
```

No task in this story touches the backend or the database. No feature flag is introduced (design §10). The story is safe to ship in any order that respects the arrows above, and — per design §15 — is a single, instant deploy with no migration and no backend coordination.

---

## Jira sub-tasks

The Atlassian MCP integration is not currently connected in this session (`claude mcp add atlassian ...` per `CLAUDE.md`'s optional MCP integrations list is not active here). If you'd like matching Jira sub-tasks created under US-013 for T-001–T-013, connect the Atlassian MCP and let me know — I'll create them on request rather than assuming you want them.
