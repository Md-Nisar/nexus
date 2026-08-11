# Coverage audit for Task US-013

**Feature:** US-013 — Implement Angular Permission Guard and Directive
**Epic:** EPIC-002 (RBAC Foundation)
**Branch:** `feature/US-013` (uncommitted working tree vs. `origin/main`)
**Auditor:** qa-engineer sub-agent (fresh context)
**Cross-referenced against:** `01-requirements.md`, `03-design.md` §12 (test plan / coverage matrix), `06-code-review.md`, `07-security-review.md` — all prior gaps those two reviews found (T-09/T-07 guide clauses, the ancestor-guard false positive, the `AuthSession.user` doc comment, the `buildSession()` defensive-default test, `Object.freeze`, SEC-1 fragment-stripping, SEC-2 `canActivateChild`) were spot-checked against the current file contents and confirmed **already remediated in code** — not re-flagged here as new findings.

**Scope note:** `password-strength-meter.component.ts`, `registration-form.component.html`, and `shared/ui/select/select.ts` are pre-existing, unrelated uncommitted edits and are excluded from this audit. Verified `git diff origin/main --stat -- nexus-backend/` is empty — **zero backend diff**, so **Step 5 (load test scenarios for endpoints seeing >10 RPS) is N/A: this diff has no backend/API surface.** No endpoint is added, changed, or gated by this story.

---

## Existing tests

- `core/guards/permission.guard.spec.ts` — allow/deny on permission match; fail-open on missing/non-string/empty-string `data.permission`; exactly-once debug log on denial with query string *and* fragment stripped (SEC-1, already fixed); no log on allow or fail-open.
- `core/guards/permission-guard-contract.spec.ts` — mechanical route-table contract (zero violations on the real table); synthetic-table cases for the ancestor-`authGuard` pattern (both `canActivate` and `canActivateChild`, SEC-2 already fixed); router-integration `describe` block (allow, deny→`/access-denied`, and the cold-start "guard alone" case proving the `authGuard`-before-`permissionGuard` composition invariant).
- `shared/directives/has-permission.directive.spec.ts` — present/absent on permission match; no-throw/no-`console.error` on empty `permissions()` (AC-4); reactive add/remove after initial render; no DOM churn when `permissions` is replaced by a value-equal array (reference-identity assertion on `nativeElement`).
- `shared/pages/access-denied/access-denied.component.spec.ts` — exactly one `<h1>` "Access denied"; `<main>` landmark; "Return to dashboard" link; "Contact your administrator" link (descriptive text, not "click here", `mailto:` href); focus moves to the heading after `whenStable()`.
- `shared/testing/auth.fixtures.ts` — not itself a spec, but the shared builder (`createAuthUser`, `createAuthSession`, `createAuthStoreStub`) all directive/guard/store specs above depend on; verified to import no test-framework module (build-breaking constraint, §12.7/16.2 of the design doc).
- `core/auth/auth.store.spec.ts` — `permissions()` empty-with-no-session, populated-after-`setSession()`, and stable-reference-when-no-session (supports the directive's churn-avoidance guarantee one layer down).
- `core/http/api-error.interceptor.spec.ts` — RBAC_001→`requiredPermission` mapped; ACCESS_DENIED→`undefined`; non-string `requiredPermission` (e.g. `12345`) rejected by the `typeof` narrowing; pre-existing 404/429/500/network-failure logging-level cases.
- `features/auth/auth.service.spec.ts` — `buildSession()` maps `/users/me`'s `permissions[]` into `AuthUser.permissions`; **defensive-default case** for a `/users/me` response that omits `permissions` entirely (older-backend scenario) → `[]` (already added, per `06-code-review.md`'s remediation).
- `e2e/access-denied.spec.ts` — zero *critical* WCAG 2A/2AA violations via `@axe-core/playwright`, no backend/login required.

## Gaps identified

- **[MED] `permission.guard.ts`'s `typeof required !== 'string'` branch was never exercised with `data.permission: null` specifically** (only missing/`undefined`, `42`, and `''` were covered) — `null` is a distinct JS value (`typeof null === 'object'`) from "key absent," and a future refactor toward `required == null` (loose equality) would silently narrow the fail-open contract without any test catching it. — added in `core/guards/permission.guard.spec.ts`.
- **[MED] No test exercised `*appHasPermission` bound to an empty string** (`*appHasPermission="''"`) — AC-3/AC-4 describe "no permissions" and "held permission" but never the case where the *required* permission itself is the empty string, which is a template-authoring mistake distinct from "user has no permissions." Verified the directive has no special-case handling (it's a plain `.includes('')` on the boolean path) but this was previously asserted only by inference, not a test. — added in `shared/directives/has-permission.directive.spec.ts`.
- **[MED] No test exercised two `*appHasPermission` instances on the same view, bound to different permission strings, reacting independently to one `AuthStore.permissions` signal change** — `03-design.md`'s own Edge Cases (§4) flagged this as "likely fine given Angular's change detection but untested by any listed scenario." Now proven directly rather than left as an inference. — added in `shared/directives/has-permission.directive.spec.ts`.
- **[LOW] No test proved Angular's signal/effect batching for two same-tick `permissions` writes (a "concurrent update" analogue for a synchronous-only client)** — reasoned through and then verified empirically: `computed()` is pull-based and `effect()` is scheduled per change-detection flush, not per signal write, so two `.set()` calls issued before a single `fixture.detectChanges()` are read exactly once, at their settled value. Proven via `nativeElement` reference-identity (the same technique the pre-existing "identical-contents" no-churn test uses) rather than a `ViewContainerRef` spy, because `ViewContainerRef` is an abstract class with no prototype methods to intercept — its real implementation is Angular's internal, non-public `R3ViewContainerRef`. **Conclusion: this is a non-issue by construction (Angular's signal scheduler coalesces same-tick writes), now backed by a test rather than left as an assumption.** — added in `shared/directives/has-permission.directive.spec.ts`.
- **[LOW] `api-error.interceptor.spec.ts` had zero coverage of the pre-existing `HTTP_ERROR` fallback path** (a 4xx/5xx body with no `code` field at all, or a non-object body) — every test added by this story exercised only the RBAC branch of `isProblemDocument`'s `code`-only validation; nothing proved the *other* branch of that same guard (the one the pre-existing `HTTP_ERROR`/`NETWORK_ERROR` fallback depends on) still degrades correctly now that `requiredPermission` narrowing shares the same type guard. This is a regression-confirmation gap, not a new behavior — closing it protects the RBAC change from ever silently breaking the older fallback. — added in `core/http/api-error.interceptor.spec.ts`.

**Explicitly checked and found to be non-gaps (no test added, per the "don't invent a fix for a non-problem" instruction):**
- **`AccessDeniedComponent`'s `afterNextRender(() => this.heading().nativeElement.focus())` resilience.** Read the component: `.focus()` on an `HTMLElement` per the DOM spec does not throw (a `tabindex="-1"` element is always focusable, so there's no "unfocusable target" edge case either); `afterNextRender` additionally only runs *after* the DOM has already been committed, so even a hypothetical throw here could not "break the whole page" — the page's visible content is already rendered by the time this callback runs, and any error would be a component-local focus-doesn't-move regression caught by Angular's own error handling, not a full-page failure. **Non-issue by construction; no test or fix needed.**
- **Authorization/role-independence of `permissionGuard`.** Read the guard: it reads `route.data['permission']` generically via bracket-index access and compares against `authStore.permissions()` with plain `.includes()` — no permission string is hardcoded anywhere in `permission.guard.ts` or `has-permission.directive.ts`. There is no role×endpoint matrix to test because there is no backend endpoint and no route in the shipped table uses the guard yet (confirmed by `permission-guard-contract.spec.ts`'s own "real route table has zero violations" test, which is vacuously green for exactly this reason). A combinatorial permission-string test matrix would exercise `Array.prototype.includes`, not this story's logic — correctly not added.
- **`AuthUser.permissions` empty vs. absent (frontend "loading" vs. "empty" state).** Already covered: `AuthStore.permissions()` normalizes both to `NO_PERMISSIONS` via `?? NO_PERMISSIONS`, and `has-permission.directive.spec.ts`'s existing "does not render... when `permissions()` is empty" test exercises this. No separate "loading" state exists in this story's scope (R-4 in `01-requirements.md` is an accepted, documented residual ambiguity, not a defect).

## Tests added

`core/guards/permission.guard.spec.ts`
- `fails open (returns true) when data.permission is explicitly null`

`shared/directives/has-permission.directive.spec.ts`
- `never renders when appHasPermission is bound to an empty string, regardless of the permissions held`
- `updates multiple directive instances independently when permissions changes once`
- `coalesces two permissions writes made before a single detectChanges() flush into one settle-consistent render`

`core/http/api-error.interceptor.spec.ts`
- `should map a 4xx response with no code field to the generic HTTP_ERROR fallback`
- `should map a non-object error body to the generic HTTP_ERROR fallback`

No production code was modified — no bug was found while writing these tests that required a fix.

## Run results

Backend: **N/A** — zero backend diff (`git diff origin/main --stat -- nexus-backend/` empty); no backend tests were touched or need to run for this story.

Frontend:
- `npm run test:ci` — **29/29 test files passing, 208/208 tests passing** (baseline before this audit: 29 files / 202 tests; +6 tests added, 0 removed, 0 modified-in-place).
- `npm run lint` — all files pass.
- `npm run build` — succeeds; one pre-existing, unrelated warning (`design-system-preview.component.scss` exceeds its SCSS budget by 4 bytes — not part of this story's diff, not introduced by this audit).

## Load scenarios

**N/A — no backend/API surface in this diff.** US-013 is frontend-only infrastructure: it adds a route guard, a structural directive, an unguarded static page, and plumbing to surface an already-shipped backend field (`permissions[]` on `GET /v1/users/me`, from US-010) through to a signal. No new endpoint is introduced or gated, no existing endpoint's call volume changes, and the guard/directive perform zero I/O (a synchronous `Array.prototype.includes` over an in-memory signal). There is nothing here to load-test.

## Flaky tests

None identified that are new to this story's diff. One pre-existing, out-of-scope pattern noted for visibility, not remediation:

- `core/http/auth.interceptor.spec.ts` (`nearExpirySession()`/`freshSession()`, lines ~159–165) computes `expiresAt` from a live `Date.now() + 60_000` / `Date.now() + 900_000` rather than a frozen clock. This is timing-dependent in principle, but the margins (60 seconds and 15 minutes) are so large relative to synchronous unit-test execution (milliseconds) that it is not a realistic flake risk in CI — flagging only because the instructions ask for any timing-dependent test to be surfaced, even ones judged low-risk. This file's only change in this diff is a fixture-literal swap (`TEST_SESSION` now built via `createAuthSession()`/`createAuthUser()` instead of an inline object) required by the `AuthUser.permissions` type change; the `Date.now()` pattern itself predates US-013 and is out of this story's scope to fix.
- No other timing-, ordering-, or external-state-dependent test was found in the audited file set. `access-denied.component.spec.ts`'s focus assertion uses `await fixture.whenStable()` (not a raw timer) and reads `document.activeElement` in an isolated per-test DOM (happy-dom via Vitest); this is deterministic, not flaky. `e2e/access-denied.spec.ts` makes no network call and asserts only *critical*-impact axe violations (the same threshold precedent used elsewhere in the suite), so it has no external-state dependency either.

---

## Files touched by this audit

- `nexus-frontend/src/app/core/guards/permission.guard.spec.ts` (+1 test)
- `nexus-frontend/src/app/shared/directives/has-permission.directive.spec.ts` (+3 tests)
- `nexus-frontend/src/app/core/http/api-error.interceptor.spec.ts` (+2 tests)
- `docs/features/US-013/08-test-audit.md` (this report)

No other file was modified.
