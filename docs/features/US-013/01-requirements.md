# Requirement Analysis Document — US-013: Implement Angular Permission Guard and Directive

**Epic:** EPIC-002 (RBAC Foundation) | **Story points:** 3 | **Priority:** P1
**Sources reviewed:** `docs/story/2-rbac/US-013.md`, `docs/story/2-rbac/EPIC-002.md` (full file, including UX section and US-010/011/012 dependency context, Open Decisions), plus direct inspection of `nexus-frontend/src/app/shared/types/auth.ts`, `nexus-frontend/src/app/features/auth/auth.service.ts`, `nexus-frontend/src/app/core/auth/auth.store.ts`, `nexus-frontend/src/app/core/guards/auth.guard.ts`, `nexus-frontend/src/app/shared/ui/error-state/error-state.ts`, `nexus-frontend/src/app/shared/types/app-error.ts`, `nexus-frontend/src/app/core/http/api-error.interceptor.ts`, `nexus-frontend/src/app/app.routes.ts`, `nexus-frontend/e2e/auth/registration.spec.ts`, `docs/DEVELOPMENT_GUIDE.md`, `nexus-backend/.../identity/interfaces/rest/dto/MeResponse.java`, `nexus-backend/.../common/web/GlobalExceptionHandler.java`.

---

## 1. Context

EPIC-002 (RBAC Foundation) delivers server-side permission enforcement (`@RequiresPermission`, shipped in US-011) and populates the JWT/`GET /v1/users/me` with `roles[]` and `permissions[]` (US-010, shipped). US-013 is the frontend counterpart: it gives every future Angular feature module a reusable, standard way to (a) block navigation to a route the current user lacks permission for, redirecting to an Access Denied page instead of the login page, and (b) hide individual UI elements the user is not entitled to act on. The story is explicit that this is **UX polish, not a security boundary** — the server-side check remains the only real enforcement. No backend work is required; the backend contract (`permissions[]` on `/users/me`, the `RBAC_001`/403 shape) already shipped under US-010/US-011.

**In scope (per story + settled decisions):**
- `PermissionGuard` functional route guard (`CanActivateFn`) checking a `permissions` signal against `data.permission`.
- `HasPermissionDirective` (`*appHasPermission`), the first structural directive in the codebase.
- The prerequisite frontend plumbing to make a `permissions` signal exist at all: `AuthUser`/`MeApiResponse` type additions and an `AuthStore` computed signal (see Dependency Status below).
- A new `AccessDeniedComponent` page (`shared/pages/access-denied/`), reusing `NxErrorState`.
- Developer guide documentation (AC-6), added to `docs/DEVELOPMENT_GUIDE.md`'s existing `## Frontend` section.
- Shipped as **infrastructure only** — no existing route is gated by `PermissionGuard` in this story (settled decision; there is currently no route in `app.routes.ts` that needs anything beyond plain authentication).

**Out of scope (per story's own "Out of Scope" list):**
- Role management UI (Epic 3).
- Permission-based field hiding within a component (future, per-feature).
- (Implicitly, per EPIC-002 scope boundary) any backend change, any new JWT-decoding capability, any new HTTP call beyond the existing `/users/me` fetch.

**Dependency status (verified against source, not assumed):**

| Dependency | Story's claim | Verified status |
|---|---|---|
| US-010 — `permissions[]` on JWT / `/users/me` | "Blocked by" | **Backend: done.** `MeResponse.java` already has a `permissions: List<String>` field. **Frontend: not done** — `AuthUser` (`shared/types/auth.ts`) and the local `MeApiResponse` interface in `auth.service.ts` have no `permissions` field, and `AuthStore` has no `permissions`/`roles` computed signal. This is **prerequisite groundwork that US-013 itself must build** (wiring an already-available backend field through to a signal), not a blocking dependency on someone else's unfinished work. Framing it as "blocked by US-010" in the story is only half-true today; the remaining half is this story's job. |
| US-011 — 403 response contract | "Blocked by" | **Done**, but with a naming correction — see Correction #1 below. |
| `authGuard` pattern to mirror | Technical Notes | Confirmed present at `core/guards/auth.guard.ts`; `PermissionGuard` can structurally mirror it (functional guard, `inject()`, returns `true`/`UrlTree`). |
| `NxErrorState` "Access denied" example | Technical Notes | Confirmed — `shared/ui/error-state/error-state.ts` ships a complete, documented `title="Access denied"` usage example with a "Contact your administrator"-style slot pattern already illustrated. |
| `@axe-core/playwright` precedent | Technical Notes (implied) | Confirmed — already a devDependency and used in `e2e/auth/registration.spec.ts` for a backend-independent WCAG 2A/2AA scan asserting zero *critical* violations (note: that precedent's assertion threshold is "critical," not "zero violations" — relevant to how AC-5's axe requirement should be worded; see Gaps). |

### Corrections carried forward into design (must not be re-litigated at Gate 2)

**Correction #1 — `required_permission` vs `requiredPermission`.** EPIC-002's `[UX]` section (line 81) and US-013's own Technical Notes both describe the 403 body's field as `required_permission` (snake_case). Direct inspection of the shipped backend (`GlobalExceptionHandler.handleInsufficientPermission`) shows the actual, live field name is **`requiredPermission`** (camelCase) — set via `problem.setProperty("requiredPermission", ...)`. **The story draft is wrong; the shipped contract is camelCase.** Any design work for the interceptor's 403 handling, and any documentation written for AC-6, must use `requiredPermission`, not `required_permission`.

**Correction #2 (clarifying, not contradicting) — this is groundwork, not a blocker.** The story's Dependencies table says "Blocked by: US-010." Read literally that implies US-013 cannot start. In fact only US-010's *backend* half is complete; the *frontend* half (types + store signal) was never separately ticketed and has no owner other than US-013. This should be reflected in the design/task breakdown as explicit in-scope work items, not treated as an external blocker to wait on.

---

## 2. Functional Requirements

Numbered and mapped to source ACs where one exists. Items with no AC number are [INFERENCE] — necessary groundwork implied by the ACs and Technical Notes but not themselves stated as an AC.

1. **[AC-1]** A route configured with `canActivate: [PermissionGuard]` and `data: { permission: '<permission-string>' }` MUST allow activation if the current user's permissions include `<permission-string>`, and MUST redirect to the Access Denied route if it does not.
2. **[AC-2]** When `PermissionGuard` denies activation, it MUST redirect to the Access Denied page, and MUST NOT redirect to the login page, for an authenticated user who simply lacks the permission.
3. **[AC-3]** `*appHasPermission="'<permission-string>'"` applied to an element MUST result in that element being absent from the rendered DOM when the current user lacks `<permission-string>`, and present when the user holds it.
4. **[AC-4]** When the current-user signal has no `permissions` (undefined/absent), `*appHasPermission` MUST treat this as "no permissions" (element hidden) and MUST NOT throw or log a console error.
5. **[AC-5]** The Access Denied page MUST meet WCAG 2.1 AA: correct heading hierarchy, full keyboard operability, a "Contact your administrator" link with descriptive (non-"click here") link text, and contrast ≥ 4.5:1.
6. **[AC-6]** The developer guide MUST document usage of both `PermissionGuard` and `*appHasPermission`, and MUST state explicitly that these are UX-only and not a security boundary.
7. **[INFERENCE, groundwork for AC-1/3/4]** `AuthUser` (`shared/types/auth.ts`) gains a `permissions` field mirroring the existing `roles` field's shape and immutability conventions.
8. **[INFERENCE, groundwork for AC-1/3/4]** The local `MeApiResponse` interface in `auth.service.ts` gains a `permissions: string[]` field, and `buildSession()` maps it into the constructed `AuthUser`.
9. **[INFERENCE, groundwork for AC-1/3/4]** `AuthStore` exposes a `permissions` computed signal, consistent with the existing `currentUser`/`isAuthenticated`/`accessToken` computed-signal pattern — no RxJS subscription, matching Technical Notes' explicit "no `currentUser$` observable exists" instruction.
10. **[INFERENCE, from Technical Notes only — not backed by any AC or QA test scenario]** `api-error.interceptor.ts` gains a distinguishable 403 handling path so that `AppError` can surface `RBAC_001`/`requiredPermission` to any component that wants to display it, alongside the existing generic pass-through. **Flagged for Gate 1 attention:** this item appears only in Technical Notes; none of the 6 ACs or 6 QA test scenarios reference it. See Open Question 6.

---

## 3. Non-Functional Requirements

The story and epic are almost entirely silent on frontend-specific NFRs; the epic's quantified NFRs (200 RPS, p95 < 300ms, JWT < 4KB, cache < 5ms) are backend-only and do not transfer to this story.

- **Performance:** Not specified. [GAP] No stated budget for guard-evaluation latency or directive re-render cost. [INFERENCE] Given the guard only reads a synchronous signal (no HTTP call), latency should be negligible, but this is not a stated requirement to verify against.
- **Scalability:** N/A — client-side, single-user-session logic.
- **Availability:** N/A at the story level; inherits the frontend app's overall availability.
- **Security:** Explicitly and repeatedly stated as **not** a security boundary (story Background, EPIC-002 §BA Compliance requirements, §UX). The only security-relevant requirement is negative: the guard/directive must never be relied upon, or documented as if it were, a substitute for `@RequiresPermission`. [INFERENCE] Any interceptor/`AppError` change (FR-10) must not leak `requiredPermission` or any other RBAC detail into any UI surface visible to the end user — EPIC-002 §UX states "No technical detail... exposed to the end user — only in the API response body for developer consumption."
- **Accessibility:** Fully specified by AC-5 (WCAG 2.1 AA, heading hierarchy, keyboard-complete, descriptive link text, ≥4.5:1 contrast) and the EPIC's UX section (error message linked via `aria-describedby`). [GAP] Focus management on the SPA route transition into the Access Denied page is not addressed by either document.
- **Observability:** Not addressed anywhere in the story or epic for the frontend side. [GAP] No requirement to log/telemetry-emit a guard denial or directive suppression event (contrast with the backend's `nexus.rbac.permission_denied` counter).
- **i18n:** Not addressed. [GAP] No language/locale requirement stated for Access Denied page copy or link text.

---

## 4. Edge Cases

- Current-user signal has no `permissions` field at all (AC-4, explicitly covered) — must hide, not throw.
- Current-user signal's `permissions` is present but empty (`[]`) — same treatment as absent; implied by "treats as empty," not explicitly distinguished in any AC.
- Route's `data.permission` is unset/misconfigured — **settled decision: guard fails open** (treated as a misconfiguration, not a security decision, since the guard is UX-only). No AC or test scenario currently exercises this path; should be added at test-planning time.
- Permission string matching is presumably exact, case-sensitive string equality (per the `resource:action`, lowercase, colon-separated convention in EPIC-002 §BA) — not explicitly stated as a frontend requirement.
- User's role is revoked mid-session: per EPIC-002 §UX Edge States, the user remains on the currently-active page until the next navigation or token refresh — the guard is **not** required to be reactive while already on a gated route. This is documented design intent but not captured as a QA test scenario for US-013.
- `AuthStore.currentUser()` is `null` because the session hasn't loaded yet versus `currentUser()` populated with a genuinely empty `permissions` array — both produce the same "no permissions" signal shape to the guard/directive; no AC or test scenario distinguishes these (see Risk R-4).
- Navigating directly to the Access Denied route (typed URL, not arrived at via redirect) — no stated behavior for whether the page always renders regardless of the user's actual permissions.
- Multiple `*appHasPermission` directives on the same view — no stated requirement on re-evaluation cost; likely fine given Angular's change detection but untested by any listed scenario.
- Concurrent/partial network failure while fetching `/users/me` right after login, before the guard/directive ever run — not addressed; overlaps with the null-vs-empty ambiguity above.

---

## 5. Assumptions

Each flagged `[CONFIRM]` requires explicit stakeholder sign-off before/at Gate 2.

1. The `permissions` signal shape is a `readonly string[]`, mirroring `AuthUser.roles`'s existing type, rather than a `Set<string>`. **[CONFIRM — Architect]**
2. `PermissionGuard` performs a single-permission check (`data.permission: string`), not a multi-permission AND/OR check. **[CONFIRM — Architect/PM]**
3. The Access Denied page is reachable at a fixed route path (`/access-denied`, by analogy with the guard's `router.createUrlTree(['/access-denied'])` example) and is itself unauthenticated-safe to view directly. **[CONFIRM — Architect]**
4. `*appHasPermission` does not need an `else`-template variant for this story. **[CONFIRM — Architect]**
5. The interceptor/`AppError` change described only in Technical Notes (FR-10) is in scope for this story's Gate 1 approval, despite not being backed by any AC or QA test scenario. **[CONFIRM — PM]**
6. No i18n/localization requirement applies to the Access Denied page copy for this story (English-only). **[CONFIRM — PM]**
7. The E2E test scenarios in the story's own QA table (items 1–2) can be satisfied using a synthetic/test-only route rather than a real production route, given the settled "infrastructure only, no route gated yet" decision. **[CONFIRM — QA/PM]**

---

## 6. Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R-1 | Developers treat `PermissionGuard`/`*appHasPermission` as an actual security control rather than UX polish. Unlike the backend (which has a tracked, if still-open, ArchUnit rule forcing every controller method to carry `@RequiresPermission`), there is no equivalent structural/static enforcement proposed for the frontend. | **High** | Explicit "UX only, not a security boundary" statement in the developer guide (AC-6) and code-review checklist item. Purely process-based mitigation — weaker than the backend's (still-open) architectural check. Architect should assess whether an ESLint/template-lint rule is feasible as a stronger mitigation. |
| R-2 | Guard's "fail open" behavior on a misconfigured/missing `data.permission` (settled design decision) is, by definition, silent — a route intended to be gated that has a typo'd or omitted `data.permission` key becomes fully open with no error, warning, or test failure signaling the mistake. | **Medium–High** | Recommend a unit-test convention requiring every route using `PermissionGuard` to be paired with an explicit `data.permission` assertion test. Not currently proposed anywhere in the story. |
| R-3 | The story's own QA test scenarios 1–2 (E2E: navigate to a guarded route with/without permission) cannot be executed against the current app as it exists today — no route in `app.routes.ts` uses `data.permission`, and the settled decision is to ship no gated route in this story. | **Medium** | Needs an explicit QA/PM decision at task-planning time (Open Question 5): add a minimal test-only route, downgrade to functional/router-integration tests, or explicitly waive with a documented follow-up. |
| R-4 | The `permissions` signal cannot currently distinguish "session/user data not yet loaded" from "loaded, user genuinely has zero permissions" — both look identical to the guard/directive. A slow or failed `/users/me` fetch immediately after login could cause a flash of Access-Denied or hidden UI that is not a true permission denial. | **Medium** | Not addressed in either source document. Needs an explicit design decision on whether this is accepted as out of scope for this story. |
| R-5 | `required_permission` vs `requiredPermission` naming mismatch (Correction #1). If design/implementation follows the story's own Technical Notes literally instead of the verified shipped contract, the interceptor would read a field that does not exist, silently producing `undefined`. | **Medium** (silent failure, but low real-world consequence since EPIC-002 §UX already mandates this detail never reach the end user) | Already corrected in this document; must be explicitly carried into the design doc's field mapping and any `AppError` type extension. |
| R-6 | This is the first structural directive in the codebase — no existing test harness pattern, ESLint config coverage, or code-review precedent exists for `@Directive` classes using `ViewContainerRef`. | **Low–Medium** | Architect should explicitly document the chosen testing pattern in the design doc, since none currently exists to reuse. |

---

## 7. Open Questions — RESOLVED

All items below were open after initial analysis and have since been resolved (by the user, or by pragmatic engineering judgment where flagged) so design can proceed without further ambiguity. The four decisions already settled earlier (fail-open behavior, infrastructure-only scope, Access Denied page location at `shared/pages/access-denied/`, `docs/DEVELOPMENT_GUIDE.md` placement) remain unchanged.

1. **Access Denied page copy/CTA target — RESOLVED.** Title: "Access denied". Message: "You don't have permission to view this resource. If you believe this is a mistake, contact your administrator." Primary action: "Return to dashboard" (`routerLink="/dashboard"`). Secondary action: "Contact your administrator" → `mailto:support@yourcompany.example` (RFC 2606 reserved placeholder domain). **Rationale:** grepped the entire frontend — no support/help route, contact config, or mailto pattern exists anywhere (the only `/help` reference is inside `NxErrorState`'s own JSDoc example, not a real route). Adding new global `AppConfig`/environment infrastructure for one mailto link would touch 13+ files that construct `AppConfig` in tests, disproportionate for a 3-point story. The placeholder is clearly marked in code for PM to swap before release; it does not block AC-5 (a real, descriptive-text `<a>` element is present and keyboard-operable either way).
2. **`*appHasPermission` else-template — RESOLVED: not built now.** No AC requires it, and Angular's structural-directive syntax allows `*appHasPermission="perm; else tpl"` to be added later without a breaking change to the current API. Deferred, not dropped.
3. **`permissions` signal type — RESOLVED: `readonly string[]`.** Matches `AuthUser.roles`'s existing convention. EPIC-002's own JWT-size analysis caps realistic permission sets at ~20 entries, so `.includes()` is effectively O(1) in practice; a `Set<string>` would add conversion overhead (arrays in, sets in signals, arrays back out for template iteration) with no measurable benefit at this scale.
4. **E2E route-guard scenarios (QA table items 1–2) — RESOLVED.** Covered via a Vitest router-integration test (a synthetic test-only route configured with `permissionGuard` inside the spec, asserting navigation outcome) rather than a real Playwright E2E. A true E2E is deferred as a documented follow-up until a real feature route (Epic 3) actually uses `permissionGuard` — no fake production route is added solely to exercise this story's code.
5. **`api-error.interceptor.ts`/`AppError` 403 work — RESOLVED: in scope.** It's a small, additive change (one optional field threaded through an existing generic code path) and is explicitly called out in the story's own Technical Notes as part of this story's definition of done, even though no top-level AC separately names it. Field name: `requiredPermission` (matching the verified backend contract — see Correction #1).
6. **EPIC-002 §UX "current role" display / registration copy change — RESOLVED: out of scope for US-013.** AC-5 enumerates only heading hierarchy/keyboard/link-text/contrast — no role-display requirement. The registration-confirmation copy change belongs to the registration feature (a different component/bounded context) and appears only in EPIC-002's Edge States narrative, not in US-013's own AC or Technical Notes. **Recorded as a backlog note for PM**, not silently dropped: both items should be raised as separate follow-up tickets if still desired.

---

## 8. Gaps

- No mockup, wireframe, or approved copy exists for the Access Denied page beyond three bullet points in the EPIC's UX section.
- No frontend-specific performance budget is stated anywhere — the epic's quantified NFRs are all backend-only.
- No observability/telemetry requirement is stated for a frontend permission denial event, despite the backend having an equivalent metric.
- No i18n/localization requirement is stated for any new user-facing copy introduced by this story.
- No focus-management requirement is stated for the SPA route transition into the Access Denied page.
- No test-harness/testing-convention precedent exists in the repository for Angular structural directives — this story is the first of its kind.
- No decision or precedent exists for whether `data.permission` should someday support multiple permissions (AND/OR semantics), despite this story being described as the pattern "all future Angular feature modules" will use.
- No stated behavior for the "data not yet loaded" vs. "loaded with zero permissions" ambiguity in the `permissions` signal (see Risk R-4).
- `AuthUser.roles`'s existing doc comment describes it as "Comma-delimited RBAC roles" while its actual type is `readonly string[]` — a pre-existing minor documentation/type mismatch. Not this story's defect to fix, but worth avoiding when writing the doc comment for the new `permissions` field.

---

## 9. Stakeholder Map

| Stakeholder | Interest / need |
|---|---|
| PM | Approves Access Denied page copy, CTA target, and scope calls (Open Questions 1, 2, 5, 6, 7, 8); owns whether interceptor work (FR-10) is in scope. |
| Architect | Owns the guard/directive API shape decisions that all future feature teams will inherit (Open Questions 3, 4); the naming-contract correction (`requiredPermission`) flows through any design work. |
| Security | Confirms the guard/directive are documented and reviewed as non-security-boundary (R-1); weighs in on whether `AppError`'s new field risks information exposure beyond what EPIC-002 §UX permits. |
| QA | Owns feasibility of the story's own E2E test scenarios given no gated route exists (Open Question 5, Risk R-3); defines the first directive-testing convention (Risk R-6). |
| Frontend development teams (all future Angular feature modules) | Direct consumers of the `PermissionGuard`/`*appHasPermission` contract. |
| Accessibility/compliance reviewer | Signs off on AC-5's WCAG 2.1 AA requirements for the Access Denied page. |
| Business users / tenant end users | Experience the Access Denied page directly when they lack a permission. |
| Tenant Administrators | Indirectly referenced as the target of "Contact your administrator" (Open Question 2). |

---

## 10. Success Metrics

The story itself states no success metrics; EPIC-002's epic-level metrics are backend-only and do not map cleanly onto this frontend-only story. The following are **[INFERENCE]**, proposed for stakeholder confirmation:

- Zero new Angular feature routes ship after this story without using `PermissionGuard`/`data.permission` for any permission-gated route.
- Zero reported console errors or blank-UI incidents traceable to `*appHasPermission` when a user's `permissions` signal is empty/undefined.
- Axe accessibility scan on the Access Denied page remains at zero *critical* violations in CI on every subsequent PR that touches it.
- The developer guide's `PermissionGuard`/`*appHasPermission` entry is referenced by the first Epic 3 team that consumes it.
- **Epic-level (not this story's to move alone):** no future pen-test or security review finding treats the frontend guard/directive as if it were an enforcement boundary.
