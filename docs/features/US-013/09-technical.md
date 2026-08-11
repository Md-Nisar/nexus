# US-013 — Technical Documentation

**Feature:** Implement Angular permission guard and directive | **Epic:** EPIC-002 (RBAC Foundation)
**Full design record:** [`03-design.md`](03-design.md) (architecture, exact code, decision register) · [`03b-threat-model.md`](03b-threat-model.md) (STRIDE) · [`04-tasks.md`](04-tasks.md) (task breakdown) · [`06-code-review.md`](06-code-review.md) · [`07-security-review.md`](07-security-review.md) · [`08-test-audit.md`](08-test-audit.md)

This document is the durable summary for future readers — cross-linking to the full artifacts above rather than repeating their content.

## 1. Overview

US-013 gives the Nexus frontend a standard way to (a) block navigation to a route the current user lacks a permission for, redirecting to an Access Denied page instead of the login page, and (b) hide individual UI controls the user isn't entitled to act on. It is the frontend counterpart to the backend enforcement layer shipped under US-009 (schema) → US-010 (JWT/`permissions[]`) → US-011 (`@RequiresPermission`) → US-012 (assignment API).

**This story is explicitly UX polish, not a security boundary.** Every artifact it adds is confirmed, by construction, unable to grant any capability — the guard returns only to the Angular Router, and the directive's internal "granted" signal is private with no output binding. The only thing either artifact can do is control which component renders or which element is visible; the server independently 403s anything the client shouldn't be allowed to do, regardless of what the client renders.

**Scope:** frontend only. Zero backend diff, zero database migration, zero API contract change — this story is a pure consumer of contracts US-010/US-011 already shipped.

## 2. What shipped

| Artifact | File | Purpose |
|---|---|---|
| `permissionGuard` | `core/guards/permission.guard.ts` | Functional route guard; redirects to `/access-denied` if the required permission is missing; fails open on a misconfigured route. |
| Route-table contract | `core/guards/permission-guard-contract.spec.ts` | Mechanically enforces, against the real route table, that every `permissionGuard` usage declares `data.permission` and composes `authGuard` (same array or an ancestor route, `canActivate` or `canActivateChild`). |
| `HasPermissionDirective` | `shared/directives/has-permission.directive.ts` | `*appHasPermission` structural directive; shows/hides its host element reactively based on the current permission set. First `@Directive` in this codebase. |
| `AccessDeniedComponent` | `shared/pages/access-denied/access-denied.component.ts` | The guard's redirect target; public, unguarded, WCAG 2.1 AA page reusing `NxErrorState`. |
| `AuthStore.permissions` | `core/auth/auth.store.ts` | New computed signal — the single read-only projection both the guard and directive consume. Never `undefined`; empty when unauthenticated. |
| `AuthUser.permissions` / `MeApiResponse.permissions` | `shared/types/auth.ts`, `features/auth/auth.service.ts` | Wires the backend's already-shipped `permissions[]` field (on `GET /v1/users/me`) through to `AuthStore`. |
| `AppError.requiredPermission` | `shared/types/app-error.ts`, `core/http/api-error.interceptor.ts` | Surfaces the backend's `RBAC_001` 403 field for developer diagnostics only — never rendered to end users. |
| Shared test fixtures | `shared/testing/auth.fixtures.ts` | `createAuthUser`/`createAuthSession`/`createAuthStoreStub` — first shared fixture module for this shape; must not import `vitest` (type-checked by the production build). |

## 3. Key decisions and why (see `03-design.md` §0 for the full register)

- **`permissionGuard` fails open** on a missing/invalid `data.permission` — treated as a developer misconfiguration, not a security decision, since the guard isn't the enforcement boundary. The failure mode is deliberately silent; the mitigation is the mechanical route-table contract spec, not a runtime warning (a per-navigation `logger.warn` would train reviewers to ignore it).
- **`permissionGuard` must never be used alone** — always after `authGuard`, or under an `authGuard`-protected ancestor. Angular's `canActivate` arrays short-circuit sequentially, so `authGuard` restores the session before `permissionGuard` reads it; used alone on a cold start, the guard would misroute an entitled user to `/access-denied` instead of `/auth/login`.
- **The directive is reactive via `effect()` + `computed()` + a plain `hasView` boolean**, not a one-shot check — `computed()`'s value-equality short-circuit is what prevents redundant DOM churn when the permission set changes identity without changing the boolean answer.
- **No `else`-template on the directive, no `Set` for `permissions`, no multi-permission `data.permission` syntax** — all deliberate scope limits for this 3-point story; recorded as backlog items, not gaps.
- **Shipped as infrastructure only** — no existing route uses `permissionGuard`, no existing component uses the directive. The first real behavior change is the first Epic 3 route that adopts them.
- **No ADR was written** (§14 of the design doc assessed this explicitly). The one candidate — clarifying that `*appHasPermission` doesn't violate `ARCHITECTURE.md`'s "no `*ngIf`/`*ngFor`" non-negotiable — was resolved with a one-clause doc edit instead, since it's a clarification of scope, not an architectural deviation.

## 4. Threat model and security posture (summary — full detail in `03b-threat-model.md`, `07-security-review.md`)

STRIDE verdict: **PASS WITH REQUIRED FOLLOW-UPS**, all 6 required mitigations closed. Security code review verdict: **APPROVED**, 0 Medium+, 3 Low (all closed — see below). The central finding, independently re-verified at both the design and code-review stages: neither the guard's nor the directive's output is *readable* by application code, so the story's biggest named risk (a future team mistaking this for real authorization) is foreclosed by the API shape itself, not just by documentation. The one place a real trust decision is readable is `AuthStore.permissions()` — its `@security` JSDoc is the load-bearing one.

Two Low findings from the security review were fixed post-review:
- The denial log strips both the query string **and** URL fragment from the attempted route (a fragment could carry a token, e.g. after an OAuth-style redirect).
- The route-table contract spec checks `canActivateChild` in addition to `canActivate`, and credits an ancestor's `authGuard` declared via either property to its descendants.

## 5. Documentation this story added/changed

- `docs/DEVELOPMENT_GUIDE.md` — new "Permission-gating the UI" section: usage examples, the UX-only statement, the fail-open/composition contract, the "route gating doesn't protect code" warning, and a code-review checklist.
- `docs/ARCHITECTURE.md` — Non-negotiable #9 clarified (custom structural directives are permitted); frontend tree diagram updated (`shared/directives/`, `shared/pages/`); new `shared/` → `core/` layering rule recorded.
- `CLAUDE.md` — stale Angular/TypeScript version corrected; one-line pointer to the UX-only convention added to "Critical conventions."

## 6. Known limitations (by design, not oversight)

- The route-table contract spec cannot see inside `loadChildren`-loaded route tables (e.g. `features/auth/auth.routes.ts`) — any future `permissionGuard` usage inside a lazy child route table needs its own equivalent local contract test.
- "Session not yet loaded" and "genuinely zero permissions" are indistinguishable to the guard/directive — both yield an empty permission list. No user-visible consequence in either direction (can only hide UI or deny navigation, never grant), and self-correcting once `/users/me` resolves.
- `GlobalErrorHandler` will `JSON.stringify` an unhandled `AppError` into a production-visible log line, including `requiredPermission` — pre-existing behavior, not introduced by this story, tracked as a backlog hardening ticket (see `03-design.md` §16.3) rather than fixed here.
