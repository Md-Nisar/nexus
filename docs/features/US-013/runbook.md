# US-013 — Runbook: Angular Permission Guard and Directive

**Feature:** `permissionGuard` / `*appHasPermission` / `AccessDeniedComponent` (frontend-only, EPIC-002 RBAC Foundation)

---

## Scope note

This story ships as **infrastructure only** — at merge time, no existing route uses `permissionGuard` and no existing component uses `*appHasPermission`. Most scenarios below describe what to do **once a future story (Epic 3+) adopts these**, not something that can happen against `main` today. They're documented now so the first team to use the guard/directive has a runbook on day one instead of discovering these failure modes cold.

---

## Scenario: "A user says they can't access a feature they should have permission for"

1. Confirm the user's actual permission set: check the `permissions[]` array in their `GET /v1/users/me` response (via devtools Network tab, or ask them to check with you on a call) or, if you have backend access, query the `user_roles` → `role_permissions` → `permissions` chain directly for their `(user_id, tenant_id)`.
2. If the permission genuinely isn't in the list: this is a role-assignment issue, not a US-013 bug — route to whoever owns role assignment (US-012's `POST /api/v1/users/{userId}/roles`).
3. If the permission **is** in the list but the user still sees `/access-denied` or a missing UI element:
   - Check **exact string match**: permission comparison is case-sensitive, exact-match only (`resource:action`, lowercase). A mismatch between the route's `data.permission` and the backend-issued string will silently deny.
   - Check the **guard composition order** on the affected route: `permissionGuard` must be listed *after* `authGuard` in `canActivate` or `canActivateChild` (or the route must sit under an `authGuard`-protected ancestor). If composed wrong, a cold-start reload can send even a fully-entitled user to `/access-denied`.
   - Ask the user to hard-refresh / log out and back in — the permission set is refreshed on login/token-refresh, not live-pushed; a role change made *after* their current session started won't reflect until their next refresh cycle (documented, accepted lag from EPIC-002).

## Scenario: "A route that should be permission-gated is accessible to everyone"

This means the guard **failed open** — a deliberate, documented behavior for a misconfigured route (the guard is UX-only, so a typo shouldn't lock out a whole feature).

1. Check the route's `data` object for a missing or misspelled `permission` key, or a non-string/empty-string value.
2. This should have been caught at build time by `nexus-frontend/src/app/core/guards/permission-guard-contract.spec.ts`, which mechanically walks the real route table. If it wasn't caught:
   - Is the route defined inside a `loadChildren`-loaded child route table (e.g. a feature's own `*.routes.ts`)? This is a documented blind spot for that spec — lazy-loaded route tables aren't statically visible to it. The fix is to add an equivalent contract test local to that feature module, not to extend the existing one.
   - Confirm the contract spec is actually running in CI and wasn't skipped/quarantined.
3. Fix the route's `data.permission`, run `npm run test:ci` locally to confirm the contract spec now catches it if you deliberately break it again, then ship the fix as a normal PR — there's no flag or runtime lever, just a code fix.

## Scenario: "The Access Denied page looks broken / links don't work"

1. `/access-denied` is a static, unguarded, backend-free page — if it's broken, it's a frontend deploy/build issue, not a data or backend issue. Check the browser console for a JS error first.
2. "Contact your administrator" links to a placeholder `mailto:support@yourcompany.example` address (an RFC 2606 reserved domain, marked `TODO(PM)` in the source) — **if this hasn't been replaced with a real support address before this reached production, that's a release-checklist gap, not a bug in the page itself.** Escalate to PM to supply the real address; don't try to "fix" the code without one.
3. If the heading isn't receiving keyboard focus on page entry (an accessibility regression): check that `afterNextRender()` is still firing in `access-denied.component.ts` — this is standard Angular behavior and unlikely to regress without a direct code change to that file.

## Scenario: "I'm building a new Epic 3 feature and need to gate a route/action — where do I start?"

Read `docs/DEVELOPMENT_GUIDE.md`'s "Permission-gating the UI" section first — it has copy-pasteable examples for both `permissionGuard` and `*appHasPermission`, plus the guard-composition rule and the "never hide already-delivered data" warning. This runbook is for *operating* the pattern once it's live, not for learning how to use it.

## Escalation

There is no on-call rotation or paging tied to this story's artifacts (see `monitoring.md` — no alerts exist by design). If a scenario above doesn't resolve the issue, the next step is a normal engineering investigation, not an incident — nothing in this story is a security boundary, so nothing here can itself be the cause of a data exposure or authorization bypass. If you suspect an actual authorization bypass (data or an action reachable that shouldn't be), that is a backend (`@RequiresPermission`, US-011) issue, not a frontend one — escalate accordingly.
