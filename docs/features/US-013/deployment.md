# US-013 — Deployment Guide: Angular Permission Guard and Directive

**Feature:** `permissionGuard` / `*appHasPermission` / `AccessDeniedComponent` (frontend-only, EPIC-002 RBAC Foundation)

---

## 1. Summary

**Trivial, instant, single deploy.** No migration, no environment variable, no feature flag, no backend change, no backend coordination, and no behavior change for any existing route or component. This story ships code that nothing yet calls, plus one new public URL (`/access-denied`).

## 2. Database

**None.** Zero-line diff to `nexus-backend/`, `nexus-database/`, and every Flyway migration. `ddl-auto=validate` is not engaged. Nothing to run before, during, or after deploy.

## 3. Feature flag

**None, deliberately** (per `03-design.md` §10, confirmed unchanged in `01-requirements.md`'s resolved decisions). No existing route carries `canActivate: [permissionGuard]` and no existing component imports `HasPermissionDirective` after this merge — a flag would gate code nothing calls, adding config surface for zero risk reduction. The first Epic 3 route that adopts the guard owns its own rollout decision; that is a route-table change, not a runtime flag.

## 4. Backend

**None.** No controller, service, entity, repository, or dependency changed. `SECURITY.md`'s dependency-check gate and this story's own security review (`07-security-review.md`) both confirm a verified zero-line backend diff.

## 5. Frontend

The only deploy-relevant artifact: a standard Angular production build.

```bash
cd nexus-frontend
npm run build     # confirms no strict-template errors, no new bundle-budget regressions
```

**New lazy chunk:** `access-denied-component` (~1.9 kB raw, ~0.8 kB transferred) — confirmed in the build output to be a separate chunk, not part of the initial bundle. No initial-bundle size regression.

**New route:** `/access-denied`, unguarded, public, lazy-loaded. This is the only new attack/access surface this deploy introduces, and it's inert — no HTTP call, no data, static copy only.

**Deploy order vs. backend:** irrelevant. `MeResponse.permissions` (the field this story's frontend types now map) already ships on `main`; if a stale backend build were ever served without it, `buildSession()`'s `?? []` default degrades to "no permissions" without throwing.

## 6. Ordering constraint (intra-PR, not inter-deploy)

The only sequencing rule is internal to the commit history, not to deployment: the `AuthUser.permissions` type change and the fixture updates it forces (T-001–T-004 in `04-tasks.md`) must land together, or `npm run build`/`npm run test:ci` goes red. This is already satisfied in the merged diff — noted here only so a future cherry-pick or partial revert doesn't split them.

## 7. Verification after deploy (~2 minutes, no special tooling)

1. Navigate to `/access-denied` directly — page renders, heading receives focus, both links work ("Return to dashboard", "Contact your administrator").
2. Log in as any existing user — `/dashboard` still loads (confirms `authGuard` and the rest of the auth chain are unaffected).
3. Open browser devtools → confirm `AuthStore.permissions()` (via Angular DevTools or a breakpoint) is populated after login — proves the `/users/me` → `AuthUser.permissions` → `AuthStore.permissions` chain is wired end-to-end.

## 8. Rollback

See `rollback.md`. Summary: a plain code revert — no data written, no schema touched, no external state, no flag to flip.
