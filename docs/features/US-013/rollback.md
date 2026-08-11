# US-013 — Rollback Plan: Angular Permission Guard and Directive

**Feature:** `permissionGuard` / `*appHasPermission` / `AccessDeniedComponent` (frontend-only, EPIC-002 RBAC Foundation)

---

## 1. Summary

**Trivial rollback: a plain code revert.** No feature flag exists to flip, no data was ever written (this story performs no HTTP writes of its own), and no schema was touched. There is nothing irreversible in this diff.

## 2. Code rollback

Revert the merge commit (or the equivalent set of commits) for US-013. That's the entire procedure.

**What breaks on revert:** `/access-denied` starts returning a router "no route matched" outcome instead of rendering — but nothing links to it yet (infrastructure-only scope, per `01-requirements.md`'s resolved decisions), so this is not user-visible. No existing route, component, or test outside this story's own files references any of the reverted symbols (`permissionGuard`, `HasPermissionDirective`, `AccessDeniedComponent`, `AuthStore.permissions`, `AppError.requiredPermission`) — confirmed by the "infrastructure only" scope decision and grep-verified during code review (`06-code-review.md`).

**What does NOT need separate handling on revert:**
- `AuthUser.permissions` / `MeApiResponse.permissions` — reverting these alongside everything else is safe; nothing outside this story's own files reads them.
- `shared/testing/auth.fixtures.ts` — the three specs that migrated onto it (`auth.store.spec.ts`, `auth.interceptor.spec.ts`) revert in the same commit set; there's no partial-revert scenario where the fixture module disappears while a spec still imports it, because they're all part of the same PR.

## 3. Data rollback

**Not applicable.** This story performs zero writes — no HTTP `POST`/`PUT`/`DELETE` calls, no new client-side persistence (session stays in-memory only, never `sessionStorage`/`localStorage`, per the corrected doc comment in `shared/types/auth.ts`). There is nothing to roll back at the data layer, and nothing irreversible was ever created.

## 4. Feature flag kill switch

**None exists, by design** (see `deployment.md` §3 for why). There is no flag to flip as a faster-than-revert rollback lever — the plain code revert above is both the fastest and only rollback path, and it's fast enough (a single frontend deploy, no backend coordination) that a flag would add config surface without buying any speed.

## 5. Cache invalidation

**Not applicable.** No server-side cache is touched (no Redis, no HTTP cache-control change). The only caching-adjacent construct in this story is `computed()`'s in-memory signal memoisation (`AuthStore.permissions`, `HasPermissionDirective.granted`) — this is per-browser-tab, in-memory JS state that disappears on page reload regardless of any rollback action; there is nothing to invalidate out-of-band.

## 6. Backend rollback

**Not applicable.** Zero backend diff — there is no backend artifact to roll back, no migration to reverse, no `nexus_app` grant to revoke.

## 7. Partial-revert risk

If only some of this story's files are reverted (e.g., a bad cherry-pick), the highest-risk split is reverting `shared/types/auth.ts`'s `AuthUser.permissions` field while leaving `features/auth/auth.service.ts`'s `buildSession()` mapping in place (or vice versa) — this reproduces the exact TS2741 compile error the design doc's task breakdown (`04-tasks.md` T-001/T-002) called out as the reason those two changes must land together. **Always revert this story as a single unit**, not file-by-file.
