# US-013 — Monitoring Guide: Angular Permission Guard and Directive

**Feature:** `permissionGuard` / `*appHasPermission` / `AccessDeniedComponent` (frontend-only, EPIC-002 RBAC Foundation)

---

## 1. Summary

**Deliberately minimal observability** (per `03-design.md` §8, confirmed by both the code review and security review). This story adds exactly one new log call site and zero metrics, zero traces, zero dashboards, and zero alerts. The reasoning: a client-side permission denial is a UX event, not a security event — the authoritative record of every denial already exists server-side (`nexus.rbac.permission_denied` counter + WARN log, shipped under US-011) and this story does not duplicate it.

## 2. Logs

| Field | Value |
|---|---|
| Message | `'Permission check denied navigation'` |
| `event` | `'permission_denied_client'` |
| `outcome` | `'FAILURE'` |
| `context.permission` | the required permission string |
| `context.route` | the attempted route's path only — query string **and** URL fragment are stripped before logging |
| Level | `debug` |
| Where | `nexus-frontend/src/app/core/guards/permission.guard.ts`, denial branch only |

**This log is inert in production.** `environment.ts` sets prod `logLevel: 'warn'`; `LoggerService.enabled('debug')` suppresses anything below the configured minimum, so this line never reaches a production console or any log-shipping pipeline (which doesn't exist for the frontend today — grep-verified zero analytics/beacon/Sentry code in `src/`, per `03b-threat-model.md` §4.4). It exists purely as a local development diagnostic.

**Explicitly not logged:**
- `HasPermissionDirective`'s suppression path — fires once per change-detection pass, per directive instance; would be pure noise.
- `permissionGuard`'s fail-open path (missing/invalid `data.permission`) — a per-navigation warning here would train reviewers to ignore it. The mitigation for a misconfigured route is the mechanical route-table contract spec (`permission-guard-contract.spec.ts`), which fails the *build*, not a runtime log line.

## 3. Metrics

**None added.** The backend's `nexus.rbac.permission_denied` counter (US-011) remains the authoritative, server-side source of truth for permission-denial volume. A client-side counter would double-count UX events that, in many cases, never even reach the server.

## 4. Dashboards

**None added.** There is no frontend telemetry sink in this codebase today (confirmed by grep during the threat model pass). Nothing in this story changes that. If frontend log shipping is ever introduced platform-wide, treat `permission_denied_client` as **non-admissible security evidence** — it is client-attested, forgeable by design (devtools), and prod-suppressed; do not build an alert or dashboard panel on it as if it were authoritative.

## 5. Alert thresholds

**None added, and none recommended for this story's own artifacts.** Existing alerting on the backend's `nexus.rbac.permission_denied` counter (if any exists under US-011/US-012's monitoring docs) is unaffected and remains the right place to alert on real denial volume.

## 6. What to look at when something goes wrong

The diagnostic table from `03-design.md` §8.3, reproduced here as the operational quick-reference:

| Symptom | First check |
|---|---|
| An entitled user lands on `/access-denied` | Is `permissionGuard` composed **after** `authGuard`, in either `canActivate` or `canActivateChild` (same array or an ancestor route)? This is the single most likely cause — a cold-start session-restore race if the ordering is wrong. |
| A gated route is open to everyone | Check `data.permission` for a typo or omission on that route — the guard fails open, silently. The route-table contract spec (`permission-guard-contract.spec.ts`) should have caught this at build time; if it didn't, check whether the route is nested inside a `loadChildren`-loaded module (a documented blind spot for that spec). |
| An element guarded by `*appHasPermission` never appears despite the user holding the permission | Check the `permissions` field in the `/users/me` response body directly; then `AuthStore.permissions()` in devtools; then confirm exact string/case match against the permission passed to the directive (`resource:action`, lowercase, exact match — no wildcard/hierarchy semantics). |
| An element appears but the underlying API call still 403s | **Expected and correct** — the directive is UX only. Check `AppError.code` (`RBAC_001` vs `ACCESS_DENIED`) and `traceId` against backend logs for the real denial reason. |

## 7. Health checks

**None added.** This is a frontend-only story with no service dependency to health-check.
