import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthStore } from '../auth/auth.store';
import { LoggerService } from '../logging/logger.service';
import { Permission } from '../../shared/types/permission';

/**
 * Route guard that requires the current user to hold a specific RBAC permission.
 *
 * Reads the required permission from the activated route's `data.permission` and
 * compares it against {@link AuthStore.permissions} — a synchronous signal read, so the
 * guard never performs I/O and never returns an Observable.
 *
 * ## Usage contract (mandatory)
 * `authGuard` MUST sit on an **ancestor** route of every route that uses `permissionGuard`,
 * and the two guards MUST NOT share a `canActivate` array:
 *
 * ```typescript
 * {
 *   path: '',
 *   canActivate: [authGuard],
 *   children: [
 *     { path: 'roles', canActivate: [permissionGuard], data: { permission: 'role:read' }, ... },
 *   ],
 * }
 * ```
 *
 * Guards inside one `canActivate` array run **concurrently** (the router combines their
 * results), so `permissionGuard` would read the store while `authGuard` is still refreshing the
 * session. Route **levels** run in sequence: an ancestor's guards complete before a child's
 * start, so by the time this guard runs the silent refresh has populated the session. Used
 * without an `authGuard` ancestor, on a cold start (page reload, session `null`) this guard
 * would see an empty permission list and misroute an entitled but not-yet-restored user to
 * `/access-denied` instead of `/auth/login`. `permission-guard-contract.spec.ts` enforces both
 * rules on the real route table.
 *
 * ## Fail-open
 * A route that reaches this guard without a non-empty string `data.permission` is a
 * *misconfiguration*, not a denial, and is allowed through. That is safe because this
 * guard is not a security boundary (below) — but it is silent, so every route that uses
 * this guard must be covered by a test asserting its `data.permission` value.
 *
 * @security **UX only — not a security boundary.** Server-side `@RequiresPermission`
 * (US-011) is the sole enforcement point. A user who edits client state or calls the API
 * directly still receives 403. Never use this guard as the only protection for anything.
 *
 * @returns `true` to allow navigation, or a `UrlTree` redirecting to `/access-denied`.
 */
export const permissionGuard: CanActivateFn = (route, state) => {
  const authStore = inject(AuthStore);
  const router = inject(Router);
  const logger = inject(LoggerService);

  // Bracket access is mandatory: `noPropertyAccessFromIndexSignature` is on
  // (tsconfig.json) and Router `Data` is an index-signature type. Annotating as
  // `unknown` keeps `any` out of the file, which `@typescript-eslint/no-explicit-any`
  // requires.
  const rawRequired: unknown = route.data['permission'];

  if (typeof rawRequired !== 'string' || rawRequired.length === 0) return true;

  // Typed as `Permission` for readers and tooling only: a name outside the catalogue is NOT
  // treated as a misconfiguration here (the fail-open semantics above are pinned, RES-39). It
  // is simply not held, so it is denied. `app.routes.spec.ts` is the compensating control that
  // keeps every real route's `data.permission` inside `PERMISSIONS`.
  const required = rawRequired as Permission;

  if (authStore.permissions().includes(required)) return true;

  logger.debug('Permission check denied navigation', {
    event: 'permission_denied_client',
    outcome: 'FAILURE',
    // Query string AND URL fragment deliberately stripped before logging: both are
    // unbounded and future-controlled (a fragment can carry a token, e.g. after an
    // OAuth-style redirect), and the attempted path alone is enough to diagnose a
    // misconfigured or intentionally-gated route.
    context: { permission: required, route: state.url.split(/[?#]/)[0] },
  });

  // Deliberately no query params on the redirect itself: reflecting the attempted URL or
  // the required permission into the address bar would put RBAC internals into browser
  // history, bookmarks, and the Referer header. The page needs no context to render.
  return router.createUrlTree(['/access-denied']);
};
