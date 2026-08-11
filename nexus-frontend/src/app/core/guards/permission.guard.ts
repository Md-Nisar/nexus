import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthStore } from '../auth/auth.store';
import { LoggerService } from '../logging/logger.service';

/**
 * Route guard that requires the current user to hold a specific RBAC permission.
 *
 * Reads the required permission from the activated route's `data.permission` and
 * compares it against {@link AuthStore.permissions} — a synchronous signal read, so the
 * guard never performs I/O and never returns an Observable.
 *
 * ## Usage contract (mandatory)
 * `permissionGuard` MUST be composed **after** `authGuard`, or sit under a route whose
 * ancestor already carries `authGuard`:
 *
 * ```typescript
 * { path: 'roles', canActivate: [authGuard, permissionGuard], data: { permission: 'roles:read' }, ... }
 * ```
 *
 * Angular evaluates a `canActivate` array sequentially and short-circuits on the first
 * non-`true` result, so `authGuard` completes its silent refresh (populating the session)
 * before this guard reads the store. Used **alone**, on a cold start (page reload, session
 * `null`) this guard would see an empty permission list and misroute an entitled but
 * not-yet-restored user to `/access-denied` instead of `/auth/login`.
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
  const required: unknown = route.data['permission'];

  if (typeof required !== 'string' || required.length === 0) return true;

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
