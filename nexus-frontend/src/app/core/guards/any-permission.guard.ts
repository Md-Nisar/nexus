import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthStore } from '../auth/auth.store';
import { LoggerService } from '../logging/logger.service';
import { PERMISSIONS, Permission } from '../../shared/types/permission';

function isValidAnyOf(raw: unknown): raw is readonly Permission[] {
  return (
    Array.isArray(raw) &&
    raw.length > 0 &&
    raw.every((p) => typeof p === 'string' && (PERMISSIONS as readonly string[]).includes(p))
  );
}

/**
 * Route guard that requires the current user to hold ANY of the permissions listed in the
 * route's own `data.anyOf` (US-020 design §4.3). A synchronous signal read of
 * {@link AuthStore.permissions}; no I/O.
 *
 * ## Usage contract (mandatory)
 * As with `permissionGuard`, `authGuard` MUST sit on an **ancestor** route and the two guards MUST
 * NOT share a `canActivate` array: guards in one array run concurrently, so this guard would read
 * the store before the silent refresh restores the session. The route must declare its own
 * `data.anyOf`. `any-permission-guard-contract.spec.ts` enforces all three on the real table.
 *
 * ## Fail-closed
 * Unlike `permissionGuard`, whose fail-open on a missing value is pinned (RES-39), this guard
 * treats a `data.anyOf` that is not a non-empty array of {@link PERMISSIONS} members as a
 * misconfiguration and **denies**: it redirects to `/access-denied` without reading the store and
 * logs `any_permission_guard_misconfigured` once, with the path only.
 *
 * @security **UX only, not a security boundary.** The server's `@RequiresPermission` is the sole
 * enforcement point.
 *
 * @returns `true` to allow navigation, or a `UrlTree` to `/access-denied` with no query params.
 */
export const anyPermissionGuard: CanActivateFn = (route, state) => {
  const router = inject(Router);
  // Bracket access is mandatory: Router `Data` is an index-signature type.
  const raw: unknown = route.data['anyOf'];

  if (!isValidAnyOf(raw)) {
    inject(LoggerService).error('anyPermissionGuard denied a route with an invalid data.anyOf', {
      event: 'any_permission_guard_misconfigured',
      outcome: 'FAILURE',
      // Path only: the query string and fragment are unbounded and can carry tokens. The raw
      // `data.anyOf` is not logged either.
      context: { route: state.url.split(/[?#]/)[0] },
    });
    return router.createUrlTree(['/access-denied']);
  }

  const held = inject(AuthStore).permissions();
  if (raw.some((p) => held.includes(p))) return true;

  // No query params: reflecting the attempted URL or the permissions into the address bar would
  // put RBAC internals into history, bookmarks and the Referer header.
  return router.createUrlTree(['/access-denied']);
};
