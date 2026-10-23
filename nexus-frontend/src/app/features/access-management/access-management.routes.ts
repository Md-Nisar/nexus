import { inject } from '@angular/core';
import { CanActivateFn, Router, Routes } from '@angular/router';
import { AuthStore } from '../../core/auth/auth.store';
import { AuthorizationProfileStore } from './data/authorization-profile.store';
import { AccessConsoleLayout } from './layout/access-console-layout';
import { CONSOLE_AREAS } from './layout/console-areas';

/** Where a user who holds none of the areas' permissions would go; the parent guard denies them first. */
const FALLBACK_AREA = '/admin/access/users';

/**
 * Sends `/admin/access` to the first console area the user holds: `role:read` gives `roles`,
 * anything else `users` (US-020 design §4.2).
 *
 * A guard, not a `redirectTo` function: redirects run during route recognition, before the shell's
 * `authGuard` has restored the session on a cold start, so a redirect function would see no
 * permissions and send a role reader to `users`. `canActivate` guards run top-down, after
 * `authGuard` and `anyPermissionGuard` on the ancestors. Reads `AuthStore` only; UX only.
 */
export const firstAreaRedirect: CanActivateFn = () => {
  const held = inject(AuthStore).permissions();
  const area = CONSOLE_AREAS.find((candidate) => held.includes(candidate.permission));
  return inject(Router).parseUrl(area?.path ?? FALLBACK_AREA);
};

/**
 * Child routes of the gated `admin/access` parent (US-020 design §4.1, §4.2), loaded lazily as the
 * console chunk.
 *
 * - The `''` child is the {@link AccessConsoleLayout}. Its route `providers` scope the console
 *   stores to the console: {@link AuthorizationProfileStore} here; the roles and catalogue stores
 *   join with their pages.
 * - Its empty path always leaves through {@link firstAreaRedirect}. The `title` on that route is
 *   never shown; it satisfies the "every page route has a title" contract.
 * - Every area page added below carries `permissionGuard` with its own `data.permission` and a
 *   static title (DQ-26). No `canActivateChild` anywhere (RC-65).
 */
export const ACCESS_MANAGEMENT_ROUTES: Routes = [
  {
    path: '',
    component: AccessConsoleLayout,
    providers: [AuthorizationProfileStore],
    children: [
      {
        path: '',
        pathMatch: 'full',
        title: 'Access management',
        canActivate: [firstAreaRedirect],
        children: [],
      },
    ],
  },
];
