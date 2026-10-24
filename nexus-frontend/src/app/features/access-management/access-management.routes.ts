import { inject } from '@angular/core';
import { CanActivateFn, Router, Routes } from '@angular/router';
import { AuthStore } from '../../core/auth/auth.store';
import { permissionGuard } from '../../core/guards/permission.guard';
import { AuthorizationProfileStore } from './data/authorization-profile.store';
import { CatalogueStore } from './data/catalogue.store';
import { RolesStore } from './data/roles.store';
import { AccessConsoleLayout } from './layout/access-console-layout';
import { CONSOLE_AREAS } from './layout/console-areas';
import { RoleDetailStore } from './role-detail/role-detail.store';
import { unsavedChangesGuard } from './role-editor/unsaved-changes.guard';

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
 *   stores to the console: {@link AuthorizationProfileStore}, {@link RolesStore} and
 *   {@link CatalogueStore}.
 * - Its empty path always leaves through {@link firstAreaRedirect}. The `title` on that route is
 *   never shown; it satisfies the "every page route has a title" contract.
 * - Every area page added below carries `permissionGuard` with its own `data.permission` and a
 *   static title (DQ-26). No `canActivateChild` anywhere (RC-65).
 * - `roles/:roleId` scopes {@link RoleDetailStore} to one role page and has its tabs and the
 *   editor (`edit`, `role:write`, `unsavedChangesGuard`) as child routes; its own route has no
 *   title (the children have static ones), so a role name never reaches `document.title`.
 * - `roles/new` (Create and Clone, `role:write`, `unsavedChangesGuard`) is declared before
 *   `roles/:roleId`.
 */
export const ACCESS_MANAGEMENT_ROUTES: Routes = [
  {
    path: '',
    component: AccessConsoleLayout,
    providers: [AuthorizationProfileStore, RolesStore, CatalogueStore],
    children: [
      {
        path: '',
        pathMatch: 'full',
        title: 'Access management',
        canActivate: [firstAreaRedirect],
        children: [],
      },
      {
        // `permission` is the roles entry of CONSOLE_AREAS (pinned by the routes spec).
        path: 'roles',
        title: 'Roles',
        canActivate: [permissionGuard],
        data: { permission: 'role:read' },
        loadComponent: () => import('./roles/roles-list.page').then((m) => m.RolesListPage),
      },
      {
        // Before `roles/:roleId`, so "new" is never matched as a role id.
        path: 'roles/new',
        title: 'Create role',
        canActivate: [permissionGuard],
        canDeactivate: [unsavedChangesGuard],
        data: { permission: 'role:write' },
        loadComponent: () => import('./role-editor/role-create.page').then((m) => m.RoleCreatePage),
      },
      {
        path: 'roles/:roleId',
        canActivate: [permissionGuard],
        data: { permission: 'role:read' },
        providers: [RoleDetailStore],
        loadComponent: () => import('./role-detail/role-detail.page').then((m) => m.RoleDetailPage),
        children: [
          { path: '', pathMatch: 'full', redirectTo: 'permissions' },
          {
            path: 'permissions',
            title: 'Role permissions',
            loadComponent: () =>
              import('./role-detail/role-permissions.tab').then((m) => m.RolePermissionsTab),
          },
          {
            // A child, so the page and its store stay: entering the editor sends no request.
            path: 'edit',
            title: 'Edit role',
            canActivate: [permissionGuard],
            canDeactivate: [unsavedChangesGuard],
            data: { permission: 'role:write' },
            loadComponent: () =>
              import('./role-editor/role-editor.page').then((m) => m.RoleEditorPage),
          },
        ],
      },
      {
        // `permission` is the permissions entry of CONSOLE_AREAS (pinned by the routes spec).
        path: 'permissions',
        title: 'Permissions',
        canActivate: [permissionGuard],
        data: { permission: 'role:read' },
        loadComponent: () => import('./catalogue/catalogue.page').then((m) => m.CataloguePage),
      },
    ],
  },
];
