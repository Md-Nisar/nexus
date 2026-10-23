import type { Permission } from '../../../shared/types/permission';

export type ConsoleAreaId = 'roles' | 'permissions' | 'users';

/** One top-level area of the console: its sub-nav tab and the permission its route requires. */
export interface ConsoleArea {
  readonly id: ConsoleAreaId;
  /** Absolute route path of the area. */
  readonly path: string;
  /** The area route's `data.permission`; the tab is shown only when `AuthStore` holds it. */
  readonly permission: Permission;
}

/**
 * The console areas in sub-nav order (US-020 design §4.2, §12.1). The first one the user holds is
 * where `firstAreaRedirect` sends `/admin/access`. UX only: each area route carries its own
 * `permissionGuard`, and the server decides.
 */
export const CONSOLE_AREAS: readonly ConsoleArea[] = [
  { id: 'roles', path: '/admin/access/roles', permission: 'role:read' },
  { id: 'permissions', path: '/admin/access/permissions', permission: 'role:read' },
  { id: 'users', path: '/admin/access/users', permission: 'user:directory:read' },
];
