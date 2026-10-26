import { InjectionToken, inject } from '@angular/core';
import { APP_CONFIG } from '../config/app-config';
import { Permission } from '../../shared/types/permission';

/** One entry of the signed-in shell's primary navigation. */
export interface NavItem {
  readonly id: string;
  readonly label: string;
  /**
   * Absolute router path; must resolve to a route whose `data.anyOf` (or `[data.permission]`)
   * equals `anyOf` as a set.
   */
  readonly path: string;
  /** Material Icons ligature name. */
  readonly icon: string;
  /** The item is shown when ANY of these permissions is held, or to everyone when `null`. */
  readonly anyOf: readonly Permission[] | null;
}

/**
 * Permissions that open the access management console (US-020 design §4.4). Shared by the
 * `admin/access` route's `data.anyOf`, its nav item and the dashboard card.
 */
export const ACCESS_CONSOLE_ANY_OF: readonly Permission[] = ['role:read', 'user:directory:read'];

/**
 * Primary navigation, in display order.
 *
 * @security UX only. Hiding an item is cosmetic; the route's guard and the server's
 * `@RequiresPermission` are the enforcement points. `nav.config.spec.ts` keeps each item's
 * `anyOf` equal to its route's `data.anyOf` (or `[data.permission]`) so the menu never misleads.
 */
export const NAV_ITEMS: readonly NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', path: '/dashboard', icon: 'dashboard', anyOf: null },
  {
    id: 'access-management',
    label: 'Access management',
    path: '/admin/access',
    icon: 'admin_panel_settings',
    anyOf: ACCESS_CONSOLE_ANY_OF,
  },
];

/**
 * Injection point for the nav items so specs can supply gated entries. Drops the access
 * management item when `accessConsoleEnabled` is false (a release control, RC-76), which keeps
 * {@link visibleNavItems} pure.
 */
export const NAV_ITEMS_TOKEN = new InjectionToken<readonly NavItem[]>('NAV_ITEMS', {
  factory: () =>
    inject(APP_CONFIG).accessConsoleEnabled
      ? NAV_ITEMS
      : NAV_ITEMS.filter((item) => item.id !== 'access-management'),
});

/** The items a user holding `permissions` may see. */
export function visibleNavItems(
  items: readonly NavItem[],
  permissions: readonly string[],
): readonly NavItem[] {
  return items.filter(
    (item) => item.anyOf === null || item.anyOf.some((p) => permissions.includes(p)),
  );
}
