import { InjectionToken } from '@angular/core';
import { Permission } from '../../shared/types/permission';

/** One entry of the signed-in shell's primary navigation. */
export interface NavItem {
  readonly id: string;
  readonly label: string;
  /** Absolute router path; must resolve to a route whose `data.permission` equals `permission`. */
  readonly path: string;
  /** Material Icons ligature name. */
  readonly icon: string;
  /** Permission required to see the item, or `null` for every signed-in user. */
  readonly permission: Permission | null;
}

/**
 * Primary navigation, in display order.
 *
 * @security UX only. Hiding an item is cosmetic; the route's guard and the server's
 * `@RequiresPermission` are the enforcement points. `nav.config.spec.ts` keeps each item's
 * `permission` equal to its route's `data.permission` so the menu never misleads.
 */
export const NAV_ITEMS: readonly NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', path: '/dashboard', icon: 'dashboard', permission: null },
];

/** Injection point for the nav items so specs can supply gated entries. */
export const NAV_ITEMS_TOKEN = new InjectionToken<readonly NavItem[]>('NAV_ITEMS', {
  factory: () => NAV_ITEMS,
});

/** The items a user holding `permissions` may see. */
export function visibleNavItems(
  items: readonly NavItem[],
  permissions: readonly string[],
): readonly NavItem[] {
  return items.filter((item) => item.permission === null || permissions.includes(item.permission));
}
