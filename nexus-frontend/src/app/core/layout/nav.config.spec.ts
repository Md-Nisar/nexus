import { Route, Routes } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { routes } from '../../app.routes';
import { NAV_ITEMS, NavItem, visibleNavItems } from './nav.config';

/** Flattens the route table to absolute path -> route (children inline; lazy modules skipped). */
function flatten(table: Routes, prefix = ''): Map<string, Route> {
  const out = new Map<string, Route>();
  for (const route of table) {
    const path = `${prefix}/${route.path ?? ''}`.replace(/\/+/g, '/');
    if (route.path !== '' || route.component || route.loadComponent) {
      out.set(path.replace(/\/$/, '') || '/', route);
    }
    flatten(route.children ?? [], path).forEach((r, p) => out.set(p, r));
  }
  return out;
}

describe('NAV_ITEMS', () => {
  const table = flatten(routes);

  it('has unique ids', () => {
    expect(new Set(NAV_ITEMS.map((i) => i.id)).size).toBe(NAV_ITEMS.length);
  });

  it.each(NAV_ITEMS.map((i) => [i.id, i] as const))(
    'resolves the path of %s to a route',
    (_id, item) => {
      expect(table.has(item.path)).toBe(true);
    },
  );

  it.each(NAV_ITEMS.map((i) => [i.id, i] as const))(
    'pins the permission of %s to the route data.permission',
    (_id, item) => {
      const route = table.get(item.path) as Route;
      expect(item.permission).toBe((route.data?.['permission'] as string | undefined) ?? null);
    },
  );
});

describe('visibleNavItems', () => {
  const open: NavItem = { id: 'a', label: 'A', path: '/a', icon: 'a', permission: null };
  const gated: NavItem = { id: 'b', label: 'B', path: '/b', icon: 'b', permission: 'role:read' };

  it('always keeps items without a permission', () => {
    expect(visibleNavItems([open, gated], [])).toEqual([open]);
  });

  it('keeps a gated item only when the permission is held', () => {
    expect(visibleNavItems([open, gated], ['role:read'])).toEqual([open, gated]);
    expect(visibleNavItems([open, gated], ['role:write'])).toEqual([open]);
  });
});
