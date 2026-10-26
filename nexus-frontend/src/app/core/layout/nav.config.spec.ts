import { TestBed } from '@angular/core/testing';
import { Route, Routes } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { routes } from '../../app.routes';
import { APP_CONFIG, AppConfig } from '../config/app-config';
import {
  ACCESS_CONSOLE_ANY_OF,
  NAV_ITEMS,
  NAV_ITEMS_TOKEN,
  NavItem,
  visibleNavItems,
} from './nav.config';

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
    'pins the anyOf of %s to the route data.anyOf, [data.permission] or null, as a set',
    (_id, item) => {
      const data = (table.get(item.path) as Route).data;
      const anyOf = data?.['anyOf'] as readonly string[] | undefined;
      const permission = data?.['permission'] as string | undefined;
      const expected = anyOf ?? (permission === undefined ? null : [permission]);
      const asSet = (list: readonly string[] | null) => (list === null ? null : [...list].sort());
      expect(asSet(item.anyOf)).toEqual(asSet(expected));
    },
  );

  it('pins ACCESS_CONSOLE_ANY_OF to exactly role:read and user:directory:read', () => {
    expect([...ACCESS_CONSOLE_ANY_OF].sort()).toEqual(['role:read', 'user:directory:read']);
  });

  it('contains the Access management item at /admin/access with ACCESS_CONSOLE_ANY_OF', () => {
    expect(NAV_ITEMS.find((i) => i.id === 'access-management')).toEqual({
      id: 'access-management',
      label: 'Access management',
      path: '/admin/access',
      icon: 'admin_panel_settings',
      anyOf: ACCESS_CONSOLE_ANY_OF,
    });
  });
});

describe('visibleNavItems', () => {
  const open: NavItem = { id: 'a', label: 'A', path: '/a', icon: 'a', anyOf: null };
  const gated: NavItem = { id: 'b', label: 'B', path: '/b', icon: 'b', anyOf: ['role:read'] };
  const anyOf: NavItem = {
    id: 'c',
    label: 'C',
    path: '/c',
    icon: 'c',
    anyOf: ['role:read', 'user:directory:read'],
  };
  const empty: NavItem = { id: 'd', label: 'D', path: '/d', icon: 'd', anyOf: [] };

  it('always keeps items without a permission', () => {
    expect(visibleNavItems([open, gated], [])).toEqual([open]);
  });

  it('keeps a gated item only when the permission is held', () => {
    expect(visibleNavItems([open, gated], ['role:read'])).toEqual([open, gated]);
    expect(visibleNavItems([open, gated], ['role:write'])).toEqual([open]);
  });

  it('keeps an any-of item held through its first member', () => {
    expect(visibleNavItems([open, anyOf], ['role:read'])).toEqual([open, anyOf]);
  });

  it('keeps an any-of item held through its second member', () => {
    expect(visibleNavItems([open, anyOf], ['user:directory:read'])).toEqual([open, anyOf]);
  });

  it('drops an any-of item when neither member is held', () => {
    expect(visibleNavItems([open, anyOf], ['user:read', 'role:write'])).toEqual([open]);
  });

  it('drops an item whose anyOf is empty', () => {
    expect(visibleNavItems([open, empty], ['role:read'])).toEqual([open]);
  });
});

describe('NAV_ITEMS_TOKEN', () => {
  function itemsWith(accessConsoleEnabled: boolean): readonly NavItem[] {
    const config: AppConfig = {
      production: false,
      apiBaseUrl: '/api',
      logLevel: 'debug',
      supportContact: null,
      accessConsoleEnabled,
    };
    TestBed.configureTestingModule({ providers: [{ provide: APP_CONFIG, useValue: config }] });
    return TestBed.inject(NAV_ITEMS_TOKEN);
  }

  it('drops the access-management item when the console is switched off', () => {
    const items = itemsWith(false);
    expect(items).toEqual(NAV_ITEMS.filter((i) => i.id !== 'access-management'));
    expect(items.some((i) => i.id === 'access-management')).toBe(false);
  });

  it('keeps every item when the console is switched on', () => {
    expect(itemsWith(true)).toEqual(NAV_ITEMS);
  });
});
