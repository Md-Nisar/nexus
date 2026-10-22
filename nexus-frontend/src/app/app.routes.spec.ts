import { Route, Routes } from '@angular/router';
import { describe, it, expect } from 'vitest';
import { routes } from './app.routes';
import { permissionGuard } from './core/guards/permission.guard';
import { PERMISSIONS } from './shared/types/permission';

/**
 * Route-table contract for `permissionGuard` (US-018 B5, FR-B5.c, TS-13).
 *
 * `permissionGuard` fails OPEN on a route with no non-empty string `data.permission` (a
 * pinned, accepted contract, RES-39), so a typo or a missing value would silently leave a
 * route ungated in the UI. This spec is the compensating control: every route that lists
 * `permissionGuard` in `canActivate`, at any depth including lazy `loadChildren`, must carry a
 * `data.permission` that is a member of `PERMISSIONS`.
 *
 * @security UX only. The server's `@RequiresPermission` is the sole enforcement point.
 */

interface Offender {
  readonly path: string;
  readonly permission: unknown;
}

/** Resolves a route's children, awaiting lazy `loadChildren` when it yields a route array. */
async function childrenOf(route: Route): Promise<Routes> {
  if (route.children) return route.children;
  if (typeof route.loadChildren !== 'function') return [];
  const loaded: unknown = await route.loadChildren();
  if (Array.isArray(loaded)) return loaded as Routes;
  // A lazily imported module whose default export is the route array.
  const maybeDefault = (loaded as { default?: unknown } | null)?.default;
  return Array.isArray(maybeDefault) ? (maybeDefault as Routes) : [];
}

/** Every route using `permissionGuard` whose `data.permission` is not a catalogue member. */
async function findOffenders(table: Routes, prefix = ''): Promise<Offender[]> {
  const offenders: Offender[] = [];
  for (const route of table) {
    const path = `${prefix}/${route.path ?? ''}`.replace(/\/+/g, '/');
    if (route.canActivate?.includes(permissionGuard)) {
      const permission: unknown = route.data?.['permission'];
      if (
        typeof permission !== 'string' ||
        !(PERMISSIONS as readonly string[]).includes(permission)
      ) {
        offenders.push({ path, permission });
      }
    }
    offenders.push(...(await findOffenders(await childrenOf(route), path)));
  }
  return offenders;
}

describe('route table permissionGuard contract', () => {
  it('gives every route that uses permissionGuard a data.permission from PERMISSIONS', async () => {
    expect(await findOffenders(routes)).toEqual([]);
  });

  it('reports a fixture route whose data.permission is not in PERMISSIONS', async () => {
    const fixture: Routes = [
      {
        path: 'ok',
        canActivate: [permissionGuard],
        data: { permission: 'role:read' },
        children: [],
      },
      {
        path: 'bad',
        canActivate: [permissionGuard],
        data: { permission: 'roles:read' },
        children: [],
      },
    ];

    expect(await findOffenders(fixture)).toEqual([{ path: '/bad', permission: 'roles:read' }]);
  });

  it('reports a fixture route that uses permissionGuard with no data.permission', async () => {
    const fixture: Routes = [{ path: 'missing', canActivate: [permissionGuard], children: [] }];

    expect(await findOffenders(fixture)).toEqual([{ path: '/missing', permission: undefined }]);
  });

  it('reports a nested fixture route under a parent that carries no guard', async () => {
    const fixture: Routes = [
      {
        path: 'parent',
        children: [{ path: 'child', canActivate: [permissionGuard], data: { permission: 42 } }],
      },
    ];

    expect(await findOffenders(fixture)).toEqual([{ path: '/parent/child', permission: 42 }]);
  });
});
