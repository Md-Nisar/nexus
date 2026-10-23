import { TestBed } from '@angular/core/testing';
import { Route, Router, Routes, provideRouter } from '@angular/router';
import { describe, it, expect } from 'vitest';
import { routes } from './app.routes';
import { AuthStore } from './core/auth/auth.store';
import { authGuard } from './core/guards/auth.guard';
import { createAuthSession } from './shared/testing/auth.fixtures';
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

describe('route tree shape (US-019 A2)', () => {
  const PUBLIC_PATHS = ['auth', 'access-denied', 'design-system'];

  it('declares the public layout before the guarded shell', () => {
    const publicIndex = routes.findIndex((r) => r.children?.some((c) => c.path === 'auth'));
    const shellIndex = routes.findIndex((r) => r.canActivate?.includes(authGuard));
    expect(publicIndex).toBeGreaterThanOrEqual(0);
    expect(shellIndex).toBeGreaterThan(publicIndex);
    expect(routes[0]).toMatchObject({ path: '', redirectTo: 'dashboard' });
  });

  it('keeps auth, access-denied and design-system under an unguarded, data-free public layout', () => {
    const layout = routes.find((r) => r.children?.some((c) => c.path === 'auth')) as Route;
    expect(layout.canActivate).toBeUndefined();
    expect(layout.data).toBeUndefined();
    expect(layout.children?.map((c) => c.path)).toEqual(expect.arrayContaining(PUBLIC_PATHS));
  });

  it('pins the public layout children to exactly auth, access-denied and design-system', () => {
    const layout = routes.find((r) => r.children?.some((c) => c.path === 'auth')) as Route;
    expect((layout.children ?? []).map((c) => c.path).sort()).toEqual([...PUBLIC_PATHS].sort());
  });

  it('declares canActivateChild with authGuard on no route (RC-65: refresh-reuse logout)', async () => {
    async function offenders(table: Routes, prefix = ''): Promise<string[]> {
      const found: string[] = [];
      for (const route of table) {
        const path = `${prefix}/${route.path ?? ''}`.replace(/\/+/g, '/');
        if ((route.canActivateChild as readonly unknown[] | undefined)?.includes(authGuard))
          found.push(path);
        found.push(...(await offenders(await childrenOf(route), path)));
      }
      return found;
    }
    expect(await offenders(routes)).toEqual([]);
  });

  it('does not place any public path inside the shell', () => {
    const shell = routes.find((r) => r.canActivate?.includes(authGuard)) as Route;
    const shellPaths = (shell.children ?? []).map((c) => c.path);
    for (const path of PUBLIC_PATHS) expect(shellPaths).not.toContain(path);
  });

  it('redirects / to /dashboard before either empty-path parent can swallow it', async () => {
    TestBed.configureTestingModule({ providers: [provideRouter(routes)] });
    TestBed.inject(AuthStore).setSession(createAuthSession());
    const router = TestBed.inject(Router);
    const ok = await router.navigateByUrl('/');
    expect(ok).toBe(true);
    expect(router.url).toBe('/dashboard');
  });
});

describe('route titles (US-019 A8)', () => {
  /** Leaf routes: those that render a page rather than only wrap children or redirect. */
  async function untitledLeaves(table: Routes, prefix = ''): Promise<string[]> {
    const found: string[] = [];
    for (const route of table) {
      const path = `${prefix}/${route.path ?? ''}`.replace(/\/+/g, '/');
      const children = await childrenOf(route);
      if (children.length > 0) {
        found.push(...(await untitledLeaves(children, path)));
      } else if (route.redirectTo === undefined && !route.title) {
        found.push(path);
      }
    }
    return found;
  }

  it('gives every page route a title', async () => {
    expect(await untitledLeaves(routes)).toEqual([]);
  });

  it('reports a fixture leaf route without a title', async () => {
    expect(await untitledLeaves([{ path: 'x', children: [{ path: 'y', children: [] }] }])).toEqual([
      '/x/y',
    ]);
  });

  it('marks access-denied as self-managing its focus', () => {
    const layout = routes.find((r) => r.children?.some((c) => c.path === 'auth')) as Route;
    const denied = layout.children?.find((c) => c.path === 'access-denied');
    expect(denied?.data?.['selfManagedFocus']).toBe(true);
  });
});
