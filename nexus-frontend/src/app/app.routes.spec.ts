import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Title } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { Route, Router, Routes, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { describe, it, expect } from 'vitest';
import { routes } from './app.routes';
import { AuthStore } from './core/auth/auth.store';
import { APP_CONFIG, AppConfig } from './core/config/app-config';
import { accessConsoleEnabledGuard } from './core/guards/access-console-enabled.guard';
import { anyPermissionGuard } from './core/guards/any-permission.guard';
import { authGuard } from './core/guards/auth.guard';
import { ACCESS_CONSOLE_ANY_OF } from './core/layout/nav.config';
import { createAuthSession, createAuthStoreStub } from './shared/testing/auth.fixtures';
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
  const PUBLIC_PATHS = ['auth', 'access-denied', 'design-system', 'unavailable'];

  it('declares the public layout before the guarded shell', () => {
    const publicIndex = routes.findIndex((r) => r.children?.some((c) => c.path === 'auth'));
    const shellIndex = routes.findIndex((r) => r.canActivate?.includes(authGuard));
    expect(publicIndex).toBeGreaterThanOrEqual(0);
    expect(shellIndex).toBeGreaterThan(publicIndex);
    expect(routes[0]).toMatchObject({ path: '', redirectTo: 'dashboard' });
  });

  it('keeps the public pages under an unguarded, data-free public layout', () => {
    const layout = routes.find((r) => r.children?.some((c) => c.path === 'auth')) as Route;
    expect(layout.canActivate).toBeUndefined();
    expect(layout.data).toBeUndefined();
    expect(layout.children?.map((c) => c.path)).toEqual(expect.arrayContaining(PUBLIC_PATHS));
  });

  it('pins the public layout children to exactly auth, access-denied, design-system and unavailable (US-020 TM §4.2)', () => {
    // An exact set, deliberately widened from three to four paths for the unavailable view
    // (RC-63(i), H-1). A fifth public path must fail this spec and go through security review.
    const layout = routes.find((r) => r.children?.some((c) => c.path === 'auth')) as Route;
    const paths = (layout.children ?? []).map((c) => c.path);
    expect(paths).toHaveLength(4);
    expect([...paths].sort()).toEqual(
      ['access-denied', 'auth', 'design-system', 'unavailable'].sort(),
    );
  });

  it('declares unavailable with no guard of any kind and only selfManagedFocus as data', () => {
    const layout = routes.find((r) => r.children?.some((c) => c.path === 'auth')) as Route;
    const unavailable = layout.children?.find((c) => c.path === 'unavailable') as Route;
    expect(unavailable).toBeDefined();
    expect(unavailable.canActivate).toBeUndefined();
    expect(unavailable.canActivateChild).toBeUndefined();
    expect(unavailable.canMatch).toBeUndefined();
    expect(unavailable.canDeactivate).toBeUndefined();
    expect(unavailable.resolve).toBeUndefined();
    expect(unavailable.providers).toBeUndefined();
    expect(unavailable.children).toBeUndefined();
    expect(unavailable.loadChildren).toBeUndefined();
    expect(unavailable.data).toEqual({ selfManagedFocus: true });
    expect(unavailable.title).toBe('Service unavailable');
    expect(typeof unavailable.loadComponent).toBe('function');
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

  it('declares canActivateChild on no route at all, lazy children included (US-020 RC-65)', async () => {
    async function withChildGuards(table: Routes, prefix = ''): Promise<string[]> {
      const found: string[] = [];
      for (const route of table) {
        const path = `${prefix}/${route.path ?? ''}`.replace(/\/+/g, '/');
        if (route.canActivateChild !== undefined) found.push(path);
        found.push(...(await withChildGuards(await childrenOf(route), path)));
      }
      return found;
    }
    expect(await withChildGuards(routes)).toEqual([]);
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

  it('marks unavailable as self-managing its focus', () => {
    const layout = routes.find((r) => r.children?.some((c) => c.path === 'auth')) as Route;
    const unavailable = layout.children?.find((c) => c.path === 'unavailable');
    expect(unavailable?.data?.['selfManagedFocus']).toBe(true);
  });
});

describe('access console entry route (US-020 T-001)', () => {
  function shell(): Route {
    return routes.find((r) => r.canActivate?.includes(authGuard)) as Route;
  }

  function consoleRoute(): Route | undefined {
    return shell().children?.find((c) => c.path === 'admin/access');
  }

  it('declares admin/access under the shell, before the ** catch-all', () => {
    const paths = (shell().children ?? []).map((c) => c.path);
    expect(paths).toContain('admin/access');
    expect(paths.indexOf('admin/access')).toBeLessThan(paths.indexOf('**'));
  });

  it('gates admin/access with the kill switch, anyPermissionGuard and ACCESS_CONSOLE_ANY_OF', () => {
    const route = consoleRoute() as Route;
    expect(route.canMatch).toEqual([accessConsoleEnabledGuard]);
    expect(route.canActivate).toEqual([anyPermissionGuard]);
    expect(route.data?.['anyOf']).toBe(ACCESS_CONSOLE_ANY_OF);
    expect(route.data?.['permission']).toBeUndefined();
    expect(typeof route.loadChildren).toBe('function');
    expect(route.title).toBe('Access management');
  });

  it('declares no canActivateChild on admin/access (RC-65)', () => {
    expect(consoleRoute()?.canActivateChild).toBeUndefined();
  });

  describe('real router', () => {
    function setup(accessConsoleEnabled: boolean, permissions: readonly string[]): void {
      const config: AppConfig = {
        production: false,
        apiBaseUrl: '/api',
        logLevel: 'debug',
        supportContact: null,
        accessConsoleEnabled,
      };
      TestBed.configureTestingModule({
        providers: [
          { provide: APP_CONFIG, useValue: config },
          {
            provide: AuthStore,
            useValue: createAuthStoreStub({ session: createAuthSession(), permissions }),
          },
          provideAnimationsAsync(),
          provideHttpClient(),
          provideHttpClientTesting(),
          provideRouter(routes),
        ],
      });
    }

    async function visit(url: string): Promise<{ root: HTMLElement; url: string }> {
      const harness = await RouterTestingHarness.create();
      await harness.navigateByUrl(url);
      harness.detectChanges();
      return { root: harness.routeNativeElement as HTMLElement, url: TestBed.inject(Router).url };
    }

    function heading(root: HTMLElement): string | undefined {
      return root.querySelector('h1')?.textContent?.trim();
    }

    it('renders Not Found and keeps the URL when the console is switched off', async () => {
      setup(false, [...PERMISSIONS]);
      const { root, url } = await visit('/admin/access');
      expect(url).toBe('/admin/access');
      expect(heading(root)).toBe('Page not found');
    });

    it('sends a member (no any-of permission) to /access-denied when switched on', async () => {
      setup(true, ['user:read']);
      const { root, url } = await visit('/admin/access');
      expect(url).toBe('/access-denied');
      expect(root.querySelector('[data-testid="access-denied-root"]')).not.toBeNull();
    });

    it('lets /admin/access/roles fall through to Not Found until the console routes exist', async () => {
      setup(true, ['role:read']);
      const { root, url } = await visit('/admin/access/roles');
      expect(url).toBe('/admin/access/roles');
      expect(heading(root)).toBe('Page not found');
    });

    it('pins what an entitled /admin/access renders while ACCESS_MANAGEMENT_ROUTES is empty', async () => {
      // C-1: the gated parent matches with no child, so the shell renders with an empty main
      // and the parent's own title. T-006 replaces this with the console layout.
      setup(true, ['role:read']);
      const { root, url } = await visit('/admin/access');
      expect(url).toBe('/admin/access');
      expect(root.querySelector('main')).not.toBeNull();
      expect(root.querySelector('main')?.children.length).toBe(1);
      expect(root.querySelector('main router-outlet')).not.toBeNull();
      expect(heading(root)).toBeUndefined();
      expect(TestBed.inject(Title).getTitle()).toBe('Access management');
    });
  });
});
