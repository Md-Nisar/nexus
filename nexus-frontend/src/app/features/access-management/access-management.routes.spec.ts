import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { Component, EnvironmentInjector, runInInjectionContext } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import {
  ActivatedRouteSnapshot,
  Route,
  Router,
  RouterStateSnapshot,
  Routes,
  UrlTree,
  provideRouter,
} from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { routes } from '../../app.routes';
import { AuthStore } from '../../core/auth/auth.store';
import { APP_CONFIG, AppConfig } from '../../core/config/app-config';
import { apiErrorInterceptor } from '../../core/http/api-error.interceptor';
import { authInterceptor } from '../../core/http/auth.interceptor';
import { correlationIdInterceptor } from '../../core/http/correlation-id.interceptor';
import { createAuthSession, createAuthStoreStub } from '../../shared/testing/auth.fixtures';
import { permissionGuard } from '../../core/guards/permission.guard';
import { ACCESS_MANAGEMENT_ROUTES, firstAreaRedirect } from './access-management.routes';
import { AuthorizationProfileStore } from './data/authorization-profile.store';
import { CatalogueStore } from './data/catalogue.store';
import { RolesStore } from './data/roles.store';
import { RoleDetailStore } from './role-detail/role-detail.store';
import { CONSOLE_AREAS } from './layout/console-areas';
import { AccessConsoleLayout } from './layout/access-console-layout';

const API = 'http://localhost:1000/api';
const PROFILE_URL = `${API}/v1/users/me/authorization`;

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

@Component({ template: '<h1>Fixture page</h1>' })
class FixturePage {}

function layoutRoute(): Route {
  return ACCESS_MANAGEMENT_ROUTES[0] as Route;
}

describe('ACCESS_MANAGEMENT_ROUTES (US-020 design §4.2)', () => {
  it('has one componentful layout child at "" with the profile store as a route provider', () => {
    expect(ACCESS_MANAGEMENT_ROUTES).toHaveLength(1);
    const layout = layoutRoute();
    expect(layout.path).toBe('');
    expect(layout.component).toBe(AccessConsoleLayout);
    expect(layout.providers).toContain(AuthorizationProfileStore);
    expect(layout.canActivate).toBeUndefined();
    expect(layout.canActivateChild).toBeUndefined();
    expect(layout.canMatch).toBeUndefined();
  });

  it('sends the empty path to the first area through a guard, after authGuard, never redirectTo', () => {
    const first = layoutRoute().children?.[0] as Route;
    expect(first.path).toBe('');
    expect(first.pathMatch).toBe('full');
    expect(first.canActivate).toEqual([firstAreaRedirect]);
    // A redirect function runs in route recognition, before the shell's authGuard has restored
    // the session at cold start, so it would always see no permissions.
    expect(first.redirectTo).toBeUndefined();
  });

  it('provides the roles store on the layout route, beside the profile store', () => {
    expect(layoutRoute().providers).toContain(RolesStore);
  });

  it('provides the catalogue store on the layout route', () => {
    expect(layoutRoute().providers).toContain(CatalogueStore);
  });

  describe('permissions area (T-008)', () => {
    function permissionsRoute(): Route {
      const route = layoutRoute().children?.find((child) => child.path === 'permissions');
      expect(route).toBeDefined();
      return route as Route;
    }

    it('comes after the roles route', () => {
      const paths = layoutRoute().children?.map((child) => child.path);
      expect(paths?.indexOf('permissions')).toBeGreaterThan(paths?.indexOf('roles') ?? 99);
    });

    it('is guarded by permissionGuard with the permission its console area requires', () => {
      const route = permissionsRoute();
      const area = CONSOLE_AREAS.find((candidate) => candidate.id === 'permissions');
      expect(route.canActivate).toEqual([permissionGuard]);
      expect(route.data).toEqual({ permission: area?.permission });
      expect(area?.path).toBe('/admin/access/permissions');
      expect(route.canActivateChild).toBeUndefined();
    });

    it('has a static title and is lazy', () => {
      const route = permissionsRoute();
      expect(route.title).toBe('Permissions');
      expect(route.component).toBeUndefined();
      expect(route.loadComponent).toBeTypeOf('function');
    });
  });

  describe('role detail (T-009, design §4.2)', () => {
    function detailRoute(): Route {
      const route = layoutRoute().children?.find((child) => child.path === 'roles/:roleId');
      expect(route).toBeDefined();
      return route as Route;
    }

    it('comes after the roles route', () => {
      const paths = layoutRoute().children?.map((child) => child.path);
      expect(paths?.indexOf('roles/:roleId')).toBeGreaterThan(paths?.indexOf('roles') ?? 99);
    });

    it('is guarded by permissionGuard with role:read and has no title of its own', () => {
      const route = detailRoute();
      expect(route.canActivate).toEqual([permissionGuard]);
      expect(route.data).toEqual({ permission: 'role:read' });
      expect(route.title).toBeUndefined();
      expect(route.canActivateChild).toBeUndefined();
      expect(route.loadComponent).toBeTypeOf('function');
    });

    it('scopes the RoleDetailStore to the role route', () => {
      expect(detailRoute().providers).toEqual([RoleDetailStore]);
      expect(layoutRoute().providers).not.toContain(RoleDetailStore);
    });

    it('sends the bare role path to the permissions tab, a lazy child with a static title', () => {
      const [redirect, permissions] = detailRoute().children ?? [];
      expect(redirect).toEqual({ path: '', pathMatch: 'full', redirectTo: 'permissions' });
      expect(permissions.path).toBe('permissions');
      // Static: the role name never reaches document.title or history (DQ-26).
      expect(permissions.title).toBe('Role permissions');
      expect(permissions.loadComponent).toBeTypeOf('function');
      expect(permissions.canActivate).toBeUndefined();
    });
  });

  describe('roles area (T-007)', () => {
    function rolesRoute(): Route {
      const route = layoutRoute().children?.find((child) => child.path === 'roles');
      expect(route).toBeDefined();
      return route as Route;
    }

    it('comes after the "" redirect child, under the layout', () => {
      const paths = layoutRoute().children?.map((child) => child.path);
      expect(paths?.[0]).toBe('');
      expect(paths).toContain('roles');
    });

    it('is guarded by permissionGuard with the permission its console area requires', () => {
      const route = rolesRoute();
      const area = CONSOLE_AREAS.find((candidate) => candidate.id === 'roles');
      expect(route.canActivate).toEqual([permissionGuard]);
      expect(route.data).toEqual({ permission: area?.permission });
      expect(area?.path).toBe('/admin/access/roles');
      expect(route.canActivateChild).toBeUndefined();
    });

    it('has a static title and is lazy', () => {
      const route = rolesRoute();
      expect(route.title).toBe('Roles');
      expect(route.component).toBeUndefined();
      expect(route.loadComponent).toBeTypeOf('function');
    });
  });
});

describe('firstAreaRedirect', () => {
  function decide(permissions: readonly string[]): string {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        { provide: AuthStore, useValue: createAuthStoreStub({ permissions }) },
      ],
    });
    const result = runInInjectionContext(TestBed.inject(EnvironmentInjector), () =>
      firstAreaRedirect({} as ActivatedRouteSnapshot, {} as RouterStateSnapshot),
    );
    expect(result).toBeInstanceOf(UrlTree);
    return TestBed.inject(Router).serializeUrl(result as UrlTree);
  }

  it.each([
    ['role:read', ['role:read'], '/admin/access/roles'],
    [
      'role:read and user:directory:read',
      ['user:directory:read', 'role:read'],
      '/admin/access/roles',
    ],
    ['user:directory:read only', ['user:directory:read'], '/admin/access/users'],
  ])('sends a holder of %s to %s', (_name, permissions, target) => {
    expect(decide(permissions)).toBe(target);
  });

  it('falls back to users for anyone else (the parent guard has already denied them)', () => {
    expect(decide([])).toBe('/admin/access/users');
  });
});

describe('console entry with the real router', () => {
  let http: HttpTestingController;

  function profileRequests(): TestRequest[] {
    return http.match(PROFILE_URL);
  }

  describe('request budget (design §6.5 "Console entry")', () => {
    beforeEach(() => {
      const layout = layoutRoute();
      TestBed.configureTestingModule({
        providers: [
          { provide: APP_CONFIG, useValue: CONFIG },
          {
            provide: AuthStore,
            useValue: createAuthStoreStub({
              session: createAuthSession(),
              permissions: ['role:read', 'user:directory:read'],
            }),
          },
          provideAnimationsAsync(),
          provideHttpClient(withInterceptors([apiErrorInterceptor])),
          provideHttpClientTesting(),
          provideRouter([
            {
              path: 'admin/access',
              children: [
                {
                  ...layout,
                  children: [
                    ...(layout.children ?? []).filter(
                      (child) => child.path !== 'roles' && child.path !== 'permissions',
                    ),
                    { path: 'roles', title: 'Roles', component: FixturePage },
                    { path: 'permissions', title: 'Permissions', component: FixturePage },
                    { path: 'users', title: 'Users', component: FixturePage },
                  ],
                },
              ],
            },
            { path: 'dashboard', title: 'Dashboard', component: FixturePage },
          ] satisfies Routes),
        ],
      });
      http = TestBed.inject(HttpTestingController);
    });

    it('one GET on entry through the redirect, zero on child navigation, one on re-entry', async () => {
      const harness = await RouterTestingHarness.create();
      const router = TestBed.inject(Router);

      await harness.navigateByUrl('/admin/access');
      expect(router.url).toBe('/admin/access/roles');
      const entry = profileRequests();
      expect(entry).toHaveLength(1);
      entry[0].flush({ userId: 'user-123', roles: [], permissions: [], isAdministrator: false });

      await harness.navigateByUrl('/admin/access/permissions');
      await harness.navigateByUrl('/admin/access/users');
      await harness.navigateByUrl('/admin/access/roles');
      harness.detectChanges();
      expect(profileRequests()).toHaveLength(0);

      await harness.navigateByUrl('/dashboard');
      expect(profileRequests()).toHaveLength(0);
      await harness.navigateByUrl('/admin/access/users');
      expect(profileRequests()).toHaveLength(1);
      http.verify({ ignoreCancelled: true });
    });
  });

  describe('cold start: the redirect sees the restored session (real shell and authGuard)', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      TestBed.configureTestingModule({
        providers: [
          { provide: APP_CONFIG, useValue: CONFIG },
          provideAnimationsAsync(),
          provideHttpClient(
            withInterceptors([correlationIdInterceptor, apiErrorInterceptor, authInterceptor]),
          ),
          provideHttpClientTesting(),
          provideRouter(routes),
        ],
      });
      http = TestBed.inject(HttpTestingController);
    });

    afterEach(() => vi.useRealTimers());

    async function coldEnter(permissions: readonly string[]): Promise<number> {
      const harness = await RouterTestingHarness.create();
      const navigation = harness.navigateByUrl('/admin/access');
      let refreshes: TestRequest[] = [];
      for (let i = 0; i < 200 && refreshes.length === 0; i++) {
        await vi.advanceTimersByTimeAsync(10);
        refreshes = http.match((r) => r.method === 'POST' && r.url === `${API}/v1/auth/refresh`);
      }
      const count = refreshes.length;
      expect(count, 'the shell authGuard must start exactly one refresh').toBe(1);
      refreshes[0].flush({ accessToken: 't', tokenType: 'Bearer', expiresIn: 3600, userId: 'u1' });
      http
        .expectOne((r) => r.method === 'GET' && r.url === `${API}/v1/users/me`)
        .flush({
          userId: 'u1',
          tenantId: 't1',
          emailVerified: true,
          roles: ['USER'],
          permissions,
          tokenVersion: 1,
        });
      await vi.advanceTimersByTimeAsync(0);
      await navigation;
      return count;
    }

    it('sends a cold-started role reader to roles, after exactly one refresh', async () => {
      const refreshes = await coldEnter(['role:read', 'user:directory:read']);

      expect(refreshes).toBe(1);
      expect(TestBed.inject(Router).url).toBe('/admin/access/roles');
    });

    it('sends a cold-started directory-only reader to users', async () => {
      await coldEnter(['user:directory:read']);

      expect(TestBed.inject(Router).url).toBe('/admin/access/users');
    });
  });
});
