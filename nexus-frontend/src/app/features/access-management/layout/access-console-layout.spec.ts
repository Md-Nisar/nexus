import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { Component, ErrorHandler } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { Route, Router, Routes, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthStore } from '../../../core/auth/auth.store';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { apiErrorInterceptor } from '../../../core/http/api-error.interceptor';
import { ServiceAvailabilityNotifier } from '../../../core/http/service-availability-notifier';
import { COOL_DOWN_RANDOM } from '../../../shared/pages/unavailable/unavailable-notice';
import {
  AuthStoreStub,
  createAuthSession,
  createAuthStoreStub,
  createAuthUser,
} from '../../../shared/testing/auth.fixtures';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import type { CallerAuthorizationResponse } from '../../../shared/types/api/rbac';
import { AuthService } from '../../auth/auth.service';
import { ACCESS_MANAGEMENT_ROUTES } from '../access-management.routes';
import { CONSOLE_COPY } from '../copy/console-copy';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { AccessConsoleLayout } from './access-console-layout';

const API = 'http://localhost:1000/api';
const PROFILE_URL = `${API}/v1/users/me/authorization`;
const USER_A = '0190a000-0000-7000-8000-000000000001';
const USER_B = '0190a000-0000-7000-8000-000000000002';
const NOW = Date.parse('2026-10-23T10:00:00Z');

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

const PROFILE: CallerAuthorizationResponse = {
  userId: USER_A,
  roles: [],
  permissions: ['role:read', 'role:write'],
  isAdministrator: false,
};

@Component({ template: '<h1 data-testid="fixture-page">Fixture page</h1>' })
class FixturePage {}

/** The real console layout route, with fixture pages standing in for the area pages. */
function consoleRoutes(): Routes {
  const layout = ACCESS_MANAGEMENT_ROUTES[0] as Route;
  return [
    {
      path: 'admin/access',
      children: [
        {
          ...layout,
          children: [
            ...(layout.children ?? []),
            { path: 'roles', title: 'Roles', component: FixturePage },
            { path: 'permissions', title: 'Permissions', component: FixturePage },
            { path: 'users', title: 'Users', component: FixturePage },
          ],
        },
      ],
    },
    { path: 'elsewhere', title: 'Elsewhere', component: FixturePage },
  ];
}

describe('AccessConsoleLayout (US-020 design §6.1, §12.1)', () => {
  let http: HttpTestingController;
  let auth: AuthStoreStub;
  let handleError: ReturnType<typeof vi.fn>;
  let refresh: ReturnType<typeof vi.fn>;
  let harness: RouterTestingHarness;

  function configure(permissions: readonly string[]): void {
    handleError = vi.fn();
    refresh = vi.fn();
    auth = createAuthStoreStub({
      session: createAuthSession({ user: createAuthUser({ userId: USER_A, permissions }) }),
      permissions,
    });
    TestBed.configureTestingModule({
      providers: [
        { provide: APP_CONFIG, useValue: CONFIG },
        { provide: AuthStore, useValue: auth },
        { provide: AuthService, useValue: { refresh } },
        { provide: ErrorHandler, useValue: { handleError } },
        { provide: COOL_DOWN_RANDOM, useValue: () => 0 },
        // The interceptor's global 503 toast is not under test here.
        { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
        provideAnimationsAsync(),
        provideHttpClient(withInterceptors([apiErrorInterceptor])),
        provideHttpClientTesting(),
        provideRouter(consoleRoutes()),
      ],
    });
    http = TestBed.inject(HttpTestingController);
  }

  async function enter(url = '/admin/access/roles'): Promise<void> {
    harness = await RouterTestingHarness.create();
    await harness.navigateByUrl(url);
    harness.detectChanges();
  }

  async function settle(): Promise<void> {
    await harness.fixture.whenStable();
    harness.detectChanges();
  }

  function root(): HTMLElement {
    return harness.fixture.nativeElement as HTMLElement;
  }

  function q(testId: string): HTMLElement | null {
    return root().querySelector(`[data-testid="${testId}"]`);
  }

  /** The route-scoped store instance the layout and its pages share. */
  function profileStore(): AuthorizationProfileStore {
    return harness.fixture.debugElement
      .query(By.directive(AccessConsoleLayout))
      .injector.get(AuthorizationProfileStore);
  }

  function profileRequests(): TestRequest[] {
    return http.match(PROFILE_URL);
  }

  function answer(respond: (req: TestRequest) => void): void {
    const pending = profileRequests();
    expect(pending).toHaveLength(1);
    respond(pending[0]);
    harness.detectChanges();
  }

  function fail(status: number, code: string, headers: Record<string, string> = {}) {
    return (req: TestRequest) =>
      req.flush(
        { code, detail: `server text ${code}`, traceId: `trace-${code}` },
        { status, statusText: 'Error', headers },
      );
  }

  function tabLabels(): string[] {
    const nav = root().querySelector('nav[aria-label="Access management areas"]');
    return [...(nav?.querySelectorAll('a') ?? [])].map((a) => a.textContent?.trim() ?? '');
  }

  afterEach(() => {
    expect(refresh).not.toHaveBeenCalled();
    expect(handleError).not.toHaveBeenCalled();
    vi.useRealTimers();
  });

  describe('area sub-nav (AuthStore permissions)', () => {
    it.each([
      [
        'role:read and user:directory:read',
        ['role:read', 'user:directory:read'],
        ['Roles', 'Permissions', 'Users'],
      ],
      ['role:read only', ['role:read'], ['Roles', 'Permissions']],
      ['user:directory:read only', ['user:directory:read'], ['Users']],
    ])('shows the areas for %s', async (_name, permissions, labels) => {
      configure(permissions);
      await enter(labels[0] === 'Users' ? '/admin/access/users' : '/admin/access/roles');

      expect(tabLabels()).toEqual(labels);
      answer((req) => req.flush(PROFILE));
    });

    it('updates the areas when the JWT permissions change', async () => {
      configure(['role:read']);
      await enter();
      answer((req) => req.flush(PROFILE));

      auth.permissions.set(['role:read', 'user:directory:read']);
      harness.detectChanges();

      expect(tabLabels()).toEqual(['Roles', 'Permissions', 'Users']);
    });

    it('links each area to its route and marks the current one', async () => {
      configure(['role:read', 'user:directory:read']);
      await enter('/admin/access/permissions');
      answer((req) => req.flush(PROFILE));

      expect(q('access-area-roles')?.getAttribute('href')).toBe('/admin/access/roles');
      expect(q('access-area-users')?.getAttribute('href')).toBe('/admin/access/users');
      expect(q('access-area-permissions')?.getAttribute('aria-selected')).toBe('true');
      expect(q('access-area-roles')?.getAttribute('aria-selected')).toBe('false');
    });
  });

  describe('profile load (design §6.3, §6.5 "Console entry")', () => {
    it('reads the profile exactly once on entry and not again on child navigation', async () => {
      configure(['role:read']);
      await enter();
      answer((req) => req.flush(PROFILE));

      await TestBed.inject(Router).navigateByUrl('/admin/access/permissions');
      harness.detectChanges();

      expect(profileRequests()).toHaveLength(0);
    });

    it('renders the page while the profile loads, with no banner', async () => {
      configure(['role:read']);
      await enter();

      expect(q('fixture-page')).not.toBeNull();
      expect(q('access-console-read-only')).toBeNull();
      answer((req) => req.flush(PROFILE));
    });

    it('shows no banner and no notice once the profile is ready', async () => {
      configure(['role:read']);
      await enter();
      answer((req) => req.flush(PROFILE));

      expect(q('access-console-read-only')).toBeNull();
      expect(q('access-console-unavailable')).toBeNull();
      expect(q('fixture-page')).not.toBeNull();
      expect(profileStore().mutationsEnabled()).toBe(true);
    });

    it('reloads for user-changed when another user signs in while the console is open', async () => {
      configure(['role:read']);
      await enter();
      answer((req) => req.flush(PROFILE));

      auth.session.set(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));
      await settle();

      answer((req) => req.flush({ ...PROFILE, userId: USER_B }));
      expect(profileStore().userId()).toBe(USER_B);
    });

    it('reads nothing for a session that ends while the console is open', async () => {
      configure(['role:read']);
      await enter();
      answer((req) => req.flush(PROFILE));

      auth.session.set(null);
      await settle();

      expect(profileRequests()).toHaveLength(0);
    });
  });

  describe('read-only mode (Q8): every change off under a banner', () => {
    it('flag off (404 RESOURCE_NOT_FOUND): banner with the reason, no Retry, no reference', async () => {
      configure(['role:read']);
      await enter();
      answer(fail(404, 'RESOURCE_NOT_FOUND'));

      const banner = q('access-console-read-only') as HTMLElement;
      expect(banner).not.toBeNull();
      expect(banner.textContent).toContain(CONSOLE_COPY.readOnly.title);
      expect(banner.textContent).toContain(CONSOLE_COPY.readOnly.body);
      expect(banner.querySelector('[role="status"]')).not.toBeNull();
      expect(q('access-console-read-only-retry')).toBeNull();
      expect(q('access-console-read-only-reference')).toBeNull();
      // Read pages keep working.
      expect(q('fixture-page')).not.toBeNull();
      expect(profileStore().mutationsEnabled()).toBe(false);
    });

    it.each([
      ['500 INTERNAL_ERROR', 500, 'INTERNAL_ERROR', 'trace-INTERNAL_ERROR'],
      ['403 ACCESS_DENIED', 403, 'ACCESS_DENIED', 'trace-ACCESS_DENIED'],
    ])('%s: banner with the reason, the reference and Retry', async (_n, status, code, ref) => {
      configure(['role:read']);
      await enter();
      answer(fail(status, code));

      const banner = q('access-console-read-only') as HTMLElement;
      expect(banner.textContent).toContain(CONSOLE_COPY.readOnly.body);
      expect(q('access-console-read-only-reference')?.textContent).toContain(ref);
      expect(q('access-console-read-only-retry')).not.toBeNull();
      expect(banner.textContent).not.toContain('server text');
      expect(q('fixture-page')).not.toBeNull();
    });

    it('a dropped connection (NETWORK_ERROR): banner with Retry and the correlation reference', async () => {
      configure(['role:read']);
      await enter();
      answer((req) => req.error(new ProgressEvent('error'), { status: 0, statusText: '' }));

      expect(q('access-console-read-only')).not.toBeNull();
      expect(q('access-console-read-only-retry')).not.toBeNull();
    });

    it('Retry reads the profile once more and keeps the banner, busy, until it answers', async () => {
      configure(['role:read']);
      await enter();
      answer(fail(502, 'HTTP_ERROR'));

      const retry = q('access-console-read-only-retry')?.querySelector('button') as HTMLElement;
      retry.click();
      retry.click();
      harness.detectChanges();

      const busy = q('access-console-read-only-retry')?.querySelector('button') as HTMLElement;
      expect(q('access-console-read-only')).not.toBeNull();
      expect(busy.getAttribute('aria-disabled')).toBe('true');
      expect(busy.getAttribute('aria-busy')).toBe('true');
      answer((req) => req.flush(PROFILE));

      expect(q('access-console-read-only')).toBeNull();
      expect(profileStore().mutationsEnabled()).toBe(true);
    });

    it('has no axe violations under the banner', async () => {
      configure(['role:read', 'user:directory:read']);
      await enter();
      answer(fail(500, 'INTERNAL_ERROR'));

      await expectNoAxeViolations(root());
    });
  });

  describe('503 AUTH_005: inline UnavailableNotice (design §4.5, §12.0)', () => {
    beforeEach(() => vi.useFakeTimers({ now: NOW }));

    it('shows the read-only banner and the notice in place of the page', async () => {
      configure(['role:read']);
      await enter();
      answer(fail(503, 'AUTH_005', { 'Retry-After': '30' }));

      expect(q('access-console-read-only')).not.toBeNull();
      const notice = q('access-console-unavailable') as HTMLElement;
      expect(notice.querySelector('h1')?.textContent?.trim()).toBe(CONSOLE_COPY.unavailable.title);
      expect(notice.textContent).toContain(CONSOLE_COPY.unavailable.body);
      expect(q('unavailable-reference')?.textContent).toContain('trace-AUTH_005');
      expect(q('fixture-page')).toBeNull();
      expect(root().querySelectorAll('h1')).toHaveLength(1);
    });

    it('cools Retry down from the failure, then reads once and restores the page', async () => {
      configure(['role:read']);
      await enter();
      answer(fail(503, 'AUTH_005', { 'Retry-After': '30' }));

      const retry = () => q('unavailable-retry') as HTMLButtonElement;
      expect(retry().getAttribute('aria-disabled')).toBe('true');
      retry().click();
      expect(profileRequests()).toHaveLength(0);

      await vi.advanceTimersByTimeAsync(30_000);
      harness.detectChanges();
      expect(retry().getAttribute('aria-disabled')).toBeNull();
      retry().click();
      retry().click();
      harness.detectChanges();

      expect(q('access-console-unavailable')).not.toBeNull();
      expect(retry().getAttribute('aria-busy')).toBe('true');
      answer((req) => req.flush(PROFILE));
      await settle();

      expect(q('access-console-unavailable')).toBeNull();
      expect(q('access-console-read-only')).toBeNull();
      expect(q('fixture-page')).not.toBeNull();
    });

    it('has no axe violations with the notice shown', async () => {
      // axe schedules its own timers.
      vi.useRealTimers();
      configure(['role:read']);
      await enter();
      answer(fail(503, 'AUTH_005'));

      await expectNoAxeViolations(root());
    });
  });

  it('has no axe violations when ready', async () => {
    configure(['role:read', 'user:directory:read']);
    await enter();
    answer((req) => req.flush(PROFILE));

    await expectNoAxeViolations(root());
  });

  it('re-reads the profile on re-entry from outside the console', async () => {
    configure(['role:read']);
    await enter();
    answer((req) => req.flush(PROFILE));

    await TestBed.inject(Router).navigateByUrl('/elsewhere');
    harness.detectChanges();
    expect(profileRequests()).toHaveLength(0);

    await TestBed.inject(Router).navigateByUrl('/admin/access/roles');
    harness.detectChanges();
    answer((req) => req.flush(PROFILE));
  });
});
