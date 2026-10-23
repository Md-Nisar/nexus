import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { NEVER, Subject, of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { AuthStore } from '../../auth/auth.store';
import { APP_CONFIG } from '../../config/app-config';
import { AuthService } from '../../../features/auth/auth.service';
import { NxToast } from '../../../shared/ui';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import { createAuthStoreStub } from '../../../shared/testing/auth.fixtures';
import { NAV_ITEMS, NAV_ITEMS_TOKEN, NavItem } from '../nav.config';
import { Shell } from './shell';

const GATED_NAV: readonly NavItem[] = [
  ...NAV_ITEMS.filter((item) => item.id === 'dashboard'),
  { id: 'roles', label: 'Roles', path: '/roles', icon: 'lock', anyOf: ['role:read'] },
  {
    id: 'console',
    label: 'Console',
    path: '/console',
    icon: 'admin_panel_settings',
    anyOf: ['role:read', 'user:directory:read'],
  },
];

const API = 'http://localhost:1000/api';

@Component({ template: '<h1>Page</h1>' })
class Page {}

function setup(
  logoutFn: ReturnType<typeof vi.fn> = vi.fn(() => of(undefined)),
  permissions: readonly string[] = [],
) {
  const authStore = createAuthStoreStub({ permissions });
  const toast = { success: vi.fn(), error: vi.fn() };
  TestBed.configureTestingModule({
    providers: [
      { provide: AuthStore, useValue: authStore },
      { provide: NAV_ITEMS_TOKEN, useValue: GATED_NAV },
      { provide: AuthService, useValue: { logout: logoutFn } },
      { provide: NxToast, useValue: toast },
      {
        provide: APP_CONFIG,
        useValue: {
          production: false,
          apiBaseUrl: API,
          logLevel: 'debug',
          accessConsoleEnabled: false,
        },
      },
      provideAnimationsAsync(),
      provideHttpClient(),
      provideHttpClientTesting(),
      provideRouter([
        {
          path: '',
          component: Shell,
          children: [
            { path: 'dashboard', component: Page },
            { path: 'roles', component: Page },
            { path: 'console', component: Page },
          ],
        },
      ]),
    ],
  });
  return { authStore, toast, http: TestBed.inject(HttpTestingController) };
}

async function render(url = '/dashboard') {
  const harness = await RouterTestingHarness.create();
  await harness.navigateByUrl(url);
  harness.detectChanges();
  const root = harness.routeNativeElement as HTMLElement;
  return { harness, root, router: TestBed.inject(Router) };
}

/**
 * Permission-filtered navigation is proved HERE, against fixture items supplied through
 * NAV_ITEMS_TOKEN: a single-permission item (roles) and an any-of item (console), so each persona
 * below is checked against both kinds of requirement. The e2e per-persona nav spec
 * (e2e/access-management/shell.spec.ts) covers only the real items the seeded personas reach.
 */
describe('Shell', () => {
  it('primes /v1/users/me exactly once', async () => {
    const { http } = setup();
    await render();
    http.expectOne(`${API}/v1/users/me`).flush({});
    expect(() => http.verify()).not.toThrow();
  });

  it('renders exactly one header, nav and main landmark', async () => {
    const { http } = setup();
    const { root } = await render();
    http.expectOne(`${API}/v1/users/me`).flush({});
    expect(root.querySelectorAll('header').length).toBe(1);
    expect(root.querySelectorAll('nav').length).toBe(1);
    expect(root.querySelectorAll('main').length).toBe(1);
    expect(root.querySelector('main')?.id).toBe('main-content');
    expect(root.querySelector('main h1')?.textContent).toBe('Page');
  });

  it('hides a nav item whose permission the user lacks', async () => {
    const { http } = setup();
    const { root } = await render();
    http.expectOne(`${API}/v1/users/me`).flush({});
    expect(root.querySelector('[data-testid="nav-dashboard"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="nav-roles"]')).toBeNull();
  });

  it.each([
    ['holds no permission', [], ['nav-dashboard']],
    ['holds only an unrelated permission', ['user:read'], ['nav-dashboard']],
    ['holds role:read', ['role:read'], ['nav-dashboard', 'nav-roles', 'nav-console']],
    ['holds user:directory:read', ['user:directory:read'], ['nav-dashboard', 'nav-console']],
    [
      'holds both any-of members',
      ['role:read', 'user:directory:read'],
      ['nav-dashboard', 'nav-roles', 'nav-console'],
    ],
  ])('renders exactly the permitted nav items for a persona that %s', async (_n, perms, ids) => {
    const { http } = setup(undefined, perms);
    const { root } = await render();
    http.expectOne(`${API}/v1/users/me`).flush({});
    const rendered = Array.from(root.querySelectorAll('[data-testid^="nav-"]'))
      .map((el) => el.getAttribute('data-testid'))
      .filter((id) => id !== 'nav-toggle');
    expect(rendered).toEqual(ids);
  });

  it('shows the item once the permission is held, reactively', async () => {
    const { http, authStore } = setup();
    const { harness, root } = await render();
    http.expectOne(`${API}/v1/users/me`).flush({});
    authStore.permissions.set(['role:read']);
    harness.detectChanges();
    expect(root.querySelector('[data-testid="nav-roles"]')).not.toBeNull();
  });

  it('skip link focuses main without a router navigation', async () => {
    const { http } = setup();
    const { harness, root, router } = await render();
    http.expectOne(`${API}/v1/users/me`).flush({});
    const urlBefore = router.url;
    const navigations = vi.spyOn(router, 'navigateByUrl');
    const link = root.querySelector('[data-testid="skip-link"]') as HTMLAnchorElement;
    const event = new MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    harness.detectChanges();
    expect(event.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(root.querySelector('#main-content'));
    expect(navigations).not.toHaveBeenCalled();
    expect(router.url).toBe(urlBefore);
  });

  it('makes the skip link the first focusable element', async () => {
    const { http } = setup();
    const { root } = await render();
    http.expectOne(`${API}/v1/users/me`).flush({});
    const first = root.querySelector('a, button') as HTMLElement;
    expect(first.getAttribute('data-testid')).toBe('skip-link');
  });

  it('toggles aria-expanded on the menu button and closes after navigation', async () => {
    const { http } = setup();
    const { harness, root, router } = await render();
    http.expectOne(`${API}/v1/users/me`).flush({});
    const button = root.querySelector('[data-testid="nav-toggle"]') as HTMLElement;
    expect(button.getAttribute('aria-expanded')).toBe('false');
    button.click();
    harness.detectChanges();
    expect(button.getAttribute('aria-expanded')).toBe('true');
    await router.navigateByUrl('/roles');
    harness.detectChanges();
    expect(button.getAttribute('aria-expanded')).toBe('false');
  });

  it('has no axe violations', async () => {
    const { http } = setup();
    const { root } = await render();
    http.expectOne(`${API}/v1/users/me`).flush({});
    await expect(expectNoAxeViolations(root)).resolves.toBeUndefined();
  });

  describe('logout', () => {
    async function openAndLogout(harness: { detectChanges(): void }, root: HTMLElement) {
      (root.querySelector('[data-testid="nx-menu-trigger"]') as HTMLElement).click();
      harness.detectChanges();
      await TestBed.inject(Router).navigateByUrl(TestBed.inject(Router).url);
      (document.body.querySelector('[data-testid="logout-button"]') as HTMLElement).click();
    }

    it('toasts and goes to /auth/login on success', async () => {
      const subject = new Subject<void>();
      const { http, toast } = setup(vi.fn(() => subject.asObservable()));
      const { harness, root, router } = await render();
      http.expectOne(`${API}/v1/users/me`).flush({});
      const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
      await openAndLogout(harness, root);
      subject.next();
      subject.complete();
      expect(toast.success).toHaveBeenCalledWith('You have been logged out.');
      expect(navigate).toHaveBeenCalledWith(['/auth/login']);
    });

    it('toasts an error and still goes to /auth/login on failure', async () => {
      const { http, toast } = setup(vi.fn(() => throwError(() => new Error('network'))));
      const { harness, root, router } = await render();
      http.expectOne(`${API}/v1/users/me`).flush({});
      const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
      await openAndLogout(harness, root);
      expect(toast.error).toHaveBeenCalled();
      expect(navigate).toHaveBeenCalledWith(['/auth/login']);
    });

    it('ignores a second logout while one is in flight', async () => {
      const logout = vi.fn(() => NEVER);
      const { http } = setup(logout);
      const { harness, root } = await render();
      http.expectOne(`${API}/v1/users/me`).flush({});
      const shell = harness.routeDebugElement?.componentInstance as Shell;
      shell.onLogout();
      shell.onLogout();
      expect(shell.loggingOut()).toBe(true);
      expect(logout).toHaveBeenCalledTimes(1);
      expect(root).toBeTruthy();
    });
  });
});
