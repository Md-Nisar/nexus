import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { AuthStore } from '../../core/auth/auth.store';
import { APP_CONFIG, AppConfig } from '../../core/config/app-config';
import { expectNoAxeViolations } from '../../shared/testing/axe';
import { AuthStoreStub, createAuthStoreStub } from '../../shared/testing/auth.fixtures';
import { PERMISSIONS } from '../../shared/types/permission';
import { DashboardComponent } from './dashboard.component';

const CARD = '[data-testid="dashboard-access-card"]';
const LINK = '[data-testid="dashboard-access-link"]';

describe('DashboardComponent', () => {
  function render(accessConsoleEnabled: boolean, permissions: readonly string[]) {
    const config: AppConfig = {
      production: false,
      apiBaseUrl: '/api',
      logLevel: 'debug',
      supportContact: null,
      accessConsoleEnabled,
    };
    const authStore: AuthStoreStub = createAuthStoreStub({ permissions });
    TestBed.configureTestingModule({
      providers: [
        { provide: APP_CONFIG, useValue: config },
        { provide: AuthStore, useValue: authStore },
        provideRouter([]),
      ],
    });
    const fixture = TestBed.createComponent(DashboardComponent);
    fixture.detectChanges();
    return { fixture, authStore, root: fixture.nativeElement as HTMLElement };
  }

  it('renders the dashboard root section with its heading', () => {
    const { root } = render(true, ['role:read']);
    const section = root.querySelector('[data-testid="dashboard-root"]');
    expect(section?.tagName).toBe('SECTION');
    expect(section?.querySelector('h1')?.textContent).toBe('Dashboard');
  });

  it('owns no landmark of its own (the shell provides main)', () => {
    const { root } = render(true, ['role:read']);
    expect(root.querySelector('main, header, nav')).toBeNull();
  });

  it('no longer renders a logout button (it lives in the shell user menu)', () => {
    expect(
      render(true, ['role:read']).root.querySelector('[data-testid="logout-button"]'),
    ).toBeNull();
  });

  describe('access management card', () => {
    it('is shown when the console is on and the user holds role:read', () => {
      expect(render(true, ['role:read']).root.querySelector(CARD)).not.toBeNull();
    });

    it('is shown when the console is on and the user holds user:directory:read', () => {
      expect(render(true, ['user:directory:read']).root.querySelector(CARD)).not.toBeNull();
    });

    it('is hidden for a user holding only user:read', () => {
      expect(render(true, ['user:read']).root.querySelector(CARD)).toBeNull();
    });

    it('is hidden when the console is switched off, even with every permission', () => {
      expect(render(false, [...PERMISSIONS]).root.querySelector(CARD)).toBeNull();
    });

    it('appears reactively when the permissions change', () => {
      const { fixture, authStore, root } = render(true, []);
      expect(root.querySelector(CARD)).toBeNull();
      authStore.permissions.set(['user:directory:read']);
      fixture.detectChanges();
      expect(root.querySelector(CARD)).not.toBeNull();
    });

    it('links to /admin/access', () => {
      const link = render(true, ['role:read']).root.querySelector(LINK) as HTMLAnchorElement;
      expect(link.tagName).toBe('A');
      expect(link.getAttribute('href')).toBe('/admin/access');
      expect(link.textContent?.trim()).toBe('Open access management');
    });

    it('keeps data-testid="dashboard-root" and exactly one h1 when shown', () => {
      const { root } = render(true, ['role:read']);
      expect(root.querySelector('[data-testid="dashboard-root"]')).not.toBeNull();
      expect(root.querySelectorAll('h1').length).toBe(1);
    });

    it('has no axe violations', async () => {
      const { root } = render(true, ['role:read']);
      expect(root.querySelector(CARD)).not.toBeNull();
      await expect(expectNoAxeViolations(root)).resolves.toBeUndefined();
    });
  });
});
