import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ErrorHandler } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthStore } from '../../../core/auth/auth.store';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { apiErrorInterceptor } from '../../../core/http/api-error.interceptor';
import { ServiceAvailabilityNotifier } from '../../../core/http/service-availability-notifier';
import { LoggerService } from '../../../core/logging/logger.service';
import {
  createAuthSession,
  createAuthStoreStub,
  createAuthUser,
} from '../../../shared/testing/auth.fixtures';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import type { PermissionPageResponse, PermissionResponse } from '../../../shared/types/api/rbac';
import { CONSOLE_COPY } from '../copy/console-copy';
import { CatalogueStore } from '../data/catalogue.store';
import { CataloguePage } from './catalogue.page';

const API = 'http://localhost:1000/api';
const URL0 = `${API}/v1/permissions?page=0&size=100`;

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

function permission(name: string, isSensitive = false): PermissionResponse {
  return { id: `id-${name}`, name, description: `Server description for ${name}`, isSensitive };
}

function pageOf(permissions: readonly PermissionResponse[]): PermissionPageResponse {
  return {
    data: permissions,
    page: { size: 100, number: 0, totalElements: permissions.length, totalPages: 1 },
    links: { next: null, prev: null },
  };
}

const SAMPLE = [
  permission('user:write', true),
  permission('role:read'),
  permission('tenant:read'),
  permission('user:read'),
  permission('audit:read', true),
];

function setup() {
  const handleError = vi.fn();
  TestBed.configureTestingModule({
    providers: [
      { provide: APP_CONFIG, useValue: CONFIG },
      { provide: ErrorHandler, useValue: { handleError } },
      { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
      {
        provide: AuthStore,
        useValue: createAuthStoreStub({
          session: createAuthSession({ user: createAuthUser({ userId: 'user-1' }) }),
          permissions: ['role:read'],
        }),
      },
      provideAnimationsAsync(),
      provideHttpClient(withInterceptors([apiErrorInterceptor])),
      provideHttpClientTesting(),
      provideRouter([
        { path: 'admin/access/permissions', component: CataloguePage, providers: [CatalogueStore] },
      ]),
    ],
  });
  const warn = vi.spyOn(TestBed.inject(LoggerService), 'warn');
  return {
    http: TestBed.inject(HttpTestingController),
    router: TestBed.inject(Router),
    handleError,
    warn,
  };
}

async function open(url = '/admin/access/permissions') {
  const harness = await RouterTestingHarness.create();
  await harness.navigateByUrl(url, CataloguePage);
  harness.detectChanges();
  const el = (): HTMLElement => harness.routeNativeElement as HTMLElement;
  const settle = async (): Promise<void> => {
    await harness.fixture.whenStable();
    harness.detectChanges();
  };
  return { harness, el, settle };
}

function byTestId(root: HTMLElement, id: string): HTMLElement | null {
  return root.querySelector(`[data-testid="${id}"]`);
}

function codes(root: HTMLElement): string[] {
  return Array.from(root.querySelectorAll('[data-testid="permission-code"]')).map(
    (node) => node.textContent?.trim() ?? '',
  );
}

function problem(req: TestRequest, status: number, code: string): void {
  req.flush(
    { code, detail: 'SERVER-DETAIL-TEXT', traceId: `trace-${code}` },
    { status, statusText: 'Error' },
  );
}

describe('CataloguePage (US-020 design §12.6)', () => {
  let ctx: ReturnType<typeof setup>;

  beforeEach(() => (ctx = setup()));

  afterEach(() => {
    ctx.http.verify({ ignoreCancelled: true });
    expect(ctx.handleError).not.toHaveBeenCalled();
  });

  describe('loading', () => {
    it('shows a busy skeleton before the answer', async () => {
      const { el } = await open();
      const region = byTestId(el(), 'catalogue-loading') as HTMLElement;
      expect(region.getAttribute('aria-busy')).toBe('true');
      expect(region.querySelectorAll('nx-skeleton').length).toBeGreaterThan(0);
      ctx.http.expectOne(URL0).flush(pageOf([]));
    });
  });

  describe('ready', () => {
    it('renders the header and explainer, and groups under an h2 per resource in fixed order', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(URL0).flush(pageOf(SAMPLE));
      await settle();

      expect(el().querySelector('h1')?.textContent).toContain('Permissions');
      expect(byTestId(el(), 'nx-page-header-description')?.textContent).toContain(
        CONSOLE_COPY.areas.permissions.explainer,
      );
      const headings = Array.from(el().querySelectorAll('h2')).map((h) => h.textContent?.trim());
      expect(headings).toEqual(['Tenant', 'Users', 'Roles', 'Audit']);
      expect(codes(el())).toEqual([
        'tenant:read',
        'user:read',
        'user:write',
        'role:read',
        'audit:read',
      ]);
    });

    it('shows label, mono code and the server description for each permission', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(URL0).flush(pageOf([permission('role:read')]));
      await settle();

      const item = byTestId(el(), 'permission-item') as HTMLElement;
      expect(item.textContent).toContain('Read roles and their permission assignments');
      expect(byTestId(item, 'permission-code')?.tagName).toBe('CODE');
      expect(item.textContent).toContain('Server description for role:read');
    });

    it('marks sensitive permissions with the badge and no others', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(URL0).flush(pageOf(SAMPLE));
      await settle();
      expect(el().querySelectorAll('[data-testid="sensitive-badge"]')).toHaveLength(2);
    });

    it('shows the Sensitive definition as visible text in a disclosure, not a tooltip only', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(URL0).flush(pageOf(SAMPLE));
      await settle();

      const disclosure = byTestId(el(), 'sensitive-definition') as HTMLDetailsElement;
      expect(disclosure.tagName).toBe('DETAILS');
      expect(disclosure.querySelector('summary')?.textContent).toContain(
        'What does Sensitive mean?',
      );
      expect(disclosure.textContent).toContain(CONSOLE_COPY.catalogue.sensitiveDefinition);
    });

    it('shows the count as a status', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(URL0).flush(pageOf(SAMPLE));
      await settle();
      const count = byTestId(el(), 'catalogue-count') as HTMLElement;
      expect(count.getAttribute('role')).toBe('status');
      expect(count.textContent?.trim()).toBe('5 permissions');
    });

    it('has no axe violations', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(URL0).flush(pageOf(SAMPLE));
      await settle();
      await expectNoAxeViolations(el());
    });
  });

  describe('unlabelled codes', () => {
    it('shows the raw code with an Unlabelled marker, grouped by its resource', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(URL0).flush(pageOf([permission('user:export'), permission('role:read')]));
      await settle();

      const items = Array.from(el().querySelectorAll('[data-testid="permission-item"]'));
      const unknown = items.find((i) => i.textContent?.includes('user:export')) as HTMLElement;
      expect(unknown.querySelector('[data-testid="unlabelled-badge"]')?.textContent).toContain(
        'Unlabelled',
      );
      expect(unknown.textContent).toContain('Server description for user:export');
      expect(el().querySelectorAll('[data-testid="unlabelled-badge"]')).toHaveLength(1);
      expect(Array.from(el().querySelectorAll('h2')).map((h) => h.textContent?.trim())).toEqual([
        'Users',
        'Roles',
      ]);
    });

    it('logs one warn per unlabelled code with the code only, however often it renders', async () => {
      const { harness, settle } = await open();
      ctx.http
        .expectOne(URL0)
        .flush(pageOf([permission('report:export'), permission('role:read')]));
      await settle();
      harness.detectChanges();
      await ctx.router.navigateByUrl('/admin/access/permissions?q=report');
      await settle();

      const calls = ctx.warn.mock.calls.filter(
        ([, meta]) => meta?.event === 'access_console_permission_unlabelled',
      );
      expect(calls).toHaveLength(1);
      expect(calls[0][1]?.context).toEqual({ area: 'permissions', permission: 'report:export' });
      expect(JSON.stringify(ctx.warn.mock.calls)).not.toContain('Server description');
    });
  });

  describe('search (q in the URL)', () => {
    it('reads q from the URL and matches label, code and description case-insensitively', async () => {
      const { el, settle } = await open('/admin/access/permissions?q=AUDIT');
      ctx.http.expectOne(URL0).flush(pageOf(SAMPLE));
      await settle();
      expect(codes(el())).toEqual(['audit:read']);

      await ctx.router.navigateByUrl('/admin/access/permissions?q=their%20permission');
      await settle();
      expect(codes(el())).toEqual(['role:read']);

      await ctx.router.navigateByUrl('/admin/access/permissions?q=description%20for%20tenant');
      await settle();
      expect(codes(el())).toEqual(['tenant:read']);
    });

    it('drops groups with no match and counts the matches', async () => {
      const { el, settle } = await open('/admin/access/permissions?q=user:');
      ctx.http.expectOne(URL0).flush(pageOf(SAMPLE));
      await settle();
      expect(Array.from(el().querySelectorAll('h2')).map((h) => h.textContent?.trim())).toEqual([
        'Users',
      ]);
      expect(byTestId(el(), 'catalogue-count')?.textContent?.trim()).toBe('2 permissions');
    });

    it('treats regex characters literally', async () => {
      const { el, settle } = await open('/admin/access/permissions?q=.*');
      ctx.http.expectOne(URL0).flush(pageOf(SAMPLE));
      await settle();
      expect(byTestId(el(), 'nx-empty-state')?.textContent).toContain(
        CONSOLE_COPY.catalogue.emptySearch,
      );
    });

    it('writes the query to the URL on search and removes it on clear', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(URL0).flush(pageOf(SAMPLE));
      await settle();

      const input = el().querySelector('input[type="search"]') as HTMLInputElement;
      input.value = 'tenant';
      input.dispatchEvent(new Event('input'));
      input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
      await settle();
      expect(ctx.router.url).toBe('/admin/access/permissions?q=tenant');

      (byTestId(el(), 'nx-search-clear') as HTMLElement).click();
      await settle();
      expect(ctx.router.url).toBe('/admin/access/permissions');
    });
  });

  describe('empty', () => {
    it('shows an empty state for a catalogue with nothing in it', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(URL0).flush(pageOf([]));
      await settle();
      expect(byTestId(el(), 'nx-empty-state')?.textContent).toContain(
        CONSOLE_COPY.catalogue.emptyAll,
      );
    });
  });

  describe('error', () => {
    it('shows copy-module text and a reference, never the server detail, and retries', async () => {
      const { el, settle } = await open();
      problem(ctx.http.expectOne(URL0), 500, 'INTERNAL_ERROR');
      await settle();

      const panel = byTestId(el(), 'catalogue-error') as HTMLElement;
      expect(panel.textContent).toContain('Something went wrong');
      expect(panel.textContent).not.toContain('SERVER-DETAIL-TEXT');
      expect(byTestId(el(), 'console-error-reference')?.textContent).toContain(
        'trace-INTERNAL_ERROR',
      );

      (panel.querySelector('button') as HTMLElement).click();
      ctx.http.expectOne(URL0).flush(pageOf(SAMPLE));
      await settle();
      expect(codes(el()).length).toBe(5);
    });

    it('shows the not-enabled empty state without Retry when the area is off', async () => {
      const { el, settle } = await open();
      problem(ctx.http.expectOne(URL0), 404, 'RESOURCE_NOT_FOUND');
      await settle();
      expect(byTestId(el(), 'catalogue-error')?.textContent).toContain("Roles aren't enabled");
      expect(el().querySelector('button')).toBeNull();
    });

    it('shows the wait notice for a 503 AUTH_005', async () => {
      const { el, settle } = await open();
      problem(ctx.http.expectOne(URL0), 503, 'AUTH_005');
      await settle();
      expect(byTestId(el(), 'console-error-wait')).not.toBeNull();
    });
  });
});
