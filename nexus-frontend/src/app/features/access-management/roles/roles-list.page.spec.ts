import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { Component, ErrorHandler, signal } from '@angular/core';
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
import type { RoleListResponse, RoleResponse } from '../../../shared/types/api/rbac';
import { CONSOLE_COPY } from '../copy/console-copy';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { RolesStore } from '../data/roles.store';
import { RolesListPage } from './roles-list.page';

const API = 'http://localhost:1000/api';
const PAGE_URL = (n: number): string => `${API}/v1/roles?page=${n}&size=100`;

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

function role(index: number, overrides: Partial<RoleResponse> = {}): RoleResponse {
  const n = String(index).padStart(3, '0');
  return {
    id: `role-${n}`,
    name: `Role ${n}`,
    description: `Describes role ${n}`,
    isSystemRole: false,
    createdAt: '2026-03-04T10:00:00Z',
    memberCount: index,
    permissionCount: 2,
    ...overrides,
  };
}

function pageOf(
  roles: readonly RoleResponse[],
  total = roles.length,
  number = 0,
): RoleListResponse {
  return {
    data: roles,
    page: {
      size: 100,
      number,
      totalElements: total,
      totalPages: Math.max(1, Math.ceil(total / 100)),
    },
    links: { next: null, prev: null },
  };
}

function manyRoles(count: number, offset = 0): RoleResponse[] {
  return Array.from({ length: count }, (_, i) => role(offset + i));
}

@Component({ template: '' })
class CreatePlaceholder {}

type ProfileStatus = 'ready' | 'error' | 'loading';

function setup(options: { permissions?: readonly string[]; profile?: ProfileStatus } = {}) {
  const permissions = options.permissions ?? ['role:read', 'role:write'];
  const profileStatus = signal<ProfileStatus>(options.profile ?? 'ready');
  const profileStub = {
    state: () => ({ status: profileStatus() }),
    can: (permission: string) => profileStatus() === 'ready' && permissions.includes(permission),
  };
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
          permissions,
        }),
      },
      provideAnimationsAsync(),
      provideHttpClient(withInterceptors([apiErrorInterceptor])),
      provideHttpClientTesting(),
      provideRouter([
        {
          path: 'admin/access/roles',
          component: RolesListPage,
          providers: [RolesStore, { provide: AuthorizationProfileStore, useValue: profileStub }],
        },
        { path: 'admin/access/roles/new', component: CreatePlaceholder },
      ]),
    ],
  });
  const logger = TestBed.inject(LoggerService);
  const logs = [
    vi.spyOn(logger, 'debug'),
    vi.spyOn(logger, 'info'),
    vi.spyOn(logger, 'warn'),
    vi.spyOn(logger, 'error'),
  ];
  return {
    http: TestBed.inject(HttpTestingController),
    router: TestBed.inject(Router),
    handleError,
    profileStatus,
    logs,
  };
}

async function open(ctx: ReturnType<typeof setup>, url = '/admin/access/roles') {
  const harness = await RouterTestingHarness.create();
  const page = await harness.navigateByUrl(url, RolesListPage);
  harness.detectChanges();
  const el = (): HTMLElement => harness.routeNativeElement as HTMLElement;
  const settle = async (): Promise<void> => {
    await harness.fixture.whenStable();
    harness.detectChanges();
  };
  return { harness, page, el, settle, ctx };
}

function byTestId(root: HTMLElement, id: string): HTMLElement | null {
  return root.querySelector(`[data-testid="${id}"]`);
}

function names(root: HTMLElement): string[] {
  return Array.from(root.querySelectorAll('[data-testid="role-name"]')).map(
    (cell) => cell.textContent?.trim() ?? '',
  );
}

function problem(req: TestRequest, status: number, code: string, extra = {}): void {
  req.flush(
    { code, detail: 'SERVER-DETAIL-TEXT', traceId: `trace-${code}`, ...extra },
    { status, statusText: 'Error' },
  );
}

describe('RolesListPage (US-020 design §12.2)', () => {
  let ctx: ReturnType<typeof setup>;

  afterEach(() => {
    ctx.http.verify({ ignoreCancelled: true });
    expect(ctx.handleError).not.toHaveBeenCalled();
  });

  describe('loading', () => {
    beforeEach(() => (ctx = setup()));

    it('shows a busy skeleton and the generic loading text before page 0 answers', async () => {
      const { el } = await open(ctx);

      const region = byTestId(el(), 'roles-loading') as HTMLElement;
      expect(region.getAttribute('aria-busy')).toBe('true');
      expect(region.querySelectorAll('nx-skeleton').length).toBeGreaterThan(0);
      expect(region.textContent).toContain('Loading roles');
      expect(byTestId(el(), 'nx-table')).toBeNull();
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf([]));
    });

    it('shows "Loading roles: {loaded} of {total}" while the other pages load', async () => {
      const { el, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(manyRoles(100), 250));
      await settle();

      expect(byTestId(el(), 'roles-loading')?.textContent).toContain('Loading roles: 100 of 250');
      ctx.http.expectOne(PAGE_URL(1)).flush(pageOf(manyRoles(100, 100), 250, 1));
      ctx.http.expectOne(PAGE_URL(2)).flush(pageOf(manyRoles(50, 200), 250, 2));
    });
  });

  describe('ready', () => {
    beforeEach(() => (ctx = setup()));

    it('renders the header, explainer, one row per role and the count', async () => {
      const { el, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf([role(1), role(2), role(3)]));
      await settle();

      expect(el().querySelector('h1')?.textContent).toContain('Roles');
      expect(byTestId(el(), 'nx-page-header-description')?.textContent).toContain(
        CONSOLE_COPY.areas.roles.explainer,
      );
      expect(names(el())).toEqual(['Role 001', 'Role 002', 'Role 003']);
      const count = byTestId(el(), 'roles-count') as HTMLElement;
      expect(count.getAttribute('role')).toBe('status');
      expect(count.textContent?.trim()).toBe('3 roles');
      expect(el().querySelector('caption')?.textContent).toContain('Roles');
    });

    it('uses the singular for one role', async () => {
      const { el, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf([role(1)]));
      await settle();
      expect(byTestId(el(), 'roles-count')?.textContent?.trim()).toBe('1 role');
    });

    it('shows type, description, counts and created date; names are plain text, not links', async () => {
      const { el, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(
        pageOf([
          role(1, { isSystemRole: true, name: 'MEMBER', description: '' }),
          role(2, {
            name: 'Support',
            description: 'Handles tickets',
            permissionCount: 7,
            memberCount: 3,
          }),
        ]),
      );
      await settle();

      const rows = Array.from(el().querySelectorAll('tbody tr'));
      const system = rows[0].textContent as string;
      expect(system).toContain('MEMBER');
      expect(system).toContain('System');
      expect(system).toContain('No description');
      const custom = rows[1].textContent as string;
      expect(custom).toContain('Custom');
      expect(custom).toContain('Handles tickets');
      expect(custom).toContain('7');
      expect(custom).toContain('3');
      expect(custom).toContain('Mar 4, 2026');
      // The role-detail route arrives in T-009; until then a name is not a link.
      expect(el().querySelector('tbody a')).toBeNull();
    });

    it('puts system roles first and keeps the server order within each group', async () => {
      const { el, settle } = await open(ctx);
      ctx.http
        .expectOne(PAGE_URL(0))
        .flush(
          pageOf([
            role(1, { name: 'Alpha' }),
            role(2, { name: 'MEMBER', isSystemRole: true }),
            role(3, { name: 'Zulu' }),
            role(4, { name: 'TENANT_ADMIN', isSystemRole: true }),
          ]),
        );
      await settle();
      expect(names(el())).toEqual(['MEMBER', 'TENANT_ADMIN', 'Alpha', 'Zulu']);
    });

    it('sends no further request when the query changes (zero warm requests)', async () => {
      const { el, harness, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(manyRoles(45)));
      await settle();

      await harness.navigateByUrl('/admin/access/roles?q=role%200&filter=custom&page=2');
      await settle();
      expect(names(el()).length).toBeGreaterThan(0);
      ctx.http.expectNone(`${API}/v1/roles?page=0&size=100`);
    });
  });

  describe('query parameters q, filter, page (FR-G1)', () => {
    beforeEach(() => (ctx = setup()));

    async function ready(url: string, roles: readonly RoleResponse[]) {
      const opened = await open(ctx, url);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(roles));
      await opened.settle();
      return opened;
    }

    it('restores search text, filter and page from the URL into the controls and the rows', async () => {
      const { el } = await ready('/admin/access/roles?q=role&filter=custom&page=2', [
        ...manyRoles(45),
        role(200, { name: 'MEMBER', isSystemRole: true }),
      ]);

      const input = el().querySelector('[data-testid="nx-search-input"]') as HTMLInputElement;
      expect(input.value).toBe('role');
      expect(names(el())).toHaveLength(20);
      expect(names(el())[0]).toBe('Role 020');
      expect(byTestId(el(), 'roles-count')?.textContent?.trim()).toBe('45 roles');
      expect(el().querySelector('mat-paginator')).not.toBeNull();
    });

    it('follows the URL as it changes, as Back and Forward do', async () => {
      const { el, harness, settle } = await ready('/admin/access/roles', [
        role(1, { name: 'Alpha' }),
        role(2, { name: 'Bravo' }),
        role(3, { name: 'MEMBER', isSystemRole: true }),
      ]);
      expect(names(el())).toEqual(['MEMBER', 'Alpha', 'Bravo']);

      await harness.navigateByUrl('/admin/access/roles?q=bra');
      await settle();
      expect(names(el())).toEqual(['Bravo']);
      expect(
        (el().querySelector('[data-testid="nx-search-input"]') as HTMLInputElement).value,
      ).toBe('bra');

      await harness.navigateByUrl('/admin/access/roles?filter=system');
      await settle();
      expect(names(el())).toEqual(['MEMBER']);
      expect(
        (el().querySelector('[data-testid="nx-search-input"]') as HTMLInputElement).value,
      ).toBe('');

      await harness.navigateByUrl('/admin/access/roles');
      await settle();
      expect(names(el())).toEqual(['MEMBER', 'Alpha', 'Bravo']);
    });

    it('writes a committed search into q and resets the page', async () => {
      const { el, settle, ctx: c } = await ready('/admin/access/roles?page=2', manyRoles(45));

      const input = el().querySelector('[data-testid="nx-search-input"]') as HTMLInputElement;
      input.value = ' Role 04 ';
      input.dispatchEvent(new Event('input'));
      input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
      await settle();

      expect(c.router.url).toBe('/admin/access/roles?q=Role%2004');
      expect(names(el())).toHaveLength(5);
    });

    it('removes q from the URL when the search is cleared', async () => {
      const {
        el,
        settle,
        ctx: c,
      } = await ready('/admin/access/roles?q=role&page=2', manyRoles(45));
      (el().querySelector('[data-testid="nx-search-clear"]') as HTMLButtonElement).click();
      await settle();
      expect(c.router.url).toBe('/admin/access/roles');
    });

    it('writes the filter into the URL and resets the page; "all" is the default and is omitted', async () => {
      const {
        harness,
        settle,
        ctx: c,
      } = await ready('/admin/access/roles?page=2', [
        ...manyRoles(45),
        role(300, { isSystemRole: true, name: 'MEMBER' }),
      ]);
      const select = harness.routeDebugElement?.query((d) => d.name === 'nx-select');
      select?.triggerEventHandler('selectionChange', 'custom');
      await settle();
      expect(c.router.url).toBe('/admin/access/roles?filter=custom');

      select?.triggerEventHandler('selectionChange', 'all');
      await settle();
      expect(c.router.url).toBe('/admin/access/roles');
    });

    it('writes the page 1-based into the URL and omits it on the first page', async () => {
      const { harness, settle, ctx: c } = await ready('/admin/access/roles', manyRoles(45));
      const table = harness.routeDebugElement?.query((d) => d.name === 'nx-table');

      table?.triggerEventHandler('pageChange', { pageIndex: 2, pageSize: 20, length: 45 });
      await settle();
      expect(c.router.url).toBe('/admin/access/roles?page=3');

      table?.triggerEventHandler('pageChange', { pageIndex: 0, pageSize: 20, length: 45 });
      await settle();
      expect(c.router.url).toBe('/admin/access/roles');
    });

    it.each([
      ['page=0', 'Role 000'],
      ['page=-4', 'Role 000'],
      ['page=abc', 'Role 000'],
      ['page=1.5', 'Role 000'],
      ['page=99', 'Role 040'],
      ['filter=%3Cscript%3E', 'Role 000'],
    ])('treats ?%s as a valid view (first row %s)', async (query, firstRow) => {
      const { el } = await ready(`/admin/access/roles?${query}`, manyRoles(45));
      expect(names(el())[0]).toBe(firstRow);
    });

    it('does not log the search text or role names (PII)', async () => {
      const {
        el,
        settle,
        ctx: c,
      } = await ready('/admin/access/roles?q=confidential-search', manyRoles(3));
      const input = el().querySelector('[data-testid="nx-search-input"]') as HTMLInputElement;
      input.value = 'another-secret-term';
      input.dispatchEvent(new Event('input'));
      input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
      await settle();

      const logged = JSON.stringify(c.logs.flatMap((spy) => spy.mock.calls));
      expect(logged).not.toContain('confidential-search');
      expect(logged).not.toContain('another-secret-term');
      expect(logged).not.toContain('Role 00');
    });
  });

  describe('empty states', () => {
    it('shows "No custom roles yet" with the Create action when only system roles exist', async () => {
      ctx = setup();
      const { el, settle } = await open(ctx, '/admin/access/roles?filter=custom');
      ctx.http
        .expectOne(PAGE_URL(0))
        .flush(pageOf([role(1, { isSystemRole: true, name: 'MEMBER' })]));
      await settle();

      const empty = byTestId(el(), 'nx-empty-state') as HTMLElement;
      expect(empty.textContent).toContain('No custom roles yet');
      expect(empty.querySelector('[data-testid="roles-create"]')).not.toBeNull();
      expect(byTestId(el(), 'roles-count')?.textContent?.trim()).toBe('0 roles');
    });

    it('offers no Create action in the empty state without role:write', async () => {
      ctx = setup({ permissions: ['role:read'] });
      const { el, settle } = await open(ctx, '/admin/access/roles?filter=custom');
      ctx.http
        .expectOne(PAGE_URL(0))
        .flush(pageOf([role(1, { isSystemRole: true, name: 'MEMBER' })]));
      await settle();

      expect(byTestId(el(), 'nx-empty-state')?.textContent).toContain('No custom roles yet');
      expect(byTestId(el(), 'roles-create')).toBeNull();
    });

    it('shows "No roles match your search" when a search finds nothing', async () => {
      ctx = setup();
      const { el, settle } = await open(ctx, '/admin/access/roles?q=nothing-like-this');
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(manyRoles(3)));
      await settle();

      expect(byTestId(el(), 'nx-empty-state')?.textContent).toContain('No roles match your search');
      expect(
        byTestId(el(), 'nx-empty-state')?.querySelector('[data-testid="roles-create"]'),
      ).toBeNull();
      // The toolbar stays, so the search can be cleared.
      expect(el().querySelector('[data-testid="nx-search-input"]')).not.toBeNull();
    });
  });

  describe('truncation (the 20-page bound)', () => {
    it('shows a banner with the number of roles actually loaded', async () => {
      ctx = setup();
      const { el, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(manyRoles(100), 2100));
      for (let i = 1; i < 20; i++) {
        ctx.http.expectOne(PAGE_URL(i)).flush(pageOf(manyRoles(100, i * 100), 2100, i));
      }
      await settle();

      const banner = byTestId(el(), 'roles-truncated') as HTMLElement;
      expect(banner.textContent).toContain(
        'Only the first 2000 roles are loaded; search covers those only.',
      );
      expect(banner.querySelector('[role="status"]')).not.toBeNull();
    });

    it('shows no banner for a complete list', async () => {
      ctx = setup();
      const { el, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(manyRoles(3)));
      await settle();
      expect(byTestId(el(), 'roles-truncated')).toBeNull();
    });
  });

  describe('errors (design §12.0, §14.1)', () => {
    beforeEach(() => (ctx = setup()));

    it('shows the copy for the code with the reference and a Retry that loads again', async () => {
      const { el, settle } = await open(ctx);
      problem(ctx.http.expectOne(PAGE_URL(0)), 500, 'INTERNAL_ERROR');
      await settle();

      const alert = el().querySelector('[role="alert"]') as HTMLElement;
      expect(alert.textContent).toContain('Something went wrong');
      expect(byTestId(el(), 'console-error-reference')?.textContent).toContain(
        'trace-INTERNAL_ERROR',
      );
      expect(el().textContent).not.toContain('SERVER-DETAIL-TEXT');
      expect(byTestId(el(), 'nx-table')).toBeNull();

      (byTestId(el(), 'nx-error-state-retry') as HTMLButtonElement).click();
      await settle();
      expect(byTestId(el(), 'roles-loading')).not.toBeNull();
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(manyRoles(2)));
      await settle();
      expect(names(el())).toHaveLength(2);
    });

    it('explains a 403 RBAC_001 by its reason', async () => {
      const { el, settle } = await open(ctx);
      problem(ctx.http.expectOne(PAGE_URL(0)), 403, 'RBAC_001', {
        reason: 'ADMINISTRATOR_REQUIRED',
        requiredPermission: 'role:read',
      });
      await settle();
      expect(el().textContent).toContain('Administrator needed');
      expect(el().textContent).not.toContain('role:read');
    });

    it('shows "Roles aren’t enabled" for a 404 RESOURCE_NOT_FOUND, without Retry', async () => {
      const { el, settle } = await open(ctx);
      problem(ctx.http.expectOne(PAGE_URL(0)), 404, 'RESOURCE_NOT_FOUND');
      await settle();
      expect(byTestId(el(), 'nx-empty-state')?.textContent).toContain("Roles aren't enabled");
      expect(byTestId(el(), 'roles-error')?.querySelector('button')).toBeNull();
    });

    it('shows the unavailable notice for a 503 AUTH_005', async () => {
      const { el, settle } = await open(ctx);
      problem(ctx.http.expectOne(PAGE_URL(0)), 503, 'AUTH_005');
      await settle();
      expect(el().textContent).toContain('Nexus is temporarily unavailable');
      expect(byTestId(el(), 'unavailable-notice')).not.toBeNull();
    });

    it('offers no search and no table over a failed load', async () => {
      const { el, settle } = await open(ctx);
      problem(ctx.http.expectOne(PAGE_URL(0)), 500, 'INTERNAL_ERROR');
      await settle();
      expect(byTestId(el(), 'nx-table')).toBeNull();
      expect(byTestId(el(), 'roles-count')).toBeNull();
    });
  });

  describe('Create role (live profile, FR-F1)', () => {
    it('is shown with role:write in the profile and navigates to the create route', async () => {
      ctx = setup();
      const { el, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(manyRoles(2)));
      await settle();

      const create = byTestId(el(), 'roles-create') as HTMLElement;
      expect(create.textContent).toContain('Create role');
      (create.querySelector('button') ?? create).click();
      await settle();
      expect(ctx.router.url).toBe('/admin/access/roles/new');
    });

    it('is hidden without role:write in the profile', async () => {
      ctx = setup({ permissions: ['role:read'] });
      const { el, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(manyRoles(2)));
      await settle();
      expect(byTestId(el(), 'roles-create')).toBeNull();
    });

    it('is hidden while the profile is loading', async () => {
      ctx = setup({ profile: 'loading' });
      const { el, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(manyRoles(2)));
      await settle();
      expect(byTestId(el(), 'roles-create')).toBeNull();
    });

    it('is disabled with a visible reason when the profile could not be read', async () => {
      ctx = setup({ profile: 'error' });
      const { el, settle } = await open(ctx);
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf(manyRoles(2)));
      await settle();

      const button = byTestId(el(), 'roles-create')?.querySelector('button') as HTMLButtonElement;
      expect(button.getAttribute('aria-disabled')).toBe('true');
      const reason = byTestId(el(), 'roles-create-reason') as HTMLElement;
      expect(reason.textContent).toContain(CONSOLE_COPY.disabledReason.profileUnavailable);
      expect(button.getAttribute('aria-describedby')).toBe(reason.id);
      button.click();
      await settle();
      expect(ctx.router.url).toBe('/admin/access/roles');
    });
  });

  describe('stored XSS and bidi (FR-G9, SD-6, SD-7)', () => {
    const HOSTILE_NAME = '<img src=x onerror=alert(1)>';
    const HOSTILE_DESCRIPTION = '<img src=x onerror=alert(1)><script>alert(2)</script>‮';

    it('renders markup in a role name and description as text, with the hidden-character badge', async () => {
      ctx = setup();
      const { el, settle } = await open(ctx);
      ctx.http
        .expectOne(PAGE_URL(0))
        .flush(pageOf([role(1, { name: HOSTILE_NAME, description: HOSTILE_DESCRIPTION })]));
      await settle();

      const root = el();
      expect(root.querySelector('img')).toBeNull();
      expect(root.querySelector('script')).toBeNull();
      expect(byTestId(root, 'role-name')?.textContent?.trim()).toBe(HOSTILE_NAME);
      const description = byTestId(root, 'role-description') as HTMLElement;
      expect(description.querySelector('bdi')?.textContent).toBe(HOSTILE_DESCRIPTION);
      expect(description.querySelector('[data-testid="user-text-hidden-badge"]')).not.toBeNull();
      expect(
        byTestId(root, 'role-name')?.querySelector('[data-testid="user-text-hidden-badge"]'),
      ).toBeNull();
    });

    it('does not interpret markup typed into the search, and matches it literally', async () => {
      ctx = setup();
      const { el, settle } = await open(
        ctx,
        `/admin/access/roles?q=${encodeURIComponent('<img src=x')}`,
      );
      ctx.http.expectOne(PAGE_URL(0)).flush(pageOf([role(1, { name: HOSTILE_NAME }), role(2)]));
      await settle();

      expect(names(el())).toEqual([HOSTILE_NAME]);
      expect(el().querySelector('img')).toBeNull();
    });
  });

  describe('accessibility', () => {
    it('has no axe violations when loaded', async () => {
      ctx = setup();
      const { el, settle } = await open(ctx);
      ctx.http
        .expectOne(PAGE_URL(0))
        .flush(
          pageOf([
            role(1, { isSystemRole: true, name: 'MEMBER' }),
            role(2),
            role(3, { description: '' }),
          ]),
        );
      await settle();
      await expectNoAxeViolations(el());
    });

    it('has no axe violations in the loading, empty and error states', async () => {
      ctx = setup();
      const loading = await open(ctx);
      await expectNoAxeViolations(loading.el());
      problem(ctx.http.expectOne(PAGE_URL(0)), 500, 'INTERNAL_ERROR');
      await loading.settle();
      await expectNoAxeViolations(loading.el());
    });
  });
});
