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
import type {
  PermissionPageResponse,
  PermissionResponse,
  RoleResponse,
} from '../../../shared/types/api/rbac';
import { CONSOLE_COPY } from '../copy/console-copy';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore } from '../data/catalogue.store';
import { RoleDetailPage } from './role-detail.page';
import { RoleDetailStore } from './role-detail.store';
import { RolePermissionsTab } from './role-permissions.tab';

const API = 'http://localhost:1000/api';
const ROLE_ID = '0190a000-0000-7000-8000-0000000000b1';
const OTHER_ROLE_ID = '0190a000-0000-7000-8000-0000000000b2';
const CATALOGUE_URL = `${API}/v1/permissions?page=0&size=100`;
const roleUrl = (id = ROLE_ID): string => `${API}/v1/roles/${id}`;
const setUrl = (id = ROLE_ID): string => `${API}/v1/roles/${id}/permissions`;

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

function role(overrides: Partial<RoleResponse> = {}): RoleResponse {
  return {
    id: ROLE_ID,
    name: 'Support',
    description: 'Handles tickets',
    isSystemRole: false,
    createdAt: '2026-01-01T00:00:00Z',
    memberCount: 3,
    permissionCount: 2,
    ...overrides,
  };
}

function permission(name: string, isSensitive = false): PermissionResponse {
  return { id: `id-${name}`, name, description: `Server description for ${name}`, isSensitive };
}

const CATALOGUE = [
  permission('role:read'),
  permission('role:write', true),
  permission('user:read'),
  permission('tenant:read'),
];

function cataloguePage(): PermissionPageResponse {
  return {
    data: CATALOGUE,
    page: { size: 100, number: 0, totalElements: CATALOGUE.length, totalPages: 1 },
    links: { next: null, prev: null },
  };
}

@Component({ template: '<h1>Placeholder</h1>' })
class Placeholder {}

type ProfileStatus = 'ready' | 'error' | 'loading';

function setup(options: { permissions?: readonly string[]; profile?: ProfileStatus } = {}) {
  const permissions = options.permissions ?? ['role:read', 'role:write'];
  const profileStatus = signal<ProfileStatus>(options.profile ?? 'ready');
  const profileStub = {
    state: () => ({ status: profileStatus() }),
    can: (p: string) => profileStatus() === 'ready' && permissions.includes(p),
    load: vi.fn(),
    reload: vi.fn(),
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
          path: 'admin/access',
          providers: [
            CatalogueStore,
            { provide: AuthorizationProfileStore, useValue: profileStub },
          ],
          children: [
            { path: 'roles', component: Placeholder },
            { path: 'roles/new', component: Placeholder },
            {
              path: 'roles/:roleId',
              component: RoleDetailPage,
              providers: [RoleDetailStore],
              children: [
                { path: '', pathMatch: 'full', redirectTo: 'permissions' },
                { path: 'permissions', component: RolePermissionsTab },
                { path: 'edit', component: Placeholder },
              ],
            },
          ],
        },
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
    profileStub,
    logs,
  };
}

type Ctx = ReturnType<typeof setup>;

async function open(url = `/admin/access/roles/${ROLE_ID}`) {
  const harness = await RouterTestingHarness.create();
  await harness.navigateByUrl(url);
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

function text(node: Element | null | undefined): string {
  return node?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
}

function button(root: HTMLElement, id: string): HTMLButtonElement | null {
  return byTestId(root, id)?.querySelector('button') ?? null;
}

function problem(req: TestRequest, status: number, code: string, headers = {}): void {
  req.flush(
    { code, detail: `server text for ${code}`, traceId: `trace-${code}` },
    { status, statusText: 'Error', headers },
  );
}

/** Answers the two role GETs, and the catalogue GET when it is pending. */
function answer(
  ctx: Ctx,
  options: {
    role?: RoleResponse;
    granted?: readonly string[];
    etag?: string | null;
    correlationId?: string;
    id?: string;
  } = {},
): void {
  const id = options.id ?? ROLE_ID;
  ctx.http.expectOne(roleUrl(id)).flush(options.role ?? role({ id }));
  const headers: Record<string, string> = {};
  const etag = options.etag === undefined ? '"v1"' : options.etag;
  if (etag !== null) headers['ETag'] = etag;
  if (options.correlationId) headers['X-Correlation-Id'] = options.correlationId;
  const granted = options.granted ?? ['role:read', 'user:read'];
  ctx.http
    .expectOne(setUrl(id))
    .flush({ data: CATALOGUE.filter((p) => granted.includes(p.name)) }, { headers });
  for (const req of ctx.http.match(CATALOGUE_URL)) req.flush(cataloguePage());
}

describe('RoleDetailPage (US-020 design §12.3)', () => {
  let ctx: Ctx;

  afterEach(() => {
    ctx.http.verify();
    // RC-73: no load failure ever reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
  });

  describe('as a role editor', () => {
    beforeEach(() => (ctx = setup()));

    it('shows a loading state with a focusable h1 before the role arrives', async () => {
      const { el } = await open();

      const title = byTestId(el(), 'role-detail-title');
      expect(title?.tagName).toBe('H1');
      expect(title?.getAttribute('tabindex')).toBe('-1');
      expect(text(title)).toBe(CONSOLE_COPY.roleDetail.loadingTitle);
      expect(byTestId(el(), 'role-detail-loading')?.getAttribute('aria-busy')).toBe('true');
      answer(ctx);
    });

    it('request budget (design §6.5, cold): the role, the set and the catalogue, once each', async () => {
      await open();

      expect(ctx.http.match(roleUrl())).toHaveLength(1);
      expect(ctx.http.match(setUrl())).toHaveLength(1);
      const catalogue = ctx.http.match(CATALOGUE_URL);
      expect(catalogue).toHaveLength(1);
      catalogue[0].flush(cataloguePage());
      // No profile read: the console layout owns it.
      expect(ctx.profileStub.load).not.toHaveBeenCalled();
      expect(ctx.profileStub.reload).not.toHaveBeenCalled();
    });

    it('request budget (warm): two GETs for another role and for a return visit', async () => {
      const { harness, settle } = await open();
      answer(ctx);
      await settle();

      await harness.navigateByUrl(`/admin/access/roles/${OTHER_ROLE_ID}`);
      expect(ctx.http.match(CATALOGUE_URL)).toHaveLength(0);
      answer(ctx, { id: OTHER_ROLE_ID });
      await settle();

      await harness.navigateByUrl('/admin/access/roles');
      await harness.navigateByUrl(`/admin/access/roles/${ROLE_ID}`);
      expect(ctx.http.match(CATALOGUE_URL)).toHaveLength(0);
      answer(ctx);
    });

    it('redirects the bare role path to the permissions tab', async () => {
      await open();
      answer(ctx);

      expect(ctx.router.url).toBe(`/admin/access/roles/${ROLE_ID}/permissions`);
    });

    it('renders the header: name, type, description, counts, Updated and Refresh', async () => {
      const { el, settle } = await open();
      answer(ctx);
      await settle();

      const title = byTestId(el(), 'role-detail-title');
      expect(title?.querySelector('bdi')?.textContent).toBe('Support');
      expect(byTestId(el(), 'system-role-badge')?.getAttribute('data-kind')).toBe('custom');
      const description = byTestId(el(), 'role-detail-description');
      expect(description?.getAttribute('dir')).toBe('auto');
      expect(text(description)).toBe('Handles tickets');
      expect(text(byTestId(el(), 'role-detail-counts'))).toBe('2 permissions · 3 members');
      expect(text(byTestId(el(), 'role-detail-updated'))).toBe('Updated now');
      expect(byTestId(el(), 'role-detail-updated')?.querySelector('time')).not.toBeNull();
      expect(text(button(el(), 'role-detail-refresh')?.querySelector('.nx-btn__label'))).toBe(
        'Refresh',
      );
    });

    it('uses the singular for one permission and one member, and says when there is no description', async () => {
      const { el, settle } = await open();
      answer(ctx, { role: role({ memberCount: 1, description: '' }), granted: ['role:read'] });
      await settle();

      expect(text(byTestId(el(), 'role-detail-counts'))).toBe('1 permission · 1 member');
      expect(text(byTestId(el(), 'role-detail-description'))).toBe(
        CONSOLE_COPY.roles.noDescription,
      );
    });

    it('shows the breadcrumb Access management › Roles › {role name}, the name isolated', async () => {
      const { el, settle } = await open();
      answer(ctx);
      await settle();

      const crumbs = byTestId(el(), 'nx-breadcrumb');
      const links = Array.from(crumbs?.querySelectorAll('a') ?? []);
      expect(links.map((a) => [text(a), a.getAttribute('href')])).toEqual([
        ['Access management', '/admin/access'],
        ['Roles', '/admin/access/roles'],
      ]);
      const current = crumbs?.querySelector('[aria-current="page"]');
      expect(current?.querySelector('bdi')?.textContent).toBe('Support');
    });

    it('shows the read-only matrix in the Permissions tab', async () => {
      const { el, settle } = await open();
      answer(ctx);
      await settle();

      const tabs = el().querySelector('nav[aria-label="Role sections"]');
      expect(text(tabs)).toBe('Permissions');
      const matrix = byTestId(el(), 'permission-matrix');
      expect(text(matrix?.querySelector('caption'))).toBe('Permissions granted by Support');
      const granted = Array.from(
        matrix?.querySelectorAll('table [data-testid="matrix-status"]') ?? [],
      ).map((s) => s.getAttribute('data-granted'));
      expect(granted.filter((g) => g === 'true')).toHaveLength(2);
      expect(granted).toHaveLength(CATALOGUE.length);
    });

    it('shows the zero-permissions empty state instead of the matrix', async () => {
      const { el, settle } = await open();
      answer(ctx, { granted: [] });
      await settle();

      expect(text(byTestId(el(), 'role-permissions-empty'))).toContain(
        'This role grants no access yet',
      );
      expect(byTestId(el(), 'permission-matrix')).toBeNull();
    });

    it('offers Edit permissions and Clone on a custom role, and they navigate', async () => {
      const { el, settle } = await open();
      answer(ctx);
      await settle();

      const edit = button(el(), 'role-edit');
      expect(text(edit?.querySelector('.nx-btn__label'))).toBe('Edit permissions');
      expect(edit?.getAttribute('aria-disabled')).toBeNull();
      edit?.click();
      await settle();
      expect(ctx.router.url).toBe(`/admin/access/roles/${ROLE_ID}/edit`);

      await ctx.router.navigateByUrl(`/admin/access/roles/${ROLE_ID}/permissions`);
      await settle();
      button(el(), 'role-clone')?.click();
      await settle();
      expect(ctx.router.url).toBe(`/admin/access/roles/new?from=${ROLE_ID}`);
    });

    it('renders no edit control at all on a system role, only the banner and Clone (FR-B7)', async () => {
      const { el, settle } = await open();
      answer(ctx, { role: role({ isSystemRole: true, name: 'TENANT_ADMIN' }) });
      await settle();

      expect(byTestId(el(), 'role-edit')).toBeNull();
      expect(byTestId(el(), 'role-edit-reason')).toBeNull();
      expect(el().textContent).not.toContain('Edit permissions');
      expect(text(byTestId(el(), 'role-system-banner'))).toContain(
        "This is a system role. Its permissions can't be changed. You can clone it to make a custom role.",
      );
      expect(byTestId(el(), 'system-role-badge')?.getAttribute('data-kind')).toBe('system');
      expect(button(el(), 'role-clone')).not.toBeNull();
    });

    it('does not show the ETag banner on a system role even when the tag is weak', async () => {
      const { el, settle } = await open();
      answer(ctx, { role: role({ isSystemRole: true }), etag: 'W/"v1"' });
      await settle();

      expect(byTestId(el(), 'role-etag-banner')).toBeNull();
    });

    describe.each([
      ['weak', 'W/"v1"'],
      ['missing', null],
    ])('with a %s ETag (design §7.2)', (_kind, etag) => {
      it('keeps Edit focusable but aria-disabled, with the visible reason linked', async () => {
        const { el, settle } = await open();
        answer(ctx, { etag, correlationId: 'corr-7' });
        await settle();

        const edit = button(el(), 'role-edit');
        expect(edit?.disabled).toBe(false);
        expect(edit?.getAttribute('aria-disabled')).toBe('true');
        const reason = byTestId(el(), 'role-edit-reason');
        expect(text(reason)).toBe(CONSOLE_COPY.disabledReason.etagUnusable);
        expect(edit?.getAttribute('aria-describedby')?.split(' ')).toContain(reason?.id);

        edit?.click();
        await settle();
        expect(ctx.router.url).toBe(`/admin/access/roles/${ROLE_ID}/permissions`);
      });

      it('explains it in a banner with the reference, and keeps the read view', async () => {
        const { el, settle } = await open();
        answer(ctx, { etag, correlationId: 'corr-7' });
        await settle();

        const banner = byTestId(el(), 'role-etag-banner');
        expect(text(banner)).toContain('Saving is unavailable');
        expect(text(banner)).toContain(
          'A network component changed the version information Nexus needs to save safely. You can still view this role.',
        );
        expect(text(byTestId(el(), 'role-etag-reference'))).toBe('Reference: corr-7');
        expect(byTestId(el(), 'permission-matrix')).not.toBeNull();
        expect(button(el(), 'role-clone')?.getAttribute('aria-disabled')).toBeNull();
      });
    });

    it('shows the banner without a reference line when the GET carried no correlation id', async () => {
      const { el, settle } = await open();
      answer(ctx, { etag: 'W/"v1"' });
      await settle();

      expect(byTestId(el(), 'role-etag-banner')).not.toBeNull();
      expect(byTestId(el(), 'role-etag-reference')).toBeNull();
    });

    it('Refresh re-reads the role and the set (2 GETs), not the catalogue or the profile', async () => {
      const { el, settle } = await open();
      answer(ctx);
      await settle();

      button(el(), 'role-detail-refresh')?.click();
      await settle();
      expect(button(el(), 'role-detail-refresh')?.getAttribute('aria-busy')).toBe('true');
      expect(byTestId(el(), 'permission-matrix')).not.toBeNull();
      expect(ctx.http.match(CATALOGUE_URL)).toHaveLength(0);
      ctx.http.expectOne(roleUrl()).flush(role({ memberCount: 8 }));
      ctx.http.expectOne(setUrl()).flush({ data: [] }, { headers: { ETag: '"v2"' } });
      await settle();

      expect(text(byTestId(el(), 'role-detail-counts'))).toBe('0 permissions · 8 members');
      expect(ctx.profileStub.reload).not.toHaveBeenCalled();
    });

    it('keeps the view and explains a failed Refresh inline, beside the action', async () => {
      const { el, settle } = await open();
      answer(ctx);
      await settle();

      button(el(), 'role-detail-refresh')?.click();
      ctx.http.expectOne(setUrl());
      problem(ctx.http.expectOne(roleUrl()), 500, 'INTERNAL_ERROR');
      await settle();

      const failure = byTestId(el(), 'role-refresh-error');
      expect(failure?.getAttribute('role')).toBe('alert');
      expect(text(failure)).toContain('Something went wrong');
      expect(text(failure)).toContain('trace-INTERNAL_ERROR');
      expect(byTestId(el(), 'permission-matrix')).not.toBeNull();
    });

    it('turns a ROLE_NOT_FOUND on Refresh into the not-found page', async () => {
      const { el, settle } = await open();
      answer(ctx);
      await settle();

      button(el(), 'role-detail-refresh')?.click();
      ctx.http.expectOne(setUrl());
      problem(ctx.http.expectOne(roleUrl()), 404, 'ROLE_NOT_FOUND');
      await settle();

      expect(text(byTestId(el(), 'role-detail-title'))).toBe('This role no longer exists');
    });

    it('loads the new role when the route parameter changes', async () => {
      const { harness, el, settle } = await open();
      answer(ctx);
      await settle();

      await harness.navigateByUrl(`/admin/access/roles/${OTHER_ROLE_ID}/permissions`);
      answer(ctx, { id: OTHER_ROLE_ID, role: role({ id: OTHER_ROLE_ID, name: 'Billing' }) });
      await settle();

      expect(byTestId(el(), 'role-detail-title')?.querySelector('bdi')?.textContent).toBe(
        'Billing',
      );
    });

    it('renders user text as text: markup and a direction override stay inert', async () => {
      const payload = '<img src=x onerror=alert(1)>‮code';
      const { el, settle } = await open();
      answer(ctx, { role: role({ name: payload, description: payload }) });
      await settle();

      expect(el().querySelector('img')).toBeNull();
      expect(byTestId(el(), 'role-detail-title')?.querySelector('bdi')?.textContent).toBe(payload);
      const description = byTestId(el(), 'role-detail-description');
      expect(description?.querySelector('bdi')?.textContent).toBe(payload);
      expect(
        byTestId(el(), 'role-detail-title')?.querySelector(
          '[data-testid="user-text-hidden-badge"]',
        ),
      ).not.toBeNull();
    });

    it('never puts the role name in the document title or a log line', async () => {
      const before = document.title;
      const { settle } = await open();
      answer(ctx, { role: role({ name: 'Very Secret Name', description: 'Secret words' }) });
      await settle();

      expect(document.title).toBe(before);
      const logged = JSON.stringify(ctx.logs.map((spy) => spy.mock.calls));
      expect(logged).not.toContain('Very Secret Name');
      expect(logged).not.toContain('Secret words');
    });

    it('has no axe violations when ready', async () => {
      const { el, settle } = await open();
      answer(ctx, { etag: 'W/"v1"', correlationId: 'corr-1' });
      await settle();

      await expect(expectNoAxeViolations(el())).resolves.toBeUndefined();
    });
  });

  describe('failures', () => {
    beforeEach(() => (ctx = setup()));

    function failRole(status: number, code: string, headers = {}): void {
      ctx.http.expectOne(setUrl());
      problem(ctx.http.expectOne(roleUrl()), status, code, headers);
      for (const req of ctx.http.match(CATALOGUE_URL)) req.flush(cataloguePage());
    }

    it.each([
      [404, 'ROLE_NOT_FOUND'],
      [400, 'VALIDATION_FAILED'],
    ])(
      'shows "This role no longer exists" with a link to Roles for %s %s',
      async (status, code) => {
        const { el, settle } = await open();
        failRole(status, code);
        await settle();

        expect(text(byTestId(el(), 'role-detail-title'))).toBe('This role no longer exists');
        expect(text(byTestId(el(), 'role-not-found'))).toContain(
          'It may have been deleted. Go back to Roles.',
        );
        const back = byTestId(el(), 'role-not-found-back');
        expect(back?.tagName).toBe('A');
        expect(back?.getAttribute('href')).toBe('/admin/access/roles');
        expect(byTestId(el(), 'role-edit')).toBeNull();
        expect(byTestId(el(), 'role-detail-refresh')).toBeNull();
      },
    );

    it('shows the roles area "not enabled" state with no Retry when the flag is off', async () => {
      const { el, settle } = await open();
      failRole(404, 'RESOURCE_NOT_FOUND');
      await settle();

      const panel = byTestId(el(), 'role-detail-error');
      expect(text(panel)).toContain("Roles aren't enabled");
      expect(panel?.querySelector('[data-testid="nx-error-state-retry"]')).toBeNull();
    });

    it('shows the unavailable notice for a 503 AUTH_005', async () => {
      const { el, settle } = await open();
      failRole(503, 'AUTH_005', { 'Retry-After': '20' });
      await settle();

      expect(byTestId(el(), 'console-error-wait')).not.toBeNull();
      expect(text(byTestId(el(), 'role-detail-error'))).toContain(
        'Nexus is temporarily unavailable',
      );
    });

    it('shows the error panel with a reference, and Retry reads both again', async () => {
      const { el, settle } = await open();
      failRole(500, 'INTERNAL_ERROR');
      await settle();

      const panel = byTestId(el(), 'role-detail-error');
      expect(text(panel)).toContain('Something went wrong');
      expect(text(panel)).toContain('trace-INTERNAL_ERROR');
      expect(text(byTestId(el(), 'role-detail-title'))).toBe(CONSOLE_COPY.roleDetail.fallbackTitle);
      (panel?.querySelector('button') as HTMLButtonElement).click();
      await settle();

      expect(ctx.http.match(CATALOGUE_URL)).toHaveLength(0);
      answer(ctx);
      await settle();
      expect(byTestId(el(), 'permission-matrix')).not.toBeNull();
    });

    it('keeps the header and explains a catalogue failure in the tab, whose Retry reads only the catalogue', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(roleUrl()).flush(role());
      ctx.http.expectOne(setUrl()).flush({ data: [CATALOGUE[0]] }, { headers: { ETag: '"v1"' } });
      problem(ctx.http.expectOne(CATALOGUE_URL), 500, 'INTERNAL_ERROR');
      await settle();

      expect(byTestId(el(), 'role-detail-title')?.querySelector('bdi')?.textContent).toBe(
        'Support',
      );
      const panel = byTestId(el(), 'role-permissions-error');
      expect(text(panel)).toContain('Something went wrong');
      (panel?.querySelector('button') as HTMLButtonElement).click();
      await settle();

      ctx.http.expectOne(CATALOGUE_URL).flush(cataloguePage());
      await settle();
      expect(byTestId(el(), 'role-permissions-error')).toBeNull();
    });

    it('shows the tab loading state while the catalogue is still on its way', async () => {
      const { el, settle } = await open();
      ctx.http.expectOne(roleUrl()).flush(role());
      ctx.http.expectOne(setUrl()).flush({ data: [CATALOGUE[0]] }, { headers: { ETag: '"v1"' } });
      await settle();

      expect(byTestId(el(), 'role-permissions-loading')?.getAttribute('aria-busy')).toBe('true');
      ctx.http.expectOne(CATALOGUE_URL).flush(cataloguePage());
    });
  });

  describe('when the profile could not be read (Q8)', () => {
    beforeEach(() => (ctx = setup({ profile: 'error' })));

    it('keeps Edit and Clone visible, aria-disabled with the profile reason', async () => {
      const { el, settle } = await open();
      answer(ctx);
      await settle();

      for (const id of ['role-edit', 'role-clone']) {
        const control = button(el(), id);
        expect(control?.getAttribute('aria-disabled')).toBe('true');
        const reasonIds = control?.getAttribute('aria-describedby')?.split(' ') ?? [];
        const reasons = reasonIds.map((reasonId) => text(el().querySelector(`#${reasonId}`)));
        expect(reasons).toContain(CONSOLE_COPY.disabledReason.profileUnavailable);
      }
    });

    it('lists both reasons on Edit when the ETag is also unusable', async () => {
      const { el, settle } = await open();
      answer(ctx, { etag: 'W/"v1"' });
      await settle();

      const reasonIds = button(el(), 'role-edit')?.getAttribute('aria-describedby')?.split(' ');
      expect(reasonIds?.map((reasonId) => text(el().querySelector(`#${reasonId}`)))).toEqual([
        CONSOLE_COPY.disabledReason.profileUnavailable,
        CONSOLE_COPY.disabledReason.etagUnusable,
      ]);
    });
  });

  describe('as a role reader without role:write', () => {
    beforeEach(() => (ctx = setup({ permissions: ['role:read'] })));

    it('renders neither Edit nor Clone, and no ETag banner', async () => {
      const { el, settle } = await open();
      answer(ctx, { etag: 'W/"v1"' });
      await settle();

      expect(byTestId(el(), 'role-edit')).toBeNull();
      expect(byTestId(el(), 'role-clone')).toBeNull();
      expect(byTestId(el(), 'role-etag-banner')).toBeNull();
      expect(byTestId(el(), 'permission-matrix')).not.toBeNull();
    });
  });

  describe('when the JWT holds role:write but the live profile does not', () => {
    beforeEach(() => {
      ctx = setup();
      ctx.profileStub.can = () => false;
    });

    it('follows the profile and hides Edit and Clone (ADR-0028)', async () => {
      const { el, settle } = await open();
      answer(ctx);
      await settle();

      expect(byTestId(el(), 'role-edit')).toBeNull();
      expect(byTestId(el(), 'role-clone')).toBeNull();
    });
  });
});
