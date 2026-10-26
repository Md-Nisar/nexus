import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { Component, ErrorHandler } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { Route, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
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
  RoleAssignmentListResponse,
  RoleAssignmentResponse,
  RoleListResponse,
  RoleResponse,
} from '../../../shared/types/api/rbac';
import type { UserDirectoryEntry } from '../../../shared/types/api/user-directory';
import { ACCESS_MANAGEMENT_ROUTES } from '../access-management.routes';
import { CONSOLE_COPY, NotEnabledCopy, RbacErrorMessages } from '../copy/console-copy';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore } from '../data/catalogue.store';
import { DirectoryCache } from '../data/directory-cache';
import { RolesStore } from '../data/roles.store';

const API = 'http://localhost:1000/api';
const USER_ID = '0190a000-0000-7000-8000-000000000042';
const CALLER_ID = '0190a000-0000-7000-8000-0000000000ca';
const ASSIGNER_ID = '0190a000-0000-7000-8000-0000000000ad';
const ADDRESS = 'person.detail@directory.invalid';
const ASSIGNER_ADDRESS = 'assigner@directory.invalid';
const SYSTEM_ROLE_ID = '0190a000-0000-7000-8000-0000000000b1';
const CUSTOM_ROLE_ID = '0190a000-0000-7000-8000-0000000000b2';
const GONE_ROLE_ID = '0190a000-0000-7000-8000-0000000000b3';
const USER_URL = `${API}/v1/users/${USER_ID}`;
const ASSIGNMENTS_URL = `${API}/v1/users/${USER_ID}/roles?page=0&size=100`;
const ROLES_URL = `${API}/v1/roles?page=0&size=100`;

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

const ALL = ['user:directory:read', 'user:read', 'role:read'] as const;

function user(): UserDirectoryEntry {
  return {
    userId: USER_ID,
    email: ADDRESS,
    status: 'ACTIVE',
    emailVerified: true,
    createdAt: '2026-01-02T03:04:05Z',
  };
}

function assignment(
  roleId: string,
  roleName: string,
  assignedBy: string | null = null,
): RoleAssignmentResponse {
  return { userId: USER_ID, roleId, roleName, assignedAt: '2026-01-03T00:00:00Z', assignedBy };
}

function assignments(entries: readonly RoleAssignmentResponse[]): RoleAssignmentListResponse {
  return {
    data: entries,
    page: { size: 100, number: 0, totalElements: entries.length, totalPages: 1 },
    links: { next: null, prev: null },
  };
}

function role(id: string, name: string, isSystemRole: boolean): RoleResponse {
  return {
    id,
    name,
    description: '',
    isSystemRole,
    createdAt: '2026-01-01T00:00:00Z',
    memberCount: 1,
    permissionCount: 1,
  };
}

function rolesPage(): RoleListResponse {
  const data = [role(SYSTEM_ROLE_ID, 'TENANT_ADMIN', true), role(CUSTOM_ROLE_ID, 'Support', false)];
  return {
    data,
    page: { size: 100, number: 0, totalElements: data.length, totalPages: 1 },
    links: { next: null, prev: null },
  };
}

const HELD = [
  assignment(SYSTEM_ROLE_ID, 'TENANT_ADMIN'),
  assignment(CUSTOM_ROLE_ID, 'Support'),
] as const;

@Component({ template: '<h1>Placeholder</h1>' })
class Placeholder {}

function userRoute(): Route {
  const layout = ACCESS_MANAGEMENT_ROUTES[0] as Route;
  const route = layout.children?.find((child) => child.path === 'users/:userId');
  if (route === undefined) throw new Error('users/:userId route missing');
  return route;
}

function setup(permissions: readonly string[] = ALL) {
  const profileStub = {
    state: () => ({ status: 'ready' }),
    userId: () => CALLER_ID,
    can: (p: string) => permissions.includes(p),
    permissions: () => new Set(permissions),
    isAdministrator: () => false,
    mutationsEnabled: () => true,
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
          session: createAuthSession({ user: createAuthUser({ userId: CALLER_ID }) }),
          permissions,
        }),
      },
      provideAnimationsAsync(),
      provideHttpClient(withInterceptors([apiErrorInterceptor])),
      provideHttpClientTesting(),
      // At the root here (the app scopes it to the layout route) so a spec can seed it first.
      DirectoryCache,
      provideRouter([
        {
          path: 'admin/access',
          providers: [
            RolesStore,
            CatalogueStore,
            { provide: AuthorizationProfileStore, useValue: profileStub },
          ],
          children: [
            { path: 'users', component: Placeholder },
            { path: 'roles/:roleId', component: Placeholder },
            userRoute(),
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
  return { http: TestBed.inject(HttpTestingController), handleError, logs };
}

type Ctx = ReturnType<typeof setup>;

async function open() {
  const harness = await RouterTestingHarness.create();
  await harness.navigateByUrl(`/admin/access/users/${USER_ID}/roles`);
  harness.detectChanges();
  const el = (): HTMLElement => harness.routeNativeElement as HTMLElement;
  const settle = async (): Promise<void> => {
    await harness.fixture.whenStable();
    harness.detectChanges();
  };
  return { harness, el, settle };
}

/** Opens the tab and answers the user GET, so the tab is rendered. */
async function openTab(ctx: Ctx) {
  const opened = await open();
  ctx.http.expectOne(USER_URL).flush(user());
  await opened.settle();
  return opened;
}

function byTestId(root: HTMLElement, id: string): HTMLElement | null {
  return root.querySelector(`[data-testid="${id}"]`);
}

function allByTestId(root: HTMLElement, id: string): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(`[data-testid="${id}"]`));
}

function text(node: Element | null | undefined): string {
  return node?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
}

function problem(req: TestRequest, status: number, code: string): void {
  req.flush(
    { code, detail: `server text with ${ADDRESS}`, traceId: `trace-${code}` },
    { status, statusText: 'Error' },
  );
}

function headers(root: HTMLElement): string[] {
  return Array.from(root.querySelectorAll('th')).map((th) => text(th));
}

function logged(ctx: Ctx): string {
  return JSON.stringify(ctx.logs.flatMap((spy) => spy.mock.calls));
}

describe('UserRolesTab (US-020 design §6.5 "User page", §12.8; Q19)', () => {
  let ctx: Ctx;

  afterEach(() => {
    ctx.http.verify();
    // RC-73: no load failure ever reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
    // PII (SD-13): no log line carries an address.
    expect(logged(ctx)).not.toContain(ADDRESS);
    expect(logged(ctx)).not.toContain(ASSIGNER_ADDRESS);
  });

  describe('request budget (design §6.5)', () => {
    it('with every permission: the user, the assignments and the roles fetch-all, once each', async () => {
      ctx = setup();
      const { settle } = await open();

      // The two user reads leave together, before either answers.
      const userReq = ctx.http.expectOne(USER_URL);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      userReq.flush(user());
      await settle();

      const roles = ctx.http.match(ROLES_URL);
      expect(roles).toHaveLength(1);
      roles[0].flush(rolesPage());
      await settle();
      ctx.http.expectNone(() => true);
    });

    it('reuses a ready roles list: no roles GET on a second visit', async () => {
      ctx = setup();
      const { harness, settle } = await open();
      ctx.http.expectOne(USER_URL).flush(user());
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await settle();
      ctx.http.expectOne(ROLES_URL).flush(rolesPage());
      await settle();

      await harness.navigateByUrl('/admin/access/users');
      await harness.navigateByUrl(`/admin/access/users/${USER_ID}/roles`);
      ctx.http.expectOne(USER_URL).flush(user());
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await settle();

      ctx.http.expectNone(ROLES_URL);
    });

    it('without user:read: no assignments GET and no roles GET, and the empty state says why', async () => {
      ctx = setup(['user:directory:read', 'role:read']);
      const { el } = await openTab(ctx);

      ctx.http.expectNone((req) => req.url.endsWith('/roles'));
      expect(text(byTestId(el(), 'user-roles-no-user-read'))).toContain(
        CONSOLE_COPY.userRoles.noUserRead,
      );
      expect(byTestId(el(), 'user-roles-table')).toBeNull();
    });

    it('without role:read: no roles GET, a visible note, and no role links', async () => {
      ctx = setup(['user:directory:read', 'user:read']);
      const { el, settle } = await openTab(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await settle();

      ctx.http.expectNone(ROLES_URL);
      expect(text(byTestId(el(), 'user-roles-no-role-read'))).toBe(
        CONSOLE_COPY.userRoles.noRoleRead,
      );
      const names = allByTestId(el(), 'user-role-name');
      expect(names.map((name) => text(name))).toEqual(['TENANT_ADMIN', 'Support']);
      expect(el().querySelector('[data-testid="user-roles-table"] a')).toBeNull();
      expect(allByTestId(el(), 'system-role-badge')).toHaveLength(0);
      expect(allByTestId(el(), 'user-role-type').map((cell) => text(cell))).toEqual([
        CONSOLE_COPY.userRoles.typeUnknown,
        CONSOLE_COPY.userRoles.typeUnknown,
      ]);
    });
  });

  describe('with every permission', () => {
    async function loaded(entries: readonly RoleAssignmentResponse[] = HELD) {
      const opened = await openTab(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(entries));
      await opened.settle();
      for (const req of ctx.http.match(ROLES_URL)) req.flush(rolesPage());
      await opened.settle();
      return opened;
    }

    it('lists each role as a link to it, with the System or Custom badge from the join', async () => {
      ctx = setup();
      const { el } = await loaded();

      const links = Array.from(
        el().querySelectorAll<HTMLAnchorElement>('[data-testid="user-role-name"] a'),
      );
      expect(links.map((link) => link.getAttribute('href'))).toEqual([
        `/admin/access/roles/${SYSTEM_ROLE_ID}`,
        `/admin/access/roles/${CUSTOM_ROLE_ID}`,
      ]);
      expect(links.map((link) => text(link))).toEqual(['TENANT_ADMIN', 'Support']);
      expect(
        allByTestId(el(), 'system-role-badge').map((badge) => badge.getAttribute('data-kind')),
      ).toEqual(['system', 'custom']);
      expect(text(allByTestId(el(), 'user-role-assigned')[0])).toContain('Jan 3, 2026');
      expect(byTestId(el(), 'user-roles-no-role-read')).toBeNull();
    });

    it('shows the dash for a role the join does not know', async () => {
      ctx = setup();
      const { el } = await loaded([assignment(GONE_ROLE_ID, 'Archived')]);

      expect(text(byTestId(el(), 'user-role-type'))).toBe(CONSOLE_COPY.userRoles.typeUnknown);
    });

    it('hides "Assigned by" when every assignment has it null', async () => {
      ctx = setup();
      const { el } = await loaded();

      expect(headers(el())).not.toContain(CONSOLE_COPY.userRoles.columns.assignedBy);
      expect(allByTestId(el(), 'user-role-assigned-by')).toHaveLength(0);
    });

    it('shows "Assigned by" as an id when the address is not in the directory cache', async () => {
      ctx = setup();
      const { el } = await loaded([
        assignment(CUSTOM_ROLE_ID, 'Support', ASSIGNER_ID),
        assignment(SYSTEM_ROLE_ID, 'TENANT_ADMIN'),
      ]);

      expect(headers(el())).toContain(CONSOLE_COPY.userRoles.columns.assignedBy);
      const cells = allByTestId(el(), 'user-role-assigned-by');
      expect(cells).toHaveLength(1);
      expect(text(cells[0].querySelector('[data-testid="user-role-assigned-by-id"]'))).toBe(
        ASSIGNER_ID,
      );
    });

    it('shows "Assigned by" as the address, in email mode, when the cache holds it', async () => {
      ctx = setup();
      TestBed.inject(DirectoryCache).remember([
        {
          userId: ASSIGNER_ID,
          email: ASSIGNER_ADDRESS,
          status: 'ACTIVE',
          emailVerified: true,
          createdAt: '2026-01-01T00:00:00Z',
        },
      ]);
      const { el } = await loaded([assignment(CUSTOM_ROLE_ID, 'Support', ASSIGNER_ID)]);

      const cell = byTestId(el(), 'user-role-assigned-by');
      expect(cell?.querySelector('[data-testid="user-text"]')?.textContent?.trim()).toBe(
        ASSIGNER_ADDRESS,
      );
      expect(cell?.querySelector('[data-testid="user-role-assigned-by-id"]')).toBeNull();
    });

    it('says "No roles assigned" for a user with none', async () => {
      ctx = setup();
      const { el } = await loaded([]);

      expect(text(byTestId(el(), 'user-roles-empty'))).toContain(CONSOLE_COPY.userRoles.empty);
      expect(byTestId(el(), 'user-roles-table')).toBeNull();
    });

    it('shows a loading state while the assignments are on their way', async () => {
      ctx = setup();
      const { el, settle } = await openTab(ctx);

      expect(byTestId(el(), 'user-roles-loading')?.getAttribute('aria-busy')).toBe('true');
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments([]));
      await settle();
      for (const req of ctx.http.match(ROLES_URL)) req.flush(rolesPage());
    });

    it('a 403 on the assignments read gives the same "no user:read" empty state (design §7.1)', async () => {
      ctx = setup();
      const { el, settle } = await openTab(ctx);
      problem(ctx.http.expectOne(ASSIGNMENTS_URL), 403, 'RBAC_001');
      await settle();

      expect(text(byTestId(el(), 'user-roles-no-user-read'))).toContain(
        CONSOLE_COPY.userRoles.noUserRead,
      );
      expect(byTestId(el(), 'user-roles-table')).toBeNull();
      // The roles join left in parallel with the assignments read; it is answered, not shown.
      ctx.http.expectOne(ROLES_URL).flush(rolesPage());
    });

    it('says role assignment is not enabled when us012 is off, with no Retry', async () => {
      ctx = setup();
      const { el, settle } = await openTab(ctx);
      problem(ctx.http.expectOne(ASSIGNMENTS_URL), 404, 'RESOURCE_NOT_FOUND');
      await settle();

      const panel = byTestId(el(), 'user-roles-error');
      expect(text(panel)).toContain(NotEnabledCopy.assignments.title);
      expect(panel?.querySelector('button')).toBeNull();
      ctx.http.expectOne(ROLES_URL).flush(rolesPage());
    });

    it('shows the error panel on a failed read; Retry reads the assignments only', async () => {
      ctx = setup();
      const { el, settle } = await openTab(ctx);
      problem(ctx.http.expectOne(ASSIGNMENTS_URL), 500, 'INTERNAL_ERROR');
      await settle();

      const panel = byTestId(el(), 'user-roles-error');
      expect(text(panel)).toContain(RbacErrorMessages.INTERNAL_ERROR.title);
      panel?.querySelector<HTMLButtonElement>('button')?.click();
      await settle();

      ctx.http.expectNone(USER_URL);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await settle();
      for (const req of ctx.http.match(ROLES_URL)) req.flush(rolesPage());
      await settle();
      expect(byTestId(el(), 'user-roles-table')).not.toBeNull();
    });

    it('notes a failed roles join beside the table, and Retry reads the roles again', async () => {
      ctx = setup();
      const { el, settle } = await openTab(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await settle();
      problem(ctx.http.expectOne(ROLES_URL), 500, 'INTERNAL_ERROR');
      await settle();

      expect(text(byTestId(el(), 'user-roles-join-error'))).toContain(
        CONSOLE_COPY.userRoles.joinFailed,
      );
      expect(byTestId(el(), 'user-roles-table')).not.toBeNull();
      expect(allByTestId(el(), 'system-role-badge')).toHaveLength(0);

      byTestId(el(), 'user-roles-join-retry')?.querySelector('button')?.click();
      await settle();
      ctx.http.expectOne(ROLES_URL).flush(rolesPage());
      await settle();
      expect(byTestId(el(), 'user-roles-join-error')).toBeNull();
      expect(allByTestId(el(), 'system-role-badge')).toHaveLength(2);
    });

    it('has no axe violations with the table shown', async () => {
      ctx = setup();
      const { el } = await loaded([assignment(CUSTOM_ROLE_ID, 'Support', ASSIGNER_ID)]);

      await expect(expectNoAxeViolations(el())).resolves.toBeUndefined();
    });
  });
});
