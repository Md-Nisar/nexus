import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { Component, ErrorHandler, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { Route, Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { of } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import problemRbac002 from '../../../../../../contracts/api/problem-rbac-002.json';
import { AuthStore } from '../../../core/auth/auth.store';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { apiErrorInterceptor } from '../../../core/http/api-error.interceptor';
import { authInterceptor } from '../../../core/http/auth.interceptor';
import { correlationIdInterceptor } from '../../../core/http/correlation-id.interceptor';
import { ServiceAvailabilityNotifier } from '../../../core/http/service-availability-notifier';
import { LoggerService } from '../../../core/logging/logger.service';
import {
  createAuthSession,
  createAuthStoreStub,
  createAuthUser,
} from '../../../shared/testing/auth.fixtures';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import type {
  CallerAuthorizationResponse,
  PermissionResponse,
  RoleAssignmentListResponse,
  RoleAssignmentResponse,
  RoleListResponse,
  RoleResponse,
} from '../../../shared/types/api/rbac';
import type { UserDirectoryEntry } from '../../../shared/types/api/user-directory';
import { NxDialog, NxToast } from '../../../shared/ui';
import { AuthService } from '../../auth/auth.service';
import { ACCESS_MANAGEMENT_ROUTES } from '../access-management.routes';
import { CONSOLE_COPY, RbacErrorMessages, Rbac001ReasonCopy, format } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import { PROPAGATION_COPY } from '../copy/propagation';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore } from '../data/catalogue.store';
import { DirectoryCache } from '../data/directory-cache';
import type { LoadState } from '../data/load-state';
import { RolesStore } from '../data/roles.store';
import { UserRolesTab } from '../user-detail/user-roles.tab';
import { chooseRevokeVariant } from './revoke-dialogs';

const API = 'http://localhost:1000/api';
const USER_ID = '0190a000-0000-7000-8000-000000000042';
const CALLER_ID = '0190a000-0000-7000-8000-0000000000ca';
/** Synthetic addresses only. */
const ADDRESS = 'revoke.target@directory.invalid';
const USER_URL = `${API}/v1/users/${USER_ID}`;
const ASSIGNMENTS_URL = `${API}/v1/users/${USER_ID}/roles?page=0&size=100`;
const ROLES_URL = `${API}/v1/roles?page=0&size=100`;
const PROFILE_URL = `${API}/v1/users/me/authorization`;
const REFRESH_URL = `${API}/v1/auth/refresh`;
const CATALOGUE_TOTAL = 9;

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

/** A role-reader user manager: four codes, not an administrator (design §19.4). */
const MANAGER = ['role:read', 'user:read', 'user:role:assign', 'user:directory:read'] as const;
const EVERY = [
  ...MANAGER,
  'role:write',
  'audit:read',
  'tenant:read',
  'tenant:write',
  'user:write',
] as const;

const ID = {
  support: '0190a000-0000-7000-8000-0000000000b1',
  admin: '0190a000-0000-7000-8000-0000000000b5',
} as const;

const GRANTS: Readonly<Record<string, readonly string[]>> = {
  [ID.support]: ['role:read', 'user:read'],
  [ID.admin]: EVERY,
};

function role(id: string, name: string, isSystemRole = false): RoleResponse {
  return {
    id,
    name,
    description: '',
    isSystemRole,
    createdAt: '2026-01-01T00:00:00Z',
    memberCount: 1,
    permissionCount: GRANTS[id].length,
  };
}

const ROLES: readonly RoleResponse[] = [
  role(ID.support, 'Support'),
  role(ID.admin, 'TENANT_ADMIN', true),
];

function rolesPage(): RoleListResponse {
  return {
    data: ROLES,
    page: { size: 100, number: 0, totalElements: ROLES.length, totalPages: 1 },
    links: { next: null, prev: null },
  };
}

function permissionSet(roleId: string): { data: PermissionResponse[] } {
  return {
    data: GRANTS[roleId].map((code) => ({
      id: `perm-${code}`,
      name: code,
      description: code,
      isSensitive: false,
    })),
  };
}

function user(overrides: Partial<UserDirectoryEntry> = {}): UserDirectoryEntry {
  return {
    userId: USER_ID,
    email: ADDRESS,
    status: 'ACTIVE',
    emailVerified: true,
    createdAt: '2026-01-02T03:04:05Z',
    ...overrides,
  };
}

function assignment(roleId: string, roleName: string): RoleAssignmentResponse {
  return {
    userId: USER_ID,
    roleId,
    roleName,
    assignedAt: '2026-01-03T00:00:00Z',
    assignedBy: null,
  };
}

function assignments(entries: readonly RoleAssignmentResponse[]): RoleAssignmentListResponse {
  return {
    data: entries,
    page: { size: 100, number: 0, totalElements: entries.length, totalPages: 1 },
    links: { next: null, prev: null },
  };
}

const HELD = [assignment(ID.support, 'Support'), assignment(ID.admin, 'TENANT_ADMIN')] as const;
const AFTER_SUPPORT = [assignment(ID.admin, 'TENANT_ADMIN')] as const;

@Component({ template: '<h1>Placeholder</h1>' })
class Placeholder {}

function userRoute(): Route {
  const layout = ACCESS_MANAGEMENT_ROUTES[0] as Route;
  const route = layout.children?.find((child) => child.path === 'users/:userId');
  if (route === undefined) throw new Error('users/:userId route missing');
  return route;
}

interface SetupOptions {
  readonly held?: readonly string[];
  readonly isAdministrator?: boolean;
  readonly callerId?: string;
  readonly catalogueTotal?: number | null;
}

function setup(options: SetupOptions = {}) {
  const held = options.held ?? MANAGER;
  const callerId = options.callerId ?? CALLER_ID;
  const profileStatus = signal<'loading' | 'ready' | 'error'>('ready');
  const ready = (): boolean => profileStatus() === 'ready';
  const profileStub = {
    state: () => ({ status: profileStatus() }),
    settled: () => profileStatus() !== 'loading',
    userId: () => (ready() ? callerId : null),
    can: (p: string) => ready() && held.includes(p),
    permissions: () => new Set(ready() ? held : []),
    isAdministrator: () => ready() && (options.isAdministrator ?? false),
    mutationsEnabled: () => ready(),
    roleIds: () => new Set<string>(),
    load: vi.fn(),
    reload: vi.fn(),
  };
  const total = options.catalogueTotal === undefined ? CATALOGUE_TOTAL : options.catalogueTotal;
  const catalogueState = signal<LoadState<{ readonly total: number }>>(
    total === null ? { status: 'idle' } : { status: 'ready', loadedAt: 0, data: { total } },
  );
  const catalogueStub = { state: catalogueState, load: vi.fn() };
  const handleError = vi.fn();
  const authStore = createAuthStoreStub({
    session: createAuthSession({ user: createAuthUser({ userId: callerId }) }),
    permissions: held,
  });
  TestBed.configureTestingModule({
    providers: [
      { provide: APP_CONFIG, useValue: CONFIG },
      { provide: ErrorHandler, useValue: { handleError } },
      { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
      { provide: AuthStore, useValue: authStore },
      provideAnimationsAsync('noop'),
      provideHttpClient(withInterceptors([apiErrorInterceptor])),
      provideHttpClientTesting(),
      DirectoryCache,
      provideRouter([
        { path: 'dashboard', component: Placeholder },
        {
          path: 'admin/access',
          providers: [
            RolesStore,
            { provide: AuthorizationProfileStore, useValue: profileStub },
            { provide: CatalogueStore, useValue: catalogueStub },
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
  return { ...instrument(), handleError, profileStub, profileStatus, catalogueStub };
}

/** Spies on the logger, the toasts and `AuthService.refresh` of the configured TestBed. */
function instrument() {
  const logger = TestBed.inject(LoggerService);
  const logs = [
    vi.spyOn(logger, 'debug'),
    vi.spyOn(logger, 'info'),
    vi.spyOn(logger, 'warn'),
    vi.spyOn(logger, 'error'),
  ];
  const toast = TestBed.inject(NxToast);
  const toasts = {
    success: vi.spyOn(toast, 'success').mockImplementation(() => undefined),
    info: vi.spyOn(toast, 'info').mockImplementation(() => undefined),
    warning: vi.spyOn(toast, 'warning').mockImplementation(() => undefined),
    error: vi.spyOn(toast, 'error').mockImplementation(() => undefined),
  };
  const refresh = vi.spyOn(TestBed.inject(AuthService), 'refresh');
  return { http: TestBed.inject(HttpTestingController), logs, toasts, refresh };
}

interface Ctx {
  readonly http: HttpTestingController;
  readonly logs: readonly { mock: { calls: unknown[][] } }[];
  readonly toasts: Readonly<Record<string, { mock: { calls: unknown[][] } }>>;
  readonly refresh: { mock: { calls: unknown[][] } };
  readonly handleError: ReturnType<typeof vi.fn>;
}

async function settleAll(harness: RouterTestingHarness): Promise<void> {
  for (let i = 0; i < 3; i++) {
    await harness.fixture.whenStable();
    harness.detectChanges();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  harness.detectChanges();
}

/** Opens the tab and answers the user, assignments and roles reads. */
async function openTab(
  ctx: Ctx,
  target: Partial<UserDirectoryEntry> = {},
  held: readonly RoleAssignmentResponse[] = HELD,
) {
  const harness = await RouterTestingHarness.create();
  await harness.navigateByUrl(`/admin/access/users/${target.userId ?? USER_ID}/roles`);
  harness.detectChanges();
  ctx.http.expectOne(USER_URL).flush(user(target));
  ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(held));
  await settleAll(harness);
  for (const req of ctx.http.match(ROLES_URL)) req.flush(rolesPage());
  await settleAll(harness);
  const el = (): HTMLElement => harness.routeNativeElement as HTMLElement;
  const settle = (): Promise<void> => settleAll(harness);
  return { harness, el, settle };
}

/** MN-1: a completed assign or revoke reads the console's roles list again, exactly once. */
function answerRolesReread(ctx: Ctx): void {
  const reread = ctx.http.match(ROLES_URL);
  expect(reread).toHaveLength(1);
  reread[0].flush(rolesPage());
}

type Page = Awaited<ReturnType<typeof openTab>>;

function byTestId(root: ParentNode, id: string): HTMLElement | null {
  return root.querySelector(`[data-testid="${id}"]`);
}

function text(node: Element | null | undefined): string {
  return node?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
}

function button(root: ParentNode, id: string): HTMLButtonElement | null {
  return byTestId(root, id)?.querySelector('button') ?? null;
}

function revokeButton(roleId: string): HTMLButtonElement | null {
  return document.querySelector<HTMLButtonElement>(
    `[data-testid="user-role-revoke"][data-role-id="${roleId}"] button`,
  );
}

function dialog(): HTMLElement | null {
  return byTestId(document, 'revoke-dialog');
}

function permissionsUrl(roleId: string): string {
  return `${API}/v1/roles/${roleId}/permissions`;
}

function revokeUrl(roleId: string): string {
  return `${API}/v1/users/${USER_ID}/roles/${roleId}`;
}

function problem(req: TestRequest, status: number, code: string, extra: object = {}): void {
  req.flush(
    { code, detail: `server text with ${ADDRESS}`, traceId: `trace-${code}`, ...extra },
    { status, statusText: 'Error' },
  );
}

function logged(ctx: Ctx): string {
  return JSON.stringify(ctx.logs.flatMap((spy) => spy.mock.calls));
}

function toasted(ctx: Ctx): string {
  return JSON.stringify(Object.values(ctx.toasts).flatMap((spy) => spy.mock.calls));
}

/** Opens the standard Revoke dialog for a row and answers its summary read when one is sent. */
async function openStandard(ctx: Ctx, page: Page, roleId: string): Promise<HTMLElement> {
  revokeButton(roleId)?.click();
  await page.settle();
  for (const req of ctx.http.match(permissionsUrl(roleId))) {
    req.flush(permissionSet(roleId), { headers: { ETag: '"v1"' } });
  }
  await page.settle();
  const root = dialog();
  if (root === null) throw new Error('Revoke dialog did not open');
  return root;
}

async function confirmStandard(page: Page, root: HTMLElement): Promise<void> {
  button(root, 'revoke-confirm')?.click();
  await page.settle();
}

function noContent(req: TestRequest): void {
  req.flush(null, { status: 204, statusText: 'No Content' });
}

describe('chooseRevokeVariant (D-5)', () => {
  it('is the typed self variant only for equal ids with an admin-looking role', () => {
    expect(
      chooseRevokeVariant({ routeUserId: USER_ID, callerUserId: USER_ID, adminHint: true }),
    ).toBe('self');
  });

  it('fails closed to the typed self variant for equal ids when the hint is unknown', () => {
    expect(
      chooseRevokeVariant({ routeUserId: USER_ID, callerUserId: USER_ID, adminHint: null }),
    ).toBe('self');
  });

  it('is standard for equal ids with a role that is known not to look like an administrator', () => {
    expect(
      chooseRevokeVariant({ routeUserId: USER_ID, callerUserId: USER_ID, adminHint: false }),
    ).toBe('standard');
  });

  it('is standard for different ids, whatever the role', () => {
    for (const adminHint of [true, false, null]) {
      expect(
        chooseRevokeVariant({ routeUserId: USER_ID, callerUserId: CALLER_ID, adminHint }),
      ).toBe('standard');
    }
  });

  it('is standard while either id is unknown', () => {
    expect(chooseRevokeVariant({ routeUserId: USER_ID, callerUserId: null, adminHint: true })).toBe(
      'standard',
    );
    expect(chooseRevokeVariant({ routeUserId: null, callerUserId: null, adminHint: true })).toBe(
      'standard',
    );
  });
});

describe('Revoke dialogs (US-020 design §6.5, §11.4, §12.10; RC-68, D-5, Q16)', () => {
  let ctx: Ctx;

  afterEach(() => {
    const titleAfter = document.title;
    vi.restoreAllMocks();
    vi.useRealTimers();
    ctx.http.verify();
    // RC-73: nothing reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
    // PII: no address in a log line or a toast, and never in the document title.
    expect(logged(ctx)).not.toContain('directory.invalid');
    expect(toasted(ctx)).not.toContain('directory.invalid');
    expect(titleAfter).not.toContain('directory.invalid');
  });

  describe('the Remove control (design §12.8)', () => {
    it('is not shown without user:role:assign', async () => {
      const setupCtx = setup({ held: ['role:read', 'user:read', 'user:directory:read'] });
      ctx = setupCtx;
      await openTab(ctx);
      expect(revokeButton(ID.support)).toBeNull();
      expect(setupCtx.refresh).not.toHaveBeenCalled();
    });

    it('is shown on every row, named with the role, for a holder of user:role:assign', async () => {
      ctx = setup();
      await openTab(ctx);
      const support = revokeButton(ID.support) as HTMLButtonElement;
      expect(support.getAttribute('aria-disabled')).toBeNull();
      expect(support.getAttribute('aria-label')).toBe(
        format(CONSOLE_COPY.revoke.openLabel, { role: 'Support' }),
      );
      expect(revokeButton(ID.admin)).not.toBeNull();
    });

    it('is disabled while the live profile is unavailable, and opens nothing (Q8)', async () => {
      const setupCtx = setup();
      ctx = setupCtx;
      setupCtx.profileStatus.set('error');
      const page = await openTab(ctx);

      const support = revokeButton(ID.support) as HTMLButtonElement;
      expect(support.getAttribute('aria-disabled')).toBe('true');
      support.click();
      await page.settle();
      expect(dialog()).toBeNull();
      ctx.http.expectNone(permissionsUrl(ID.support));
    });
  });

  describe('the standard dialog', () => {
    it('titles the dialog with the role and the address, shows TargetIdentity and what they will lose', async () => {
      ctx = setup();
      const page = await openTab(ctx, { emailVerified: false });
      const root = await openStandard(ctx, page, ID.support);

      const heading = byTestId(root, 'revoke-dialog-title') as HTMLElement;
      expect(heading.tagName).toBe('H2');
      expect(text(heading)).toBe(`Remove Support from ${ADDRESS}?`);
      const identity = byTestId(root, 'target-identity') as HTMLElement;
      expect(
        identity.querySelector('[data-testid="user-status-badge"]')?.getAttribute('data-status'),
      ).toBe('ACTIVE');
      expect(text(byTestId(identity, 'target-identity-verified'))).toContain(
        CONSOLE_COPY.badges.unverified,
      );
      expect(text(byTestId(root, 'revoke-loss'))).toBe(
        format(CONSOLE_COPY.revoke.loses, {
          labels: [permissionLabel('role:read'), permissionLabel('user:read')].join(
            CONSOLE_COPY.save.listSeparator,
          ),
        }),
      );
      expect(byTestId(root, 'revoke-admin-warning')).toBeNull();
      const confirm = button(root, 'revoke-confirm') as HTMLButtonElement;
      expect(text(confirm)).toBe(CONSOLE_COPY.revoke.confirm);
      expect(byTestId(root, 'revoke-confirm')?.querySelector('.nx-btn--danger')).not.toBeNull();

      button(root, 'revoke-cancel')?.click();
      await page.settle();
      expect(dialog()).toBeNull();
      ctx.http.expectNone(() => true);
    });

    it('RC-68: hidden characters in the address are tokens in the title and on the identity line', async () => {
      ctx = setup();
      const rlo = String.fromCodePoint(0x202e);
      const page = await openTab(ctx, { email: `revoke${rlo}tegrat@directory.invalid` });
      const root = await openStandard(ctx, page, ID.support);

      const heading = byTestId(root, 'revoke-dialog-title') as HTMLElement;
      expect(heading.querySelector('[data-testid="user-text-hidden-token"]')?.textContent).toBe(
        '⟨U+202E⟩',
      );
      const identity = byTestId(root, 'target-identity') as HTMLElement;
      expect(byTestId(identity, 'user-text-hidden-badge')).not.toBeNull();
      expect(root.textContent).not.toContain(rlo);
    });

    it('without role:read the summary is the generic line and no GET is made', async () => {
      ctx = setup({ held: ['user:read', 'user:role:assign', 'user:directory:read'] });
      const page = await openTab(ctx);
      revokeButton(ID.support)?.click();
      await page.settle();

      ctx.http.expectNone(permissionsUrl(ID.support));
      expect(text(byTestId(dialog() as HTMLElement, 'revoke-loss'))).toBe(
        CONSOLE_COPY.revoke.losesGeneric,
      );
    });

    it('a failed summary read falls back to the generic line, and the revoke still works', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      revokeButton(ID.support)?.click();
      await page.settle();
      problem(ctx.http.expectOne(permissionsUrl(ID.support)), 500, 'INTERNAL_ERROR');
      await page.settle();

      const root = dialog() as HTMLElement;
      expect(text(byTestId(root, 'revoke-loss'))).toBe(CONSOLE_COPY.revoke.losesGeneric);
      expect(button(root, 'revoke-confirm')?.getAttribute('aria-disabled')).toBeNull();
      button(root, 'revoke-cancel')?.click();
      await page.settle();
    });

    it('shows the admin warning when the role is hinted admin-defining', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true });
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.admin);

      expect(text(byTestId(root, 'revoke-admin-warning'))).toBe(CONSOLE_COPY.revoke.adminWarning);
    });

    it('shows no admin warning while the catalogue total is unknown (a hint, never a guess)', async () => {
      const setupCtx = setup({ held: EVERY, isAdministrator: true, catalogueTotal: null });
      ctx = setupCtx;
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.admin);

      expect(byTestId(root, 'revoke-admin-warning')).toBeNull();
      // Opening the dialog never reads the catalogue (design §6.5).
      expect(setupCtx.catalogueStub.load).not.toHaveBeenCalled();
    });

    it('opens at most one dialog at a time (FR-G5)', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      await openStandard(ctx, page, ID.support);
      revokeButton(ID.admin)?.click();
      await page.settle();
      expect(document.querySelectorAll('[data-testid="revoke-dialog"]')).toHaveLength(1);
      ctx.http.expectNone(permissionsUrl(ID.admin));
    });
  });

  describe('D-5: the self-revoke variant is chosen by user id, never by address', () => {
    it('ids equal and a hinted role: the typed confirm with the role name, no identity line, no GET', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true, callerId: USER_ID });
      const typed = vi
        .spyOn(TestBed.inject(NxDialog), 'confirmTyped')
        .mockReturnValue({ afterClosed: () => of(false) } as ReturnType<NxDialog['confirmTyped']>);
      const page = await openTab(ctx);

      revokeButton(ID.admin)?.click();
      await page.settle();

      expect(typed).toHaveBeenCalledTimes(1);
      expect(typed.mock.calls[0][0]).toEqual({
        title: format(CONSOLE_COPY.revoke.selfTitle, { role: 'TENANT_ADMIN' }),
        message: CONSOLE_COPY.revoke.selfMessage,
        expectedText: 'TENANT_ADMIN',
        confirmLabel: CONSOLE_COPY.revoke.selfConfirm,
        cancelLabel: CONSOLE_COPY.revoke.cancel,
      });
      expect(dialog()).toBeNull();
      expect(byTestId(document, 'target-identity')).toBeNull();
      ctx.http.expectNone(permissionsUrl(ID.admin));
      // Cancelled: nothing is sent.
      ctx.http.expectNone(revokeUrl(ID.admin));
    });

    it('is NOT chosen when the caller has the same address but a different id', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true, callerId: CALLER_ID });
      // The caller's own directory entry carries the very same address as the target.
      TestBed.inject(DirectoryCache).remember([user({ userId: CALLER_ID })]);
      const typed = vi.spyOn(TestBed.inject(NxDialog), 'confirmTyped');
      const page = await openTab(ctx);

      const root = await openStandard(ctx, page, ID.admin);

      expect(typed).not.toHaveBeenCalled();
      expect(byTestId(root, 'target-identity')).not.toBeNull();
      expect(text(byTestId(root, 'revoke-admin-warning'))).toBe(CONSOLE_COPY.revoke.adminWarning);
    });

    it('ids equal and a role known not to look like an administrator: the standard dialog', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true, callerId: USER_ID });
      const typed = vi.spyOn(TestBed.inject(NxDialog), 'confirmTyped');
      const page = await openTab(ctx);

      const root = await openStandard(ctx, page, ID.support);
      expect(typed).not.toHaveBeenCalled();
      expect(byTestId(root, 'target-identity')).not.toBeNull();
    });

    it('the typed confirm unlocks only on the exact role name', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true, callerId: USER_ID });
      const page = await openTab(ctx);
      revokeButton(ID.admin)?.click();
      await page.settle();

      const input = document.querySelector<HTMLInputElement>(
        '[data-testid="nx-input"]',
      ) as HTMLInputElement;
      const confirm = document.querySelector<HTMLButtonElement>(
        '[data-testid="nx-typed-confirm-confirm"]',
      ) as HTMLButtonElement;
      expect(text(document.querySelector('nx-typed-confirm-shell h2'))).toBe(
        format(CONSOLE_COPY.revoke.selfTitle, { role: 'TENANT_ADMIN' }),
      );

      for (const attempt of ['tenant_admin', 'TENANT_ADMI', 'TENANT ADMIN']) {
        input.value = attempt;
        input.dispatchEvent(new Event('input'));
        await page.settle();
        expect(confirm.getAttribute('aria-disabled')).toBe('true');
        confirm.click();
        await page.settle();
        ctx.http.expectNone(revokeUrl(ID.admin));
      }

      input.value = 'TENANT_ADMIN';
      input.dispatchEvent(new Event('input'));
      await page.settle();
      expect(confirm.getAttribute('aria-disabled')).toBe('false');
      confirm.click();
      await page.settle();
      const req = ctx.http.expectOne(revokeUrl(ID.admin));
      expect(req.request.method).toBe('DELETE');
      problem(req, 409, 'RBAC_002');
      await page.settle();
    });
  });

  describe('request budget (design §6.5)', () => {
    it('open ×1 GET (0 on a re-open); confirm DELETE ×1, then the list ×1 and the roles list ×1 (MN-1)', async () => {
      ctx = setup();
      const page = await openTab(ctx);

      revokeButton(ID.support)?.click();
      await page.settle();
      ctx.http.expectOne(permissionsUrl(ID.support)).flush(permissionSet(ID.support));
      await page.settle();
      button(dialog() as HTMLElement, 'revoke-cancel')?.click();
      await page.settle();

      // Re-opened: the summary is cached.
      revokeButton(ID.support)?.click();
      await page.settle();
      ctx.http.expectNone(permissionsUrl(ID.support));
      const root = dialog() as HTMLElement;
      expect(text(byTestId(root, 'revoke-loss'))).toContain(permissionLabel('role:read') ?? '');

      await confirmStandard(page, root);
      const deletes = ctx.http.match(revokeUrl(ID.support));
      expect(deletes).toHaveLength(1);
      expect(deletes[0].request.method).toBe('DELETE');
      noContent(deletes[0]);
      await page.settle();
      answerRolesReread(ctx);
      const reread = ctx.http.match(ASSIGNMENTS_URL);
      expect(reread).toHaveLength(1);
      reread[0].flush(assignments(AFTER_SUPPORT));
      await page.settle();
      ctx.http.expectNone(() => true);
    });

    it('a self-revoke adds exactly one profile read', async () => {
      const setupCtx = setup({ held: EVERY, isAdministrator: true, callerId: USER_ID });
      ctx = setupCtx;
      vi.spyOn(TestBed.inject(NxDialog), 'confirmTyped').mockReturnValue({
        afterClosed: () => of(true),
      } as ReturnType<NxDialog['confirmTyped']>);
      const page = await openTab(ctx);

      revokeButton(ID.admin)?.click();
      await page.settle();
      noContent(ctx.http.expectOne(revokeUrl(ID.admin)));
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments([assignment(ID.support, 'Support')]));
      await page.settle();

      expect(setupCtx.profileStub.reload).toHaveBeenCalledTimes(1);
      expect(setupCtx.profileStub.reload).toHaveBeenCalledWith('own-access-change');
      ctx.http.expectNone(() => true);
    });
  });

  describe('outcomes (design §11.4)', () => {
    it('204: closes, toasts "Role removed.", shows the revoke line and re-reads the list', async () => {
      const setupCtx = setup();
      ctx = setupCtx;
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.support);

      await confirmStandard(page, root);
      noContent(ctx.http.expectOne(revokeUrl(ID.support)));
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(AFTER_SUPPORT));
      await page.settle();

      expect(dialog()).toBeNull();
      expect(setupCtx.toasts.success).toHaveBeenCalledWith(CONSOLE_COPY.revoke.success);
      const line = byTestId(page.el(), 'user-roles-propagation') as HTMLElement;
      expect(text(line)).toBe(PROPAGATION_COPY.revoke);
      expect(line.getAttribute('role')).toBe('status');
      expect(revokeButton(ID.support)).toBeNull();
      expect(setupCtx.profileStub.reload).not.toHaveBeenCalled();
      expect(logged(ctx)).toContain('access_console_role_revoked');
      expect(logged(ctx)).not.toContain('Support');
    });

    it.each([
      ['204', false],
      ['404 ROLE_ASSIGNMENT_NOT_FOUND', true],
    ])('MN-1: re-reads the roles list once after a revoke (%s)', async (_name, converge) => {
      ctx = setup();
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.support);

      await confirmStandard(page, root);
      const sent = ctx.http.expectOne(revokeUrl(ID.support));
      if (converge) problem(sent, 404, 'ROLE_ASSIGNMENT_NOT_FOUND');
      else noContent(sent);
      await page.settle();

      const reread = ctx.http.match(ROLES_URL);
      expect(reread).toHaveLength(1);
      reread[0].flush(rolesPage());
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(AFTER_SUPPORT));
      await page.settle();
      ctx.http.expectNone(() => true);
    });

    it('404 ROLE_ASSIGNMENT_NOT_FOUND converges: "already removed" and the same re-read', async () => {
      const setupCtx = setup();
      ctx = setupCtx;
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.support);

      await confirmStandard(page, root);
      problem(ctx.http.expectOne(revokeUrl(ID.support)), 404, 'ROLE_ASSIGNMENT_NOT_FOUND');
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(AFTER_SUPPORT));
      await page.settle();

      expect(dialog()).toBeNull();
      expect(setupCtx.toasts.success).toHaveBeenCalledWith(
        RbacErrorMessages.ROLE_ASSIGNMENT_NOT_FOUND.body,
      );
      expect(byTestId(page.el(), 'user-roles-propagation')).toBeNull();
    });

    it('409 RBAC_002 (contract fixture): inline last-administrator copy, nothing changed, no re-read', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true });
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.admin);

      await confirmStandard(page, root);
      ctx.http
        .expectOne(revokeUrl(ID.admin))
        .flush(problemRbac002, { status: 409, statusText: 'Conflict' });
      await page.settle();

      expect(dialog()).not.toBeNull();
      const error = byTestId(root, 'revoke-dialog-error') as HTMLElement;
      expect(error.getAttribute('role')).toBe('alert');
      expect(text(error)).toContain(RbacErrorMessages.RBAC_002.title);
      expect(text(error)).toContain(RbacErrorMessages.RBAC_002.body);
      // The server's detail (which names a role) is never shown.
      expect(text(root)).not.toContain(problemRbac002.detail);
      ctx.http.expectNone(ASSIGNMENTS_URL);
      expect(revokeButton(ID.admin)).not.toBeNull();
    });

    it('409 RBAC_002 after the typed self confirm shows inline on the tab', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true, callerId: USER_ID });
      vi.spyOn(TestBed.inject(NxDialog), 'confirmTyped').mockReturnValue({
        afterClosed: () => of(true),
      } as ReturnType<NxDialog['confirmTyped']>);
      const router = TestBed.inject(Router);
      const page = await openTab(ctx);

      revokeButton(ID.admin)?.click();
      await page.settle();
      ctx.http
        .expectOne(revokeUrl(ID.admin))
        .flush(problemRbac002, { status: 409, statusText: 'Conflict' });
      await page.settle();

      const error = byTestId(page.el(), 'user-roles-revoke-error') as HTMLElement;
      expect(error.getAttribute('role')).toBe('alert');
      expect(text(error)).toContain(RbacErrorMessages.RBAC_002.body);
      expect(router.url).toBe(`/admin/access/users/${USER_ID}/roles`);
      ctx.http.expectNone(ASSIGNMENTS_URL);
    });

    it.each([
      [
        'NOT_TENANT_ADMIN',
        { reason: 'ADMINISTRATOR_REQUIRED' },
        Rbac001ReasonCopy.ADMINISTRATOR_REQUIRED,
      ],
      [
        'GRANT_EXCEEDS_CALLER',
        { reason: 'GRANT_EXCEEDS_CALLER' },
        Rbac001ReasonCopy.GRANT_EXCEEDS_CALLER,
      ],
      ['no reason', {}, Rbac001ReasonCopy.UNSPECIFIED],
    ] as const)('403 %s: the reason inline, the profile re-read', async (_name, extra, copy) => {
      const setupCtx = setup();
      ctx = setupCtx;
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.support);

      await confirmStandard(page, root);
      problem(ctx.http.expectOne(revokeUrl(ID.support)), 403, 'RBAC_001', extra);
      await page.settle();

      const error = byTestId(root, 'revoke-dialog-error') as HTMLElement;
      expect(text(error)).toContain(copy.title);
      expect(text(error)).toContain(copy.body);
      expect(text(root)).not.toContain('server text');
      expect(setupCtx.profileStub.reload).toHaveBeenCalledWith('denied-predicted-allowed');
      ctx.http.expectNone(ASSIGNMENTS_URL);
    });

    it('429 RBAC_011: a countdown on the confirm and the rows, no automatic retry, usable at zero', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      ctx = setup();
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.support);

      await confirmStandard(page, root);
      problem(ctx.http.expectOne(revokeUrl(ID.support)), 429, 'RBAC_011');
      await page.settle();

      const confirm = button(root, 'revoke-confirm') as HTMLButtonElement;
      expect(confirm.getAttribute('aria-disabled')).toBe('true');
      const wait = byTestId(root, 'revoke-dialog-wait') as HTMLElement;
      expect(text(wait)).toBe(format(CONSOLE_COPY.revoke.wait, { n: 30 }));
      expect(confirm.getAttribute('aria-describedby')).toBe(wait.id);
      confirm.click();
      await page.settle();
      ctx.http.expectNone(revokeUrl(ID.support));

      button(root, 'revoke-cancel')?.click();
      await page.settle();
      expect(revokeButton(ID.admin)?.getAttribute('aria-disabled')).toBe('true');

      await vi.advanceTimersByTimeAsync(30_000);
      await page.settle();
      ctx.http.expectNone(revokeUrl(ID.support));
      expect(revokeButton(ID.support)?.getAttribute('aria-disabled')).toBeNull();
    });

    it('a second confirm while the DELETE runs is ignored (FR-G5)', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.support);

      await confirmStandard(page, root);
      await confirmStandard(page, root);
      const deletes = ctx.http.match(revokeUrl(ID.support));
      expect(deletes).toHaveLength(1);
      noContent(deletes[0]);
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(AFTER_SUPPORT));
      await page.settle();
    });

    it('never predicts the last administrator: no up-front block and memberCount is not read (Q16)', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true });
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.admin);
      expect(button(root, 'revoke-confirm')?.getAttribute('aria-disabled')).toBeNull();
      expect(text(root)).not.toContain(RbacErrorMessages.RBAC_002.title);
    });
  });

  describe('own access (FR-C6 as amended, FR-G6; §6.3)', () => {
    it('after a self-revoke: one profile reload, then the toast, then /dashboard; never a refresh', async () => {
      const setupCtx = setup({ held: EVERY, isAdministrator: true, callerId: USER_ID });
      ctx = setupCtx;
      setupCtx.profileStub.reload.mockImplementation(() => setupCtx.profileStatus.set('loading'));
      vi.spyOn(TestBed.inject(NxDialog), 'confirmTyped').mockReturnValue({
        afterClosed: () => of(true),
      } as ReturnType<NxDialog['confirmTyped']>);
      const router = TestBed.inject(Router);
      const page = await openTab(ctx);

      revokeButton(ID.admin)?.click();
      await page.settle();
      noContent(ctx.http.expectOne(revokeUrl(ID.admin)));
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments([assignment(ID.support, 'Support')]));
      await page.settle();

      expect(setupCtx.profileStub.reload).toHaveBeenCalledTimes(1);
      // Still reading the profile: neither the toast nor the navigation yet.
      expect(setupCtx.toasts.info).not.toHaveBeenCalled();
      expect(router.url).toBe(`/admin/access/users/${USER_ID}/roles`);

      setupCtx.profileStatus.set('ready');
      await page.settle();

      expect(setupCtx.toasts.info).toHaveBeenCalledTimes(1);
      expect(setupCtx.toasts.info).toHaveBeenCalledWith(CONSOLE_COPY.save.ownAccess);
      expect(setupCtx.toasts.success).not.toHaveBeenCalled();
      expect(router.url).toBe('/dashboard');
      const reloadOrder = setupCtx.profileStub.reload.mock.invocationCallOrder[0];
      const toastOrder = setupCtx.toasts.info.mock.invocationCallOrder[0];
      expect(reloadOrder).toBeLessThan(toastOrder);
      expect(setupCtx.refresh).not.toHaveBeenCalled();
    });

    it('a standard revoke of a non-admin role from yourself re-reads the profile and stays', async () => {
      const setupCtx = setup({ held: EVERY, isAdministrator: true, callerId: USER_ID });
      ctx = setupCtx;
      const router = TestBed.inject(Router);
      const page = await openTab(ctx);
      const root = await openStandard(ctx, page, ID.support);

      await confirmStandard(page, root);
      noContent(ctx.http.expectOne(revokeUrl(ID.support)));
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(AFTER_SUPPORT));
      await page.settle();

      expect(setupCtx.profileStub.reload).toHaveBeenCalledWith('own-access-change');
      expect(setupCtx.toasts.info).toHaveBeenCalledWith(CONSOLE_COPY.save.ownAccess);
      expect(router.url).toBe(`/admin/access/users/${USER_ID}/roles`);
      expect(setupCtx.refresh).not.toHaveBeenCalled();
    });
  });

  it('has no axe violations on the standard dialog with the admin warning', async () => {
    ctx = setup({ held: EVERY, isAdministrator: true });
    const page = await openTab(ctx, { emailVerified: false });
    const root = await openStandard(ctx, page, ID.admin);
    await expect(expectNoAxeViolations(root)).resolves.toBeUndefined();
  });

  it('has no axe violations on the typed self-revoke dialog', async () => {
    ctx = setup({ held: EVERY, isAdministrator: true, callerId: USER_ID });
    const page = await openTab(ctx);
    revokeButton(ID.admin)?.click();
    await page.settle();
    const shell = document.querySelector('nx-typed-confirm-shell') as HTMLElement;
    await expect(expectNoAxeViolations(shell)).resolves.toBeUndefined();
  });
});

describe('own access through the real interceptor chain (RC-65, SD-4)', () => {
  it('the profile reload and the list re-read both 401 on the bumped epoch and share ONE refresh', async () => {
    const handleError = vi.fn();
    TestBed.configureTestingModule({
      providers: [
        { provide: APP_CONFIG, useValue: CONFIG },
        { provide: ErrorHandler, useValue: { handleError } },
        { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
        provideAnimationsAsync('noop'),
        provideHttpClient(
          withInterceptors([correlationIdInterceptor, apiErrorInterceptor, authInterceptor]),
        ),
        provideHttpClientTesting(),
        DirectoryCache,
        provideRouter([
          { path: 'dashboard', component: Placeholder },
          {
            path: 'admin/access',
            providers: [
              RolesStore,
              AuthorizationProfileStore,
              {
                provide: CatalogueStore,
                useValue: {
                  state: signal({ status: 'ready', loadedAt: 0, data: { total: CATALOGUE_TOTAL } }),
                  load: vi.fn(),
                },
              },
            ],
            children: [userRoute()],
          },
        ]),
      ],
    });
    TestBed.inject(AuthStore).setSession(
      createAuthSession({ user: createAuthUser({ userId: USER_ID, permissions: [...EVERY] }) }),
    );
    const tools = instrument();
    const ctx = { ...tools, handleError };
    vi.spyOn(TestBed.inject(NxDialog), 'confirmTyped').mockReturnValue({
      afterClosed: () => of(true),
    } as ReturnType<NxDialog['confirmTyped']>);
    const router = TestBed.inject(Router);

    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl(`/admin/access/users/${USER_ID}/roles`);
    harness.detectChanges();
    ctx.http.expectOne(USER_URL).flush(user());
    ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
    await settleAll(harness);
    for (const req of ctx.http.match(ROLES_URL)) req.flush(rolesPage());
    await settleAll(harness);
    // The console layout reads the live profile on entry; without the layout, the route-scoped
    // store the tab uses is read here.
    const store = harness.fixture.debugElement
      .query(By.directive(UserRolesTab))
      .injector.get(AuthorizationProfileStore);
    store.load();
    const profileRead: CallerAuthorizationResponse = {
      userId: USER_ID,
      roles: [{ roleId: ID.admin, name: 'TENANT_ADMIN' }],
      permissions: [...EVERY],
      isAdministrator: true,
    };
    ctx.http.expectOne(PROFILE_URL).flush(profileRead);
    await settleAll(harness);

    revokeButton(ID.admin)?.click();
    await settleAll(harness);
    noContent(ctx.http.expectOne(revokeUrl(ID.admin)));
    await settleAll(harness);

    // Every re-read (the list, the profile and, MN-1, the roles list) leaves on the old token and
    // is refused on the bumped epoch.
    const stale = { code: 'AUTH_003', detail: 'stale', traceId: 't-401' };
    ctx.http.expectOne(ASSIGNMENTS_URL).flush(stale, { status: 401, statusText: 'Unauthorized' });
    ctx.http.expectOne(PROFILE_URL).flush(stale, { status: 401, statusText: 'Unauthorized' });
    ctx.http.expectOne(ROLES_URL).flush(stale, { status: 401, statusText: 'Unauthorized' });

    const refreshes = ctx.http.match((req) => req.method === 'POST' && req.url === REFRESH_URL);
    expect(refreshes).toHaveLength(1);
    refreshes[0].flush({
      accessToken: 'renewed',
      tokenType: 'Bearer',
      expiresIn: 900,
      userId: USER_ID,
    });
    ctx.http.expectOne(`${API}/v1/users/me`).flush({
      userId: USER_ID,
      tenantId: 'tenant-456',
      emailVerified: true,
      roles: ['USER'],
      permissions: ['user:read'],
      tokenVersion: 2,
    });
    await settleAll(harness);

    const listReplay = ctx.http.expectOne(ASSIGNMENTS_URL);
    expect(listReplay.request.headers.get('Authorization')).toBe('Bearer renewed');
    listReplay.flush(assignments([assignment(ID.support, 'Support')]));
    const profileReplay = ctx.http.expectOne(PROFILE_URL);
    expect(profileReplay.request.headers.get('Authorization')).toBe('Bearer renewed');
    profileReplay.flush({
      ...profileRead,
      roles: [],
      permissions: ['user:read'],
      isAdministrator: false,
    });
    const rolesReplay = ctx.http.expectOne(ROLES_URL);
    expect(rolesReplay.request.headers.get('Authorization')).toBe('Bearer renewed');
    rolesReplay.flush(rolesPage());
    await settleAll(harness);

    // The one refresh is the interceptor's; the console started none of its own.
    expect(tools.refresh).toHaveBeenCalledTimes(1);
    expect(tools.toasts.info).toHaveBeenCalledWith(CONSOLE_COPY.save.ownAccess);
    expect(router.url).toBe('/dashboard');
    ctx.http.verify();
    expect(handleError).not.toHaveBeenCalled();
  });
});
