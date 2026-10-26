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
import { Route, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { of } from 'rxjs';
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
  PermissionResponse,
  RoleAssignmentListResponse,
  RoleAssignmentResponse,
  RoleListResponse,
  RoleResponse,
} from '../../../shared/types/api/rbac';
import type { UserDirectoryEntry, UserStatus } from '../../../shared/types/api/user-directory';
import { NxDialog, NxToast } from '../../../shared/ui';
import { ACCESS_MANAGEMENT_ROUTES } from '../access-management.routes';
import { CONSOLE_COPY, RbacErrorMessages, Rbac001ReasonCopy, format } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import { PROPAGATION_COPY } from '../copy/propagation';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore } from '../data/catalogue.store';
import { DirectoryCache } from '../data/directory-cache';
import type { LoadState } from '../data/load-state';
import { RolesStore } from '../data/roles.store';
import { UserRolesTab } from './user-roles.tab';

const API = 'http://localhost:1000/api';
const USER_ID = '0190a000-0000-7000-8000-000000000042';
const CALLER_ID = '0190a000-0000-7000-8000-0000000000ca';
/** Synthetic addresses only. */
const ADDRESS = 'assign.target@directory.invalid';
/** U+202E RIGHT-TO-LEFT OVERRIDE inside the local part (T-S15), written as a code point. */
const RLO = String.fromCodePoint(0x202e);
const RLO_ADDRESS = `assign${RLO}tegrat@directory.invalid`;
const USER_URL = `${API}/v1/users/${USER_ID}`;
const ASSIGNMENTS_URL = `${API}/v1/users/${USER_ID}/roles?page=0&size=100`;
const ASSIGN_URL = `${API}/v1/users/${USER_ID}/roles`;
const ROLES_URL = `${API}/v1/roles?page=0&size=100`;
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
  audit: '0190a000-0000-7000-8000-0000000000b2',
  directory: '0190a000-0000-7000-8000-0000000000b3',
  wide: '0190a000-0000-7000-8000-0000000000b4',
  admin: '0190a000-0000-7000-8000-0000000000b5',
  held: '0190a000-0000-7000-8000-0000000000b6',
} as const;

/** What each candidate grants, by code. */
const GRANTS: Readonly<Record<string, readonly string[]>> = {
  [ID.support]: ['role:read'],
  [ID.audit]: ['role:read', 'audit:read'],
  [ID.directory]: ['user:directory:read'],
  [ID.wide]: ['role:read', 'user:read', 'audit:read', 'tenant:read', 'role:write'],
  [ID.admin]: EVERY,
  [ID.held]: ['user:read'],
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
  role(ID.audit, 'Auditor'),
  role(ID.directory, 'Directory Reader'),
  role(ID.held, 'Held Already'),
  role(ID.support, 'Support'),
  role(ID.admin, 'TENANT_ADMIN', true),
  role(ID.wide, 'Wide'),
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

const HELD = [assignment(ID.held, 'Held Already')] as const;

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
  const profileStatus = signal<'loading' | 'ready' | 'error'>('ready');
  const ready = (): boolean => profileStatus() === 'ready';
  // A re-read of a ready profile keeps its data (stale-while-revalidate) with mutations off.
  const profileReloading = signal(false);
  const profileStub = {
    state: () => ({ status: profileStatus() }),
    reloading: profileReloading,
    settled: () => profileStatus() !== 'loading' && !profileReloading(),
    userId: () => (ready() ? (options.callerId ?? CALLER_ID) : null),
    can: (p: string) => ready() && held.includes(p),
    permissions: () => new Set(ready() ? held : []),
    isAdministrator: () => ready() && (options.isAdministrator ?? false),
    mutationsEnabled: () => ready() && !profileReloading(),
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
  TestBed.configureTestingModule({
    providers: [
      { provide: APP_CONFIG, useValue: CONFIG },
      { provide: ErrorHandler, useValue: { handleError } },
      { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
      {
        provide: AuthStore,
        useValue: createAuthStoreStub({
          session: createAuthSession({
            user: createAuthUser({ userId: options.callerId ?? CALLER_ID }),
          }),
          permissions: held,
        }),
      },
      provideAnimationsAsync('noop'),
      provideHttpClient(withInterceptors([apiErrorInterceptor])),
      provideHttpClientTesting(),
      DirectoryCache,
      provideRouter([
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
  const logger = TestBed.inject(LoggerService);
  const logs = [
    vi.spyOn(logger, 'debug'),
    vi.spyOn(logger, 'info'),
    vi.spyOn(logger, 'warn'),
    vi.spyOn(logger, 'error'),
  ];
  const toast = TestBed.inject(NxToast);
  const toasts = [
    vi.spyOn(toast, 'success').mockImplementation(() => undefined),
    vi.spyOn(toast, 'info').mockImplementation(() => undefined),
    vi.spyOn(toast, 'warning').mockImplementation(() => undefined),
    vi.spyOn(toast, 'error').mockImplementation(() => undefined),
  ];
  return {
    http: TestBed.inject(HttpTestingController),
    handleError,
    logs,
    toasts,
    profileStub,
    profileStatus,
    profileReloading,
    catalogueStub,
  };
}

type Ctx = ReturnType<typeof setup>;

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
  await harness.navigateByUrl(`/admin/access/users/${USER_ID}/roles`);
  harness.detectChanges();
  ctx.http.expectOne(USER_URL).flush(user(target));
  ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(held));
  await settleAll(harness);
  for (const req of ctx.http.match(ROLES_URL)) req.flush(rolesPage());
  await settleAll(harness);
  const el = (): HTMLElement => harness.routeNativeElement as HTMLElement;
  const settle = (): Promise<void> => settleAll(harness);
  const tab = (): UserRolesTab =>
    harness.fixture.debugElement.query(By.directive(UserRolesTab))
      .componentInstance as UserRolesTab;
  return { harness, el, settle, tab };
}

function byTestId(root: ParentNode, id: string): HTMLElement | null {
  return root.querySelector(`[data-testid="${id}"]`);
}

function allByTestId(root: ParentNode, id: string): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(`[data-testid="${id}"]`));
}

function text(node: Element | null | undefined): string {
  return node?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
}

function button(root: ParentNode, id: string): HTMLButtonElement | null {
  return byTestId(root, id)?.querySelector('button') ?? null;
}

function dialog(): HTMLElement | null {
  return byTestId(document, 'assign-dialog');
}

function option(roleId: string): HTMLElement | null {
  return document.querySelector(`[data-testid="assign-role-option"][data-role-id="${roleId}"]`);
}

function radio(roleId: string): HTMLInputElement | null {
  return option(roleId)?.querySelector('input[type="radio"]') ?? null;
}

function permissionsUrl(roleId: string): string {
  return `${API}/v1/roles/${roleId}/permissions`;
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
  return JSON.stringify(ctx.toasts.flatMap((spy) => spy.mock.calls));
}

/** MN-1: a completed assign or revoke reads the console's roles list again, exactly once. */
function answerRolesReread(ctx: Ctx): void {
  const reread = ctx.http.match(ROLES_URL);
  expect(reread).toHaveLength(1);
  reread[0].flush(rolesPage());
}

/** Opens the Assign dialog from the tab. */
async function openDialog(page: Awaited<ReturnType<typeof openTab>>): Promise<HTMLElement> {
  button(page.el(), 'user-roles-assign')?.click();
  await page.settle();
  const root = dialog();
  if (root === null) throw new Error('Assign dialog did not open');
  return root;
}

/** Selects a candidate and answers its permissions read. */
async function select(
  ctx: Ctx,
  page: Awaited<ReturnType<typeof openTab>>,
  roleId: string,
): Promise<void> {
  radio(roleId)?.click();
  await page.settle();
  for (const req of ctx.http.match(permissionsUrl(roleId))) {
    req.flush(permissionSet(roleId), { headers: { ETag: '"v1"' } });
  }
  await page.settle();
}

describe('Assign dialog (US-020 design §6.5, §8.3, §12.9; RC-68, RC-69, H-2, D-4)', () => {
  let ctx: Ctx;

  afterEach(() => {
    const titleAfter = document.title;
    vi.restoreAllMocks();
    ctx.http.verify();
    // RC-73: nothing reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
    // PII: no address in a log line or a toast, and never in the document title.
    expect(logged(ctx)).not.toContain(ADDRESS);
    expect(logged(ctx)).not.toContain('directory.invalid');
    expect(toasted(ctx)).not.toContain('directory.invalid');
    expect(titleAfter).not.toContain('directory.invalid');
    expect(titleAfter).not.toContain(CONSOLE_COPY.assign.open);
  });

  describe('the Assign role button (design §12.8, FR-C4)', () => {
    it('is not shown without user:role:assign', async () => {
      ctx = setup({ held: ['role:read', 'user:read', 'user:directory:read'] });
      const page = await openTab(ctx);
      expect(byTestId(page.el(), 'user-roles-assign')).toBeNull();
    });

    it("is disabled with the reason on the caller's own page for a non-administrator", async () => {
      ctx = setup({ callerId: USER_ID });
      const page = await openTab(ctx);

      const assign = button(page.el(), 'user-roles-assign') as HTMLButtonElement;
      expect(assign.getAttribute('aria-disabled')).toBe('true');
      expect(text(byTestId(page.el(), 'user-roles-assign-reason'))).toBe(
        CONSOLE_COPY.disabledReason.selfAssign,
      );
      expect(assign.getAttribute('aria-describedby')).toBe(
        byTestId(page.el(), 'user-roles-assign-reason')?.id,
      );
      assign.click();
      await page.settle();
      expect(dialog()).toBeNull();
    });

    it('is disabled with the reason without role:read, which the picker needs (Q19)', async () => {
      ctx = setup({ held: ['user:read', 'user:role:assign', 'user:directory:read'] });
      const page = await openTab(ctx);

      expect(button(page.el(), 'user-roles-assign')?.getAttribute('aria-disabled')).toBe('true');
      expect(text(byTestId(page.el(), 'user-roles-assign-reason'))).toBe(
        CONSOLE_COPY.disabledReason.noRoleRead,
      );
    });

    it('is disabled with the reason while the live profile is unavailable (Q8)', async () => {
      ctx = setup();
      ctx.profileStatus.set('error');
      const page = await openTab(ctx);

      expect(button(page.el(), 'user-roles-assign')?.getAttribute('aria-disabled')).toBe('true');
      expect(text(byTestId(page.el(), 'user-roles-assign-reason'))).toBe(
        CONSOLE_COPY.disabledReason.profileUnavailable,
      );
    });
  });

  describe('request budget (design §6.5)', () => {
    it('open 0; a candidate ×1, cached for a re-selection; confirm POST ×1 then the re-reads ×1 each (MN-1)', async () => {
      ctx = setup();
      const page = await openTab(ctx);

      await openDialog(page);
      ctx.http.expectNone(() => true);

      radio(ID.support)?.click();
      await page.settle();
      ctx.http.expectOne(permissionsUrl(ID.support)).flush(permissionSet(ID.support));
      await page.settle();

      radio(ID.audit)?.click();
      await page.settle();
      ctx.http.expectOne(permissionsUrl(ID.audit)).flush(permissionSet(ID.audit));
      await page.settle();

      // Back to Support: cached for the dialog's life, no second GET.
      radio(ID.support)?.click();
      await page.settle();
      ctx.http.expectNone(permissionsUrl(ID.support));

      button(document, 'assign-confirm')?.click();
      await page.settle();
      const post = ctx.http.expectOne(ASSIGN_URL);
      expect(post.request.method).toBe('POST');
      expect(post.request.body).toEqual({ roleId: ID.support });
      post.flush(assignment(ID.support, 'Support'), { status: 201, statusText: 'Created' });
      await page.settle();

      answerRolesReread(ctx);
      const reread = ctx.http.match(ASSIGNMENTS_URL);
      expect(reread).toHaveLength(1);
      reread[0].flush(assignments([...HELD, assignment(ID.support, 'Support')]));
      await page.settle();
      ctx.http.expectNone(() => true);
    });

    it('the pigeonhole pre-check makes no request: the option is disabled with its reason', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      await openDialog(page);

      const wide = radio(ID.wide) as HTMLInputElement;
      expect(wide.disabled).toBe(true);
      expect(text(option(ID.wide)?.querySelector('[data-testid="assign-role-reason"]'))).toBe(
        CONSOLE_COPY.disabledReason.roleNeedsMoreAccessUnlisted,
      );
      wide.click();
      await page.settle();
      ctx.http.expectNone(permissionsUrl(ID.wide));
    });

    it('a held role is disabled "Already assigned" and is never requested', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      await openDialog(page);

      expect(radio(ID.held)?.disabled).toBe(true);
      expect(text(option(ID.held)?.querySelector('[data-testid="assign-role-reason"]'))).toBe(
        CONSOLE_COPY.disabledReason.alreadyAssigned,
      );
      ctx.http.expectNone(permissionsUrl(ID.held));
    });

    it('RBAC_012: the POST is re-sent once, then the list is re-read once', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      await openDialog(page);
      await select(ctx, page, ID.support);

      button(document, 'assign-confirm')?.click();
      await page.settle();
      problem(ctx.http.expectOne(ASSIGN_URL), 409, 'RBAC_012');
      await page.settle();
      ctx.http
        .expectOne(ASSIGN_URL)
        .flush(assignment(ID.support, 'Support'), { status: 201, statusText: 'Created' });
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await page.settle();
    });
  });

  describe('the dialog', () => {
    it('titles the dialog with the address through UserText, and shows TargetIdentity under it', async () => {
      ctx = setup();
      const page = await openTab(ctx, { email: RLO_ADDRESS, emailVerified: false });
      const root = await openDialog(page);

      const heading = byTestId(root, 'assign-dialog-title') as HTMLElement;
      expect(heading.tagName).toBe('H2');
      expect(text(heading)).toContain('Assign a role to');
      expect(heading.querySelector('[data-testid="user-text-hidden-token"]')?.textContent).toBe(
        '⟨U+202E⟩',
      );
      const identity = byTestId(root, 'target-identity') as HTMLElement;
      expect(
        identity.querySelector('[data-testid="user-status-badge"]')?.getAttribute('data-status'),
      ).toBe('ACTIVE');
      expect(text(byTestId(identity, 'target-identity-verified'))).toContain(
        CONSOLE_COPY.badges.unverified,
      );
      expect(byTestId(identity, 'user-text-hidden-badge')).not.toBeNull();
      expect(byTestId(identity, 'user-text-hidden-token')?.textContent).toBe('⟨U+202E⟩');
      // The raw override never reaches the dialog.
      expect(root.textContent).not.toContain(RLO);
    });

    it('lists candidates with the System badge and permission count, and filters by search', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      const root = await openDialog(page);

      expect(allByTestId(root, 'assign-role-option')).toHaveLength(ROLES.length);
      expect(text(option(ID.support))).toContain('Support');
      expect(text(option(ID.support))).toContain(
        format(CONSOLE_COPY.assign.permissionCountOne, { n: 1 }),
      );
      expect(option(ID.admin)?.querySelector('[data-testid="system-role-badge"]')).not.toBeNull();

      const search = root.querySelector('[data-testid="nx-search-input"]') as HTMLInputElement;
      search.value = 'aud';
      search.dispatchEvent(new Event('input'));
      search.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
      await page.settle();
      expect(
        allByTestId(root, 'assign-role-option').map((node) => node.getAttribute('data-role-id')),
      ).toEqual([ID.audit]);

      search.value = 'zzz';
      search.dispatchEvent(new Event('input'));
      search.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
      await page.settle();
      expect(text(byTestId(root, 'assign-no-match'))).toBe(CONSOLE_COPY.assign.noMatches);
    });

    it('keeps Assign disabled until a valid, loaded selection, then shows what the role grants', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      const root = await openDialog(page);

      expect(button(root, 'assign-confirm')?.getAttribute('aria-disabled')).toBe('true');
      radio(ID.support)?.click();
      await page.settle();
      expect(byTestId(root, 'assign-selected-loading')).not.toBeNull();
      expect(button(root, 'assign-confirm')?.getAttribute('aria-disabled')).toBe('true');

      ctx.http.expectOne(permissionsUrl(ID.support)).flush(permissionSet(ID.support));
      await page.settle();
      expect(text(byTestId(root, 'assign-selected-grants'))).toBe(
        format(CONSOLE_COPY.assign.grants, { labels: permissionLabel('role:read') ?? '' }),
      );
      const confirm = button(root, 'assign-confirm') as HTMLButtonElement;
      expect(confirm.getAttribute('aria-disabled')).toBeNull();
      expect(text(confirm)).toBe(CONSOLE_COPY.assign.confirm);
      expect(byTestId(root, 'assign-confirm')?.querySelector('.nx-btn--primary')).not.toBeNull();
    });

    it('C3(b): a loaded role with a permission the caller lacks disables Assign with the labels', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      const root = await openDialog(page);
      await select(ctx, page, ID.audit);

      expect(text(byTestId(root, 'assign-selected-reason'))).toBe(
        format(CONSOLE_COPY.disabledReason.roleNeedsMoreAccess, {
          labels: permissionLabel('audit:read') ?? '',
        }),
      );
      expect(button(root, 'assign-confirm')?.getAttribute('aria-disabled')).toBe('true');
    });

    it('PII rule: a role carrying user:directory:read is administrator-only', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      const root = await openDialog(page);
      await select(ctx, page, ID.directory);

      expect(text(byTestId(root, 'assign-selected-reason'))).toBe(
        CONSOLE_COPY.disabledReason.adminOnlyDirectory,
      );
      expect(button(root, 'assign-confirm')?.getAttribute('aria-disabled')).toBe('true');
    });

    it('(c) a hinted admin role for a non-administrator: the hint, with the PII reason that follows from it', async () => {
      ctx = setup({ held: EVERY });
      const page = await openTab(ctx);
      const root = await openDialog(page);
      await select(ctx, page, ID.admin);

      expect(text(byTestId(root, 'assign-selected-hint'))).toBe(CONSOLE_COPY.hints.adminAssign);
      // The whole catalogue includes user:directory:read: only an administrator may grant it.
      expect(text(byTestId(root, 'assign-selected-reason'))).toBe(
        CONSOLE_COPY.disabledReason.adminOnlyDirectory,
      );
      expect(button(root, 'assign-confirm')?.getAttribute('aria-disabled')).toBe('true');
    });

    it('(c) gives an administrator no hint and an enabled confirm for the admin role', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true });
      const page = await openTab(ctx);
      const root = await openDialog(page);
      await select(ctx, page, ID.admin);

      expect(byTestId(root, 'assign-selected-hint')).toBeNull();
      expect(byTestId(root, 'assign-selected-reason')).toBeNull();
      expect(button(root, 'assign-confirm')?.getAttribute('aria-disabled')).toBeNull();
    });
  });

  describe('PENDING targets (RC-69, H-2, D-4)', () => {
    const PENDING: Partial<UserDirectoryEntry> = {
      status: 'PENDING' as UserStatus,
      emailVerified: false,
    };

    it('shows the risk warning as role=alert and the "Assign to unverified account" danger confirm', async () => {
      ctx = setup();
      const page = await openTab(ctx, PENDING);
      const root = await openDialog(page);

      const warning = byTestId(root, 'assign-pending-warning') as HTMLElement;
      expect(warning.querySelector('[role="alert"]')).not.toBeNull();
      expect(text(warning)).toContain(CONSOLE_COPY.assign.pendingWarning);

      await select(ctx, page, ID.support);
      const confirm = button(root, 'assign-confirm') as HTMLButtonElement;
      // Never disabled because the target is PENDING.
      expect(confirm.getAttribute('aria-disabled')).toBeNull();
      expect(text(confirm)).toBe(CONSOLE_COPY.assign.confirmUnverified);
      expect(byTestId(root, 'assign-confirm')?.querySelector('.nx-btn--danger')).not.toBeNull();

      confirm.click();
      await page.settle();
      ctx.http
        .expectOne(ASSIGN_URL)
        .flush(assignment(ID.support, 'Support'), { status: 201, statusText: 'Created' });
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await page.settle();
    });

    it('H-2: a hinted admin-defining role is disabled with pending-admin-role, without a request', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true });
      const page = await openTab(ctx, PENDING);
      await openDialog(page);

      expect(radio(ID.admin)?.disabled).toBe(true);
      expect(text(option(ID.admin)?.querySelector('[data-testid="assign-role-reason"]'))).toBe(
        CONSOLE_COPY.disabledReason.pendingAdminRole,
      );
      ctx.http.expectNone(permissionsUrl(ID.admin));
    });

    it('D-4: with the catalogue total unknown, every role is disabled with its own reason', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true, catalogueTotal: null });
      const page = await openTab(ctx, PENDING);
      await openDialog(page);

      for (const candidate of ROLES.filter((entry) => entry.id !== ID.held)) {
        expect(radio(candidate.id)?.disabled).toBe(true);
        // Not the administrator-role copy: a one-permission role is not an administrator role.
        expect(
          text(option(candidate.id)?.querySelector('[data-testid="assign-role-reason"]')),
        ).toBe(CONSOLE_COPY.disabledReason.pendingCatalogueUnknown);
      }
    });

    it('MJ-3: a PENDING target makes the tab read the catalogue once, so the total becomes known', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true, catalogueTotal: null });
      const page = await openTab(ctx, PENDING);

      expect(ctx.catalogueStub.load).toHaveBeenCalledTimes(1);
      ctx.catalogueStub.state.set({
        status: 'ready',
        loadedAt: 0,
        data: { total: CATALOGUE_TOTAL },
      });
      await openDialog(page);

      expect(radio(ID.support)?.disabled).toBe(false);
      expect(radio(ID.admin)?.disabled).toBe(true);
      expect(text(option(ID.admin)?.querySelector('[data-testid="assign-role-reason"]'))).toBe(
        CONSOLE_COPY.disabledReason.pendingAdminRole,
      );
    });

    it('MJ-3: a failed catalogue read says so in the dialog, and its Retry reads it again', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true, catalogueTotal: null });
      const page = await openTab(ctx, PENDING);
      ctx.catalogueStub.state.set({
        status: 'error',
        error: { code: 'INTERNAL_ERROR', message: 'synthetic' },
        failedAt: 0,
      });
      const root = await openDialog(page);
      ctx.catalogueStub.load.mockClear();

      const failed = byTestId(root, 'assign-catalogue-error') as HTMLElement;
      expect(text(failed)).toContain(CONSOLE_COPY.assign.catalogueFailed);
      failed.querySelector('button')?.click();
      await page.settle();
      expect(ctx.catalogueStub.load).toHaveBeenCalledTimes(1);
    });

    it('MJ-3: a verified target never reads the catalogue (design §6.5: open 0)', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true, catalogueTotal: null });
      const page = await openTab(ctx);
      await openDialog(page);

      expect(ctx.catalogueStub.load).not.toHaveBeenCalled();
      expect(byTestId(document, 'assign-catalogue-error')).toBeNull();
    });

    it('Low 1: an ACTIVE account that has not verified its address gets the PENDING protections', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true });
      const page = await openTab(ctx, { status: 'ACTIVE', emailVerified: false });
      const root = await openDialog(page);

      expect(byTestId(root, 'assign-pending-warning')).not.toBeNull();
      expect(radio(ID.admin)?.disabled).toBe(true);
      expect(text(option(ID.admin)?.querySelector('[data-testid="assign-role-reason"]'))).toBe(
        CONSOLE_COPY.disabledReason.pendingAdminRole,
      );
      await select(ctx, page, ID.support);
      expect(text(button(root, 'assign-confirm'))).toBe(CONSOLE_COPY.assign.confirmUnverified);
    });

    it('with the H-2 block switched off (spec only, post-F-4 path): the typed confirm with the role name', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true });
      const typed = vi
        .spyOn(TestBed.inject(NxDialog), 'confirmTyped')
        .mockReturnValue({ afterClosed: () => of(true) } as ReturnType<NxDialog['confirmTyped']>);
      const page = await openTab(ctx, PENDING);
      page.tab()['pendingAdminRoleBlock'].set(false);
      const root = await openDialog(page);
      await select(ctx, page, ID.admin);

      const confirm = button(root, 'assign-confirm') as HTMLButtonElement;
      expect(text(confirm)).toBe(CONSOLE_COPY.assign.confirmUnverified);
      confirm.click();
      await page.settle();

      expect(typed).toHaveBeenCalledTimes(1);
      expect(typed.mock.calls[0][0]).toMatchObject({
        title: format(CONSOLE_COPY.assign.typedTitle, { role: 'TENANT_ADMIN' }),
        expectedText: 'TENANT_ADMIN',
        confirmLabel: CONSOLE_COPY.assign.confirmUnverified,
      });
      ctx.http
        .expectOne(ASSIGN_URL)
        .flush(assignment(ID.admin, 'TENANT_ADMIN'), { status: 201, statusText: 'Created' });
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await page.settle();
    });

    it('the typed confirm cancelled sends nothing', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true });
      vi.spyOn(TestBed.inject(NxDialog), 'confirmTyped').mockReturnValue({
        afterClosed: () => of(false),
      } as ReturnType<NxDialog['confirmTyped']>);
      const page = await openTab(ctx, PENDING);
      page.tab()['pendingAdminRoleBlock'].set(false);
      await openDialog(page);
      await select(ctx, page, ID.admin);

      button(document, 'assign-confirm')?.click();
      await page.settle();
      ctx.http.expectNone(ASSIGN_URL);
      expect(dialog()).not.toBeNull();
    });
  });

  describe('outcomes (design §12.9)', () => {
    it('201: closes, toasts "Role assigned.", shows the grant line, and re-reads the list', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      await openDialog(page);
      await select(ctx, page, ID.support);

      button(document, 'assign-confirm')?.click();
      await page.settle();
      ctx.http
        .expectOne(ASSIGN_URL)
        .flush(assignment(ID.support, 'Support'), { status: 201, statusText: 'Created' });
      await page.settle();
      answerRolesReread(ctx);
      ctx.http
        .expectOne(ASSIGNMENTS_URL)
        .flush(assignments([...HELD, assignment(ID.support, 'Support')]));
      await page.settle();

      expect(dialog()).toBeNull();
      expect(ctx.toasts[0]).toHaveBeenCalledWith(CONSOLE_COPY.assign.success);
      expect(text(byTestId(page.el(), 'user-roles-propagation'))).toBe(PROPAGATION_COPY.grant);
      expect(byTestId(page.el(), 'user-roles-propagation')?.getAttribute('role')).toBe('status');
      expect(ctx.profileStub.reload).not.toHaveBeenCalled();
    });

    it('MN-1: re-reads the roles list once after an assign, keeping the Type badges meanwhile', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      expect(text(byTestId(page.el(), 'user-role-type'))).not.toBe(
        CONSOLE_COPY.userRoles.typeUnknown,
      );
      await openDialog(page);
      await select(ctx, page, ID.support);

      button(document, 'assign-confirm')?.click();
      await page.settle();
      ctx.http
        .expectOne(ASSIGN_URL)
        .flush(assignment(ID.support, 'Support'), { status: 201, statusText: 'Created' });
      await page.settle();

      // Member counts changed: the console's roles list is read again, once.
      const reread = ctx.http.match(ROLES_URL);
      expect(reread).toHaveLength(1);
      // The assignments re-read answers first; the roles re-read is still pending. The join must
      // be retained meanwhile, so the table shows real Type badges (a missing cell proves nothing).
      ctx.http
        .expectOne(ASSIGNMENTS_URL)
        .flush(assignments([...HELD, assignment(ID.support, 'Support')]));
      await page.settle();
      const typeCell = byTestId(page.el(), 'user-role-type');
      expect(typeCell).not.toBeNull();
      expect(text(typeCell)).not.toBe(CONSOLE_COPY.userRoles.typeUnknown);
      reread[0].flush(rolesPage());
      await page.settle();
      expect(byTestId(page.el(), 'user-roles-join-error')).toBeNull();
      ctx.http.expectNone(() => true);
    });

    it('MJ-5: while the profile re-reads, the picker keeps its reasons and the confirm is off', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      const root = await openDialog(page);
      await select(ctx, page, ID.support);
      expect(button(root, 'assign-confirm')?.getAttribute('aria-disabled')).toBeNull();

      ctx.profileReloading.set(true);
      await page.settle();

      // No pigeonhole flip: what the caller holds is still known.
      expect(radio(ID.support)?.disabled).toBe(false);
      expect(option(ID.support)?.querySelector('[data-testid="assign-role-reason"]')).toBeNull();
      expect(button(root, 'assign-confirm')?.getAttribute('aria-disabled')).toBe('true');
      button(root, 'assign-confirm')?.click();
      await page.settle();
      ctx.http.expectNone(ASSIGN_URL);

      ctx.profileReloading.set(false);
      await page.settle();
      expect(button(root, 'assign-confirm')?.getAttribute('aria-disabled')).toBeNull();
    });

    it('RBAC_004 converges: "This person already had this role." and the same re-read', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      await openDialog(page);
      await select(ctx, page, ID.support);

      button(document, 'assign-confirm')?.click();
      await page.settle();
      problem(ctx.http.expectOne(ASSIGN_URL), 409, 'RBAC_004');
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await page.settle();

      expect(dialog()).toBeNull();
      expect(ctx.toasts[0]).toHaveBeenCalledWith(RbacErrorMessages.RBAC_004.body);
      expect(text(byTestId(page.el(), 'user-roles-propagation'))).toBe(PROPAGATION_COPY.grant);
    });

    it.each([
      [
        '403 SELF_ASSIGNMENT',
        403,
        'RBAC_001',
        { reason: 'SELF_ASSIGNMENT' },
        Rbac001ReasonCopy.SELF_ASSIGNMENT,
      ],
      [
        '403 GRANT_EXCEEDS_CALLER',
        403,
        'RBAC_001',
        { reason: 'GRANT_EXCEEDS_CALLER' },
        Rbac001ReasonCopy.GRANT_EXCEEDS_CALLER,
      ],
      ['409 RBAC_010', 409, 'RBAC_010', {}, RbacErrorMessages.RBAC_010],
    ] as const)(
      '%s stays inline with the dialog open',
      async (_name, status, code, extra, copy) => {
        ctx = setup();
        const page = await openTab(ctx);
        const root = await openDialog(page);
        await select(ctx, page, ID.support);

        button(root, 'assign-confirm')?.click();
        await page.settle();
        problem(ctx.http.expectOne(ASSIGN_URL), status, code, extra);
        await page.settle();

        expect(dialog()).not.toBeNull();
        const error = byTestId(root, 'assign-error') as HTMLElement;
        expect(error.getAttribute('role')).toBe('alert');
        expect(text(error)).toContain(copy.title);
        expect(text(error)).toContain(copy.body);
        // The server's detail is never shown.
        expect(text(root)).not.toContain('server text');
        ctx.http.expectNone(ASSIGNMENTS_URL);
        if (status === 403) {
          expect(ctx.profileStub.reload).toHaveBeenCalledWith('denied-predicted-allowed');
        }
      },
    );

    it('the final RBAC_012 (after the one retry) stays inline', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      const root = await openDialog(page);
      await select(ctx, page, ID.support);

      button(root, 'assign-confirm')?.click();
      await page.settle();
      problem(ctx.http.expectOne(ASSIGN_URL), 409, 'RBAC_012');
      problem(ctx.http.expectOne(ASSIGN_URL), 409, 'RBAC_012');
      await page.settle();

      expect(text(byTestId(root, 'assign-error'))).toContain(RbacErrorMessages.RBAC_012.title);
      ctx.http.expectNone(ASSIGN_URL);
    });

    it('429 RBAC_011: a countdown on the confirm, no automatic retry, usable again at zero', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      try {
        ctx = setup();
        const page = await openTab(ctx);
        const root = await openDialog(page);
        await select(ctx, page, ID.support);

        button(root, 'assign-confirm')?.click();
        await page.settle();
        problem(ctx.http.expectOne(ASSIGN_URL), 429, 'RBAC_011', {});
        await page.settle();

        const confirm = button(root, 'assign-confirm') as HTMLButtonElement;
        expect(confirm.getAttribute('aria-disabled')).toBe('true');
        expect(text(byTestId(root, 'assign-wait'))).toBe(
          format(CONSOLE_COPY.assign.wait, { n: 30 }),
        );
        confirm.click();
        await page.settle();
        ctx.http.expectNone(ASSIGN_URL);

        await vi.advanceTimersByTimeAsync(30_000);
        await page.settle();
        ctx.http.expectNone(ASSIGN_URL);
        expect(button(root, 'assign-confirm')?.getAttribute('aria-disabled')).toBeNull();
      } finally {
        vi.useRealTimers();
      }
    });

    it('a second confirm while the POST runs is ignored (FR-G5)', async () => {
      ctx = setup();
      const page = await openTab(ctx);
      const root = await openDialog(page);
      await select(ctx, page, ID.support);

      button(root, 'assign-confirm')?.click();
      await page.settle();
      button(root, 'assign-confirm')?.click();
      await page.settle();
      const posts = ctx.http.match(ASSIGN_URL);
      expect(posts).toHaveLength(1);
      posts[0].flush(assignment(ID.support, 'Support'), { status: 201, statusText: 'Created' });
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await page.settle();
    });

    it('FR-G6: an administrator assigning to themself re-reads the live profile', async () => {
      ctx = setup({ held: EVERY, isAdministrator: true, callerId: USER_ID });
      const page = await openTab(ctx);
      await openDialog(page);
      await select(ctx, page, ID.support);

      button(document, 'assign-confirm')?.click();
      await page.settle();
      ctx.http
        .expectOne(ASSIGN_URL)
        .flush(assignment(ID.support, 'Support'), { status: 201, statusText: 'Created' });
      await page.settle();
      answerRolesReread(ctx);
      ctx.http.expectOne(ASSIGNMENTS_URL).flush(assignments(HELD));
      await page.settle();

      expect(ctx.profileStub.reload).toHaveBeenCalledWith('own-access-change');
      expect(ctx.toasts[1]).toHaveBeenCalledWith(CONSOLE_COPY.save.ownAccess);
    });
  });

  it('has no axe violations with a PENDING target, the warning and a selected role', async () => {
    ctx = setup();
    const page = await openTab(ctx, {
      status: 'PENDING',
      emailVerified: false,
      email: RLO_ADDRESS,
    });
    const root = await openDialog(page);
    await select(ctx, page, ID.support);
    await expect(expectNoAxeViolations(root)).resolves.toBeUndefined();
  });
});
