import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { Component, ErrorHandler, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { Route, Router, provideRouter } from '@angular/router';
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
import type { UserDirectoryEntry, UserStatus } from '../../../shared/types/api/user-directory';
import { ACCESS_MANAGEMENT_ROUTES } from '../access-management.routes';
import { CONSOLE_COPY, NotEnabledCopy, RbacErrorMessages } from '../copy/console-copy';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore } from '../data/catalogue.store';
import { DirectoryCache } from '../data/directory-cache';
import { RolesStore } from '../data/roles.store';

const API = 'http://localhost:1000/api';
const USER_ID = '0190a000-0000-7000-8000-000000000042';
const CALLER_ID = '0190a000-0000-7000-8000-0000000000ca';
const ADDRESS = 'person.detail@directory.invalid';
const userUrl = (id = USER_ID): string => `${API}/v1/users/${id}`;
const assignmentsUrl = (id = USER_ID): string => `${API}/v1/users/${id}/roles?page=0&size=100`;

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

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

@Component({ template: '<h1>Placeholder</h1>' })
class Placeholder {}

/** The real `users/:userId` route, so its providers, children and titles are the ones shipped. */
function userRoute(): Route {
  const layout = ACCESS_MANAGEMENT_ROUTES[0] as Route;
  const route = layout.children?.find((child) => child.path === 'users/:userId');
  if (route === undefined) throw new Error('users/:userId route missing');
  return route;
}

function setup(options: { permissions?: readonly string[]; profileUserId?: string | null } = {}) {
  // The roles join is the Roles tab's concern (user-roles.tab.spec); without role:read the tab
  // sends no roles GET, so these specs answer the page's own reads only.
  const permissions = options.permissions ?? ['user:directory:read', 'user:read'];
  const profileUserId = signal<string | null>(
    options.profileUserId === undefined ? CALLER_ID : options.profileUserId,
  );
  const profileStub = {
    state: () => ({ status: 'ready' }),
    userId: profileUserId,
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
      provideRouter([
        {
          path: 'admin/access',
          providers: [
            RolesStore,
            CatalogueStore,
            DirectoryCache,
            { provide: AuthorizationProfileStore, useValue: profileStub },
          ],
          children: [
            { path: '', component: Placeholder },
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
  return {
    http: TestBed.inject(HttpTestingController),
    router: TestBed.inject(Router),
    handleError,
    profileUserId,
    logs,
  };
}

type Ctx = ReturnType<typeof setup>;

async function open(url = `/admin/access/users/${USER_ID}`) {
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

function problem(req: TestRequest, status: number, code: string): void {
  req.flush(
    { code, detail: `server text with ${ADDRESS}`, traceId: `trace-${code}` },
    { status, statusText: 'Error' },
  );
}

/** Answers the user GET, and the assignments GET where it is pending. */
function answer(ctx: Ctx, entry: UserDirectoryEntry = user()): void {
  ctx.http.expectOne(userUrl(entry.userId)).flush(entry);
  for (const req of ctx.http.match(assignmentsUrl(entry.userId))) {
    req.flush({
      data: [],
      page: { size: 100, number: 0, totalElements: 0, totalPages: 0 },
      links: { next: null, prev: null },
    });
  }
}

function logged(ctx: Ctx): string {
  return JSON.stringify(ctx.logs.flatMap((spy) => spy.mock.calls));
}

describe('UserDetailPage (US-020 design §12.8)', () => {
  let ctx: Ctx;

  afterEach(() => {
    ctx.http.verify();
    // RC-73: no load failure ever reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
    // PII (SD-13): no log line carries the address.
    expect(logged(ctx)).not.toContain(ADDRESS);
  });

  it('shows a loading state with a focusable h1 before the user arrives', async () => {
    ctx = setup();
    const { el } = await open();

    const title = byTestId(el(), 'user-detail-title');
    expect(title?.tagName).toBe('H1');
    expect(title?.getAttribute('tabindex')).toBe('-1');
    expect(text(title)).toBe(CONSOLE_COPY.userDetail.loadingTitle);
    expect(byTestId(el(), 'user-detail-loading')?.getAttribute('aria-busy')).toBe('true');
    answer(ctx);
  });

  it('opens on the Roles tab under a static title that never carries the address (DQ-26)', async () => {
    ctx = setup();
    const { settle } = await open();
    answer(ctx);
    await settle();

    expect(ctx.router.url).toBe(`/admin/access/users/${USER_ID}/roles`);
    expect(document.title).toBe('User roles');
    expect(document.title).not.toContain('@');
  });

  it('heads the page with the address in email mode, status, Verified and the join date', async () => {
    ctx = setup();
    const { el, settle } = await open();
    answer(ctx);
    await settle();

    const title = byTestId(el(), 'user-detail-title');
    expect(title?.querySelector('[data-testid="user-text"]')?.textContent?.trim()).toBe(ADDRESS);
    expect(byTestId(el(), 'user-status-badge')?.getAttribute('data-status')).toBe('ACTIVE');
    const verified = byTestId(el(), 'user-verified');
    expect(verified?.getAttribute('data-verified')).toBe('true');
    expect(text(verified)).toContain(CONSOLE_COPY.badges.verified);
    expect(text(byTestId(el(), 'user-detail-joined'))).toBe('Joined Jan 2, 2026');
    expect(byTestId(el(), 'user-text-hidden-badge')).toBeNull();
    expect(byTestId(el(), 'user-status-banner')).toBeNull();
  });

  it('marks an unverified address', async () => {
    ctx = setup();
    const { el, settle } = await open();
    answer(ctx, user({ emailVerified: false }));
    await settle();

    const verified = byTestId(el(), 'user-verified');
    expect(verified?.getAttribute('data-verified')).toBe('false');
    expect(text(verified)).toContain(CONSOLE_COPY.badges.unverified);
  });

  it('shows hidden characters in the heading as tokens with the badge (RC-68)', async () => {
    ctx = setup();
    const { el, settle } = await open();
    answer(ctx, user({ email: 'person‮liated@directory.invalid' }));
    await settle();

    const title = byTestId(el(), 'user-detail-title');
    const token = title?.querySelector('[data-testid="user-text-hidden-token"]');
    expect(token?.textContent).toBe('⟨U+202E⟩');
    expect(token?.getAttribute('aria-label')).toBe('hidden character U+202E');
    expect(byTestId(el(), 'user-text-hidden-badge')).not.toBeNull();
    expect(title?.textContent).not.toContain('‮');
  });

  it('says "(you)" when the user id is the profile user id (FR-G8)', async () => {
    ctx = setup({ profileUserId: USER_ID });
    const { el, settle } = await open();
    answer(ctx);
    await settle();

    expect(text(byTestId(el(), 'user-you'))).toBe(CONSOLE_COPY.badges.you);
  });

  it('never says "(you)" for another id, nor before the profile is known', async () => {
    ctx = setup({ profileUserId: null });
    const { el, settle } = await open();
    answer(ctx);
    await settle();
    expect(byTestId(el(), 'user-you')).toBeNull();

    ctx.profileUserId.set(CALLER_ID);
    await settle();
    expect(byTestId(el(), 'user-you')).toBeNull();
  });

  it.each([
    ['LOCKED', "This person is locked out and can't sign in until the lock ends."],
    ['DISABLED', 'This account is disabled.'],
    ['PENDING', "This person hasn't verified their email address yet."],
  ] as const)('shows the %s status note in an info banner', async (status: UserStatus, note) => {
    ctx = setup();
    const { el, settle } = await open();
    answer(ctx, user({ status }));
    await settle();

    const banner = byTestId(el(), 'user-status-banner');
    expect(banner?.getAttribute('data-status')).toBe(status);
    expect(banner?.querySelector('.nx-banner--info')).not.toBeNull();
    expect(text(banner?.querySelector('[data-testid="nx-banner-title"]'))).toBe(note);
  });

  it('has a breadcrumb back to the console and the users list, with no address in it', async () => {
    ctx = setup();
    const { el, settle } = await open();
    answer(ctx);
    await settle();

    const crumbs = byTestId(el(), 'nx-breadcrumb');
    const links = Array.from(crumbs?.querySelectorAll('a') ?? []).map((a) =>
      a.getAttribute('href'),
    );
    expect(links).toEqual(['/admin/access', '/admin/access/users']);
    expect(text(crumbs)).not.toContain('@');
    expect(text(crumbs)).toContain(CONSOLE_COPY.userDetail.breadcrumbCurrent);
  });

  it('links the Roles tab to this user', async () => {
    ctx = setup();
    const { el, settle } = await open();
    answer(ctx);
    await settle();

    expect(byTestId(el(), 'user-tab-roles')?.getAttribute('href')).toBe(
      `/admin/access/users/${USER_ID}/roles`,
    );
  });

  it.each([
    ['USER_NOT_FOUND', 404],
    ['VALIDATION_FAILED', 400],
  ] as const)(
    '%s is the one "not found" page, for a missing, foreign or malformed id (SD-20)',
    async (code, status) => {
      ctx = setup();
      const { el, settle } = await open();
      problem(ctx.http.expectOne(userUrl()), status, code);
      for (const req of ctx.http.match(assignmentsUrl())) problem(req, status, code);
      await settle();

      expect(text(byTestId(el(), 'user-detail-title'))).toBe(
        RbacErrorMessages.USER_NOT_FOUND.title,
      );
      expect(text(byTestId(el(), 'user-not-found'))).toContain(
        RbacErrorMessages.USER_NOT_FOUND.body,
      );
      expect(byTestId(el(), 'user-not-found-back')?.getAttribute('href')).toBe(
        '/admin/access/users',
      );
      expect(byTestId(el(), 'user-tab-roles')).toBeNull();
      expect(byTestId(el(), 'user-detail-error')).toBeNull();
    },
  );

  it('shows the error panel on a failed read, and Retry reads the user again', async () => {
    ctx = setup();
    const { el, settle } = await open();
    problem(ctx.http.expectOne(userUrl()), 500, 'INTERNAL_ERROR');
    for (const req of ctx.http.match(assignmentsUrl())) problem(req, 500, 'INTERNAL_ERROR');
    await settle();

    const panel = byTestId(el(), 'user-detail-error');
    expect(text(panel)).toContain(RbacErrorMessages.INTERNAL_ERROR.title);
    expect(text(panel)).toContain('trace-INTERNAL_ERROR');
    expect(text(panel)).not.toContain('server text');
    expect(text(byTestId(el(), 'user-detail-title'))).toBe(CONSOLE_COPY.userDetail.fallbackTitle);

    panel?.querySelector<HTMLButtonElement>('button')?.click();
    await settle();
    answer(ctx);
    await settle();
    expect(byTestId(el(), 'user-detail-error')).toBeNull();
  });

  it('says the directory is not enabled when us019 is off, with no Retry', async () => {
    ctx = setup();
    const { el, settle } = await open();
    problem(ctx.http.expectOne(userUrl()), 404, 'RESOURCE_NOT_FOUND');
    for (const req of ctx.http.match(assignmentsUrl())) problem(req, 404, 'RESOURCE_NOT_FOUND');
    await settle();

    const panel = byTestId(el(), 'user-detail-error');
    expect(text(panel)).toContain(NotEnabledCopy.users.title);
    expect(panel?.querySelector('button')).toBeNull();
  });

  it('has no axe violations once loaded', async () => {
    ctx = setup();
    const { el, settle } = await open();
    answer(ctx, user({ status: 'PENDING', emailVerified: false }));
    await settle();

    await expect(expectNoAxeViolations(el())).resolves.toBeUndefined();
  });
});
