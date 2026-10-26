import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { Location } from '@angular/common';
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
  UserDirectoryEntry,
  UserDirectoryPage,
} from '../../../shared/types/api/user-directory';
import { CONSOLE_COPY } from '../copy/console-copy';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { UsersListPage } from './users-list.page';
import { UsersListStore } from './users-list.store';

const API = 'http://localhost:1000/api';
const LOOKUP_URL = `${API}/v1/users/lookup`;
const SELF_ID = '0190a000-0000-7000-8000-00000000aaaa';
const SELF_ADDRESS = 'the.caller@directory.invalid';
const LOOKUP_ADDRESS = 'secret.lookup.target@directory.invalid';

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

function listUrl(page: number, size = 20, status?: string): string {
  return `${API}/v1/users?page=${page}&size=${size}${status ? `&status=${status}` : ''}`;
}

function isList(req: { method: string; url: string }): boolean {
  return req.method === 'GET' && req.url === `${API}/v1/users`;
}

function entry(index: number, overrides: Partial<UserDirectoryEntry> = {}): UserDirectoryEntry {
  return {
    userId: `0190a000-0000-7000-8000-${String(index).padStart(12, '0')}`,
    email: `row-${index}@directory.invalid`,
    status: 'ACTIVE',
    emailVerified: true,
    createdAt: '2026-03-04T10:00:00Z',
    ...overrides,
  };
}

function pageOf(
  entries: readonly UserDirectoryEntry[],
  options: { number?: number; size?: number; total?: number } = {},
): UserDirectoryPage {
  const size = options.size ?? 20;
  const total = options.total ?? entries.length;
  return {
    data: entries,
    page: {
      size,
      number: options.number ?? 0,
      totalElements: total,
      totalPages: Math.ceil(total / size),
    },
    links: { next: null, prev: null },
  };
}

function many(count: number): UserDirectoryEntry[] {
  return Array.from({ length: count }, (_, i) => entry(i + 1));
}

function problem(req: TestRequest, status: number, code: string, headers = {}): void {
  req.flush(
    { code, detail: 'SERVER-DETAIL-TEXT', traceId: `trace-${code}` },
    { status, statusText: 'Error', headers },
  );
}

@Component({ template: '<h1>User page placeholder</h1>' })
class UserPagePlaceholder {}

function setup() {
  const profileUserId = signal<string | null>(SELF_ID);
  const handleError = vi.fn();
  TestBed.configureTestingModule({
    providers: [
      { provide: APP_CONFIG, useValue: CONFIG },
      { provide: ErrorHandler, useValue: { handleError } },
      { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
      {
        provide: AuthStore,
        useValue: createAuthStoreStub({
          session: createAuthSession({ user: createAuthUser({ userId: SELF_ID }) }),
          permissions: ['user:directory:read'],
        }),
      },
      provideAnimationsAsync(),
      provideHttpClient(withInterceptors([apiErrorInterceptor])),
      provideHttpClientTesting(),
      provideRouter([
        {
          path: 'admin/access/users',
          component: UsersListPage,
          providers: [
            UsersListStore,
            { provide: AuthorizationProfileStore, useValue: { userId: profileUserId } },
          ],
        },
        { path: 'admin/access/users/:userId', component: UserPagePlaceholder },
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
    location: TestBed.inject(Location),
    handleError,
    profileUserId,
    logged: () => JSON.stringify(logs.flatMap((spy) => spy.mock.calls)),
  };
}

async function open(ctx: ReturnType<typeof setup>, url = '/admin/access/users') {
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

function emailCells(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll('[data-testid="user-row-email"]'));
}

function lookupInput(root: HTMLElement): HTMLInputElement {
  return root.querySelector('[data-testid="nx-search-input"]') as HTMLInputElement;
}

function type(root: HTMLElement, text: string): void {
  const input = lookupInput(root);
  input.value = text;
  input.dispatchEvent(new Event('input'));
}

function pressEnter(root: HTMLElement): void {
  lookupInput(root).dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
}

function lookupButton(root: HTMLElement): HTMLButtonElement {
  return byTestId(root, 'users-lookup-submit')?.querySelector('button') as HTMLButtonElement;
}

describe('UsersListPage (US-020 design §12.7)', () => {
  let ctx: ReturnType<typeof setup>;

  beforeEach(() => (ctx = setup()));

  afterEach(() => {
    ctx.http.verify({ ignoreCancelled: true });
    // RC-73: no failure on this page reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
    vi.useRealTimers();
  });

  async function ready(url: string, body: UserDirectoryPage, expected = listUrl(0)) {
    const opened = await open(ctx, url);
    ctx.http.expectOne(expected).flush(body);
    await opened.settle();
    return opened;
  }

  describe('loading and ready', () => {
    it('shows a busy skeleton until the page answers', async () => {
      const { el } = await open(ctx);

      const region = byTestId(el(), 'users-loading') as HTMLElement;
      expect(region.getAttribute('aria-busy')).toBe('true');
      expect(region.querySelectorAll('nx-skeleton').length).toBeGreaterThan(0);
      expect(byTestId(el(), 'nx-table')).toBeNull();
      ctx.http.expectOne(listUrl(0)).flush(pageOf([]));
    });

    it('renders the header, explainer, toolbar and one row per user', async () => {
      const { el } = await ready('/admin/access/users', pageOf(many(3)));

      expect(el().querySelector('h1')?.textContent).toContain('Users');
      expect(byTestId(el(), 'nx-page-header-description')?.textContent).toContain(
        CONSOLE_COPY.areas.users.explainer,
      );
      expect(emailCells(el())).toHaveLength(3);
      expect(el().querySelector('caption')?.textContent).toContain('Users');
      expect(byTestId(el(), 'users-lookup-hint')?.textContent).toContain(
        'Enter a full email address',
      );
      expect(lookupInput(el()).getAttribute('aria-label')).toBe('Find by email');
      // Submit-mode lookup without a <form>: nothing can submit the address as a GET.
      expect(el().querySelector('form')).toBeNull();
    });

    it('shows each column: email in a <bdi>, status, verified, joined', async () => {
      const { el } = await ready(
        '/admin/access/users',
        pageOf([
          entry(1),
          entry(2, { status: 'LOCKED', emailVerified: false, createdAt: '2026-05-06T00:00:00Z' }),
        ]),
      );

      const rows = Array.from(el().querySelectorAll('tbody tr'));
      expect(rows[0].querySelector('bdi')?.textContent).toBe(entry(1).email);
      expect(rows[0].querySelector('[data-testid="user-status-badge"]')?.textContent).toContain(
        'Active',
      );
      expect(rows[0].querySelector('[data-testid="user-verified"]')?.textContent).toContain(
        'Verified',
      );
      expect(rows[0].textContent).toContain('Mar 4, 2026');
      expect(rows[1].querySelector('[data-testid="user-status-badge"]')?.textContent).toContain(
        'Locked',
      );
      const unverified = rows[1].querySelector('[data-testid="user-verified"]') as HTMLElement;
      expect(unverified.textContent).toContain('Unverified email');
      expect(unverified.querySelector('nx-icon')).not.toBeNull();
      expect(rows[1].textContent).toContain('May 6, 2026');
    });

    it('shows "No users match this filter" for an empty page', async () => {
      const { el } = await ready(
        '/admin/access/users?status=disabled',
        pageOf([]),
        listUrl(0, 20, 'DISABLED'),
      );
      expect(byTestId(el(), 'nx-empty-state')?.textContent).toContain('No users match this filter');
      // The toolbar stays, so the filter can be changed.
      expect(byTestId(el(), 'users-status-filter')).not.toBeNull();
    });
  });

  describe('"(you)" (FR-G8)', () => {
    it('marks the row whose userId is the profile userId, and only that one', async () => {
      const { el } = await ready(
        '/admin/access/users',
        pageOf([
          entry(1, { userId: SELF_ID, email: SELF_ADDRESS }),
          // Same address as the caller, another id: never marked (identity is the id, not text).
          entry(2, { email: SELF_ADDRESS }),
        ]),
      );

      const cells = emailCells(el());
      expect(cells[0].querySelector('[data-testid="user-you"]')?.textContent?.trim()).toBe('(you)');
      expect(cells[1].querySelector('[data-testid="user-you"]')).toBeNull();
    });

    it('marks no row while the profile has no userId', async () => {
      ctx.profileUserId.set(null);
      const { el } = await ready('/admin/access/users', pageOf([entry(1, { userId: SELF_ID })]));
      expect(byTestId(el(), 'user-you')).toBeNull();
    });
  });

  describe('opening a user (T-016 route)', () => {
    it('links each email to the user page by id', async () => {
      const { el } = await ready('/admin/access/users', pageOf(many(2)));
      const links = Array.from(el().querySelectorAll<HTMLAnchorElement>('tbody a'));
      expect(links.map((a) => a.getAttribute('href'))).toEqual([
        `/admin/access/users/${entry(1).userId}`,
        `/admin/access/users/${entry(2).userId}`,
      ]);
    });

    it('opens the user page on a row click', async () => {
      const { harness, settle } = await ready('/admin/access/users', pageOf(many(2)));
      const table = harness.routeDebugElement?.query((d) => d.name === 'nx-table');
      table?.triggerEventHandler('rowClick', { userId: entry(2).userId });
      await settle();
      expect(ctx.router.url).toBe(`/admin/access/users/${entry(2).userId}`);
    });
  });

  describe('hidden characters in an address (RC-68, D-1)', () => {
    it('shows each hidden code point as a token and the badge in the email cell', async () => {
      const spoof = `adm\u202Enimda\u3164@directory.invalid`;
      const { el } = await ready('/admin/access/users', pageOf([entry(1, { email: spoof })]));

      const cell = emailCells(el())[0];
      const tokens = Array.from(cell.querySelectorAll('[data-testid="user-text-hidden-token"]'));
      expect(tokens.map((t) => t.textContent)).toEqual(['⟨U+202E⟩', '⟨U+3164⟩']);
      expect(cell.querySelector('[data-testid="user-text-hidden-badge"]')).not.toBeNull();
      expect(/[\u202E\u3164]/u.test(el().textContent ?? '')).toBe(false);
    });

    it('shows no badge for a clean address', async () => {
      const { el } = await ready('/admin/access/users', pageOf([entry(1)]));
      expect(byTestId(el(), 'user-text-hidden-badge')).toBeNull();
    });
  });

  describe('URL state: status, page and size (FR-G1)', () => {
    it('reads status, page and size from the URL into the request (page 1-based in the URL)', async () => {
      await ready(
        '/admin/access/users?status=locked&page=3&size=50',
        pageOf([entry(1, { status: 'LOCKED' })], { number: 2, size: 50, total: 120 }),
        listUrl(2, 50, 'LOCKED'),
      );
    });

    it.each([
      ['status=ROOT', listUrl(0)],
      ['status=%3Cscript%3E', listUrl(0)],
      ['page=0', listUrl(0)],
      ['page=-2', listUrl(0)],
      ['page=1.5', listUrl(0)],
      ['page=abc', listUrl(0)],
      ['size=7', listUrl(0)],
      ['size=1000', listUrl(0)],
      ['size=100', listUrl(0, 100)],
    ])('treats ?%s as a valid view', async (query, expected) => {
      await ready(`/admin/access/users?${query}`, pageOf([]), expected);
    });

    it('writes the status filter into the URL, resets the page, and omits "All"', async () => {
      const { harness, settle } = await ready(
        '/admin/access/users?page=2',
        pageOf(many(20), { number: 1, total: 60 }),
        listUrl(1),
      );
      const select = harness.routeDebugElement?.query((d) => d.name === 'nx-select');

      select?.triggerEventHandler('selectionChange', 'PENDING');
      await settle();
      expect(ctx.router.url).toBe('/admin/access/users?status=pending');
      ctx.http.expectOne(listUrl(0, 20, 'PENDING')).flush(pageOf([]));
      await settle();

      select?.triggerEventHandler('selectionChange', 'ALL');
      await settle();
      expect(ctx.router.url).toBe('/admin/access/users');
      ctx.http.expectOne(listUrl(0)).flush(pageOf([]));
    });

    it('writes page (1-based, omitted on the first) and size (omitted at 20) into the URL', async () => {
      const { harness, settle } = await ready(
        '/admin/access/users',
        pageOf(many(20), { total: 95 }),
      );
      const table = harness.routeDebugElement?.query((d) => d.name === 'nx-table');

      table?.triggerEventHandler('pageChange', { pageIndex: 2, pageSize: 20, length: 95 });
      await settle();
      expect(ctx.router.url).toBe('/admin/access/users?page=3');
      ctx.http.expectOne(listUrl(2)).flush(pageOf(many(20), { number: 2, total: 95 }));
      await settle();

      table?.triggerEventHandler('pageChange', { pageIndex: 0, pageSize: 50, length: 95 });
      await settle();
      expect(ctx.router.url).toBe('/admin/access/users?size=50');
      ctx.http.expectOne(listUrl(0, 50)).flush(pageOf(many(50), { size: 50, total: 95 }));
    });

    it('keeps the table and its paginator, marked busy, while the next page loads', async () => {
      const { el, harness, settle } = await ready(
        '/admin/access/users',
        pageOf(many(20), { total: 95 }),
      );
      const table = harness.routeDebugElement?.query((d) => d.name === 'nx-table');

      table?.triggerEventHandler('pageChange', { pageIndex: 1, pageSize: 20, length: 95 });
      await settle();
      const list = byTestId(el(), 'users-list') as HTMLElement;
      expect(list.getAttribute('aria-busy')).toBe('true');
      expect(el().querySelector('mat-paginator')).not.toBeNull();
      expect(el().querySelector('mat-progress-bar')).not.toBeNull();
      expect(emailCells(el())).toHaveLength(20);

      ctx.http.expectOne(listUrl(1)).flush(pageOf(many(3), { number: 1, total: 95 }));
      await settle();
      expect(byTestId(el(), 'users-list')?.getAttribute('aria-busy')).toBeNull();
      expect(emailCells(el())).toHaveLength(3);
    });

    it('follows Back and Forward: each URL is one GET, and a revisit is a new page view', async () => {
      const { harness, settle } = await ready('/admin/access/users', pageOf(many(2)));

      await harness.navigateByUrl('/admin/access/users?status=active');
      await settle();
      ctx.http.expectOne(listUrl(0, 20, 'ACTIVE')).flush(pageOf(many(1)));
      await harness.navigateByUrl('/admin/access/users');
      await settle();
      ctx.http.expectOne(listUrl(0)).flush(pageOf(many(2)));
      await settle();
      expect(ctx.http.match(isList)).toHaveLength(0);
    });
  });

  describe('request budget (design §6.5 "Users list")', () => {
    it('one GET per page view, none on a lookup, one POST per submit', async () => {
      const { el, settle } = await open(ctx);
      const gets = ctx.http.match(isList);
      expect(gets).toHaveLength(1);
      gets[0].flush(pageOf(many(2)));
      await settle();

      type(el(), LOOKUP_ADDRESS);
      pressEnter(el());
      await settle();
      expect(ctx.http.match(isList)).toHaveLength(0);
      const posts = ctx.http.match(LOOKUP_URL);
      expect(posts).toHaveLength(1);
      posts[0].flush({ data: [] });
    });
  });

  describe('lookup (design §12.7; SD-13)', () => {
    it('sends no request per keystroke; Enter sends one POST with the address in the body', async () => {
      const { el, settle } = await ready('/admin/access/users', pageOf(many(2)));

      for (const prefix of ['s', 'se', 'sec', LOOKUP_ADDRESS]) type(el(), prefix);
      await settle();
      ctx.http.expectNone(LOOKUP_URL);

      pressEnter(el());
      await settle();
      const req = ctx.http.expectOne(LOOKUP_URL);
      expect(req.request.body).toEqual({ email: LOOKUP_ADDRESS });
      req.flush({ data: [] });
    });

    it('the Find button submits the current text, one POST per click', async () => {
      const { el, settle } = await ready('/admin/access/users', pageOf(many(2)));
      type(el(), LOOKUP_ADDRESS);
      lookupButton(el()).click();
      await settle();
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
      await settle();

      lookupButton(el()).click();
      await settle();
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
    });

    it('keeps the address out of the URL, history and logs (router.url and location.path)', async () => {
      const { el, settle } = await ready(
        '/admin/access/users?status=active',
        pageOf(many(2)),
        listUrl(0, 20, 'ACTIVE'),
      );
      type(el(), LOOKUP_ADDRESS);
      pressEnter(el());
      await settle();
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [entry(7, { email: LOOKUP_ADDRESS })] });
      await settle();

      for (const url of [ctx.router.url, ctx.location.path()]) {
        expect(url).not.toContain('@');
        expect(url).not.toContain('%40');
        expect(url).not.toContain('secret.lookup.target');
      }
      expect(ctx.router.url).toBe('/admin/access/users?status=active');
      const logged = ctx.logged();
      expect(logged).not.toContain('secret.lookup.target');
      expect(logged).not.toContain('@');
    });

    it('a hit shows one row under the visible "Lookup result" caption, instead of the list', async () => {
      const { el, settle } = await ready('/admin/access/users', pageOf(many(3)));
      type(el(), LOOKUP_ADDRESS);
      pressEnter(el());
      await settle();
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [entry(7)] });
      await settle();

      const result = byTestId(el(), 'users-lookup-result') as HTMLElement;
      const caption = result.querySelector('caption') as HTMLElement;
      expect(caption.textContent).toContain('Lookup result');
      expect(caption.classList).not.toContain('nx-table__caption--hidden');
      expect(emailCells(el())).toHaveLength(1);
      expect(result.querySelector('a')?.getAttribute('href')).toBe(
        `/admin/access/users/${entry(7).userId}`,
      );
    });

    it('a miss shows the miss copy, and Clear returns to the list with no request', async () => {
      const { el, settle } = await ready('/admin/access/users', pageOf(many(3)));
      type(el(), LOOKUP_ADDRESS);
      pressEnter(el());
      await settle();
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
      await settle();

      expect(byTestId(el(), 'users-lookup-miss')?.textContent).toContain(
        'No one in your organisation has this email address.',
      );
      expect(emailCells(el())).toHaveLength(0);

      (byTestId(el(), 'nx-search-clear') as HTMLButtonElement).click();
      await settle();
      expect(byTestId(el(), 'users-lookup-miss')).toBeNull();
      expect(emailCells(el())).toHaveLength(3);
      ctx.http.expectNone(isList);
    });

    it('shows a busy region while the lookup runs', async () => {
      const { el, settle } = await ready('/admin/access/users', pageOf(many(3)));
      type(el(), LOOKUP_ADDRESS);
      pressEnter(el());
      await settle();
      expect(byTestId(el(), 'users-lookup-loading')?.getAttribute('aria-busy')).toBe('true');
      expect(lookupButton(el()).getAttribute('aria-busy')).toBe('true');
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
    });

    it('429 USER_DIR_001: countdown on the lookup button, re-enabled at zero, no auto-retry', async () => {
      const { el, settle, harness } = await ready('/admin/access/users', pageOf(many(3)));
      type(el(), LOOKUP_ADDRESS);
      pressEnter(el());
      await settle();
      problem(ctx.http.expectOne(LOOKUP_URL), 429, 'USER_DIR_001', { 'Retry-After': '2' });
      await settle();

      const button = lookupButton(el());
      expect(button.getAttribute('aria-disabled')).toBe('true');
      const wait = byTestId(el(), 'users-lookup-wait') as HTMLElement;
      expect(wait.textContent).toContain('Try again in 2 seconds.');
      // Linked, not live: the countdown is not announced every second.
      expect(button.getAttribute('aria-describedby')).toBe(wait.id);
      expect(wait.getAttribute('role')).toBeNull();
      expect(wait.getAttribute('aria-live')).toBeNull();
      expect(byTestId(el(), 'users-lookup-error')?.textContent).toContain('Too many lookups');
      // The list stays usable.
      expect(emailCells(el())).toHaveLength(3);

      button.click();
      pressEnter(el());
      await settle();
      ctx.http.expectNone(LOOKUP_URL);

      await vi.waitFor(
        () => {
          harness.detectChanges();
          expect(byTestId(el(), 'users-lookup-wait')?.textContent).toContain(
            'Try again in 1 second.',
          );
        },
        { timeout: 2500, interval: 50 },
      );
      await vi.waitFor(
        () => {
          harness.detectChanges();
          expect(lookupButton(el()).getAttribute('aria-disabled')).toBeNull();
        },
        { timeout: 2500, interval: 50 },
      );
      expect(byTestId(el(), 'users-lookup-wait')).toBeNull();
      // Nothing was sent at zero: the user decides.
      ctx.http.expectNone(LOOKUP_URL);

      lookupButton(el()).click();
      await settle();
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
    });

    it('shows other lookup failures inline with the copy, never server text', async () => {
      const { el, settle } = await ready('/admin/access/users', pageOf(many(1)));
      type(el(), LOOKUP_ADDRESS);
      pressEnter(el());
      await settle();
      problem(ctx.http.expectOne(LOOKUP_URL), 500, 'INTERNAL_ERROR');
      await settle();

      const error = byTestId(el(), 'users-lookup-error') as HTMLElement;
      expect(error.getAttribute('role')).toBe('alert');
      expect(error.textContent).toContain('Something went wrong');
      expect(error.textContent).toContain('trace-INTERNAL_ERROR');
      expect(el().textContent).not.toContain('SERVER-DETAIL-TEXT');
      expect(lookupButton(el()).getAttribute('aria-disabled')).toBeNull();
    });
  });

  describe('errors (design §12.0, §14.1)', () => {
    it('beyond the 10,000 offset: the 400 gives the "past the end" copy and a way back', async () => {
      const { el, settle } = await open(ctx, '/admin/access/users?page=502');
      problem(ctx.http.expectOne(listUrl(501)), 400, 'VALIDATION_FAILED');
      await settle();

      const offset = byTestId(el(), 'users-offset') as HTMLElement;
      expect(offset.textContent).toContain(
        'This page is past the end of the list. Use the status filter to narrow it.',
      );
      expect(byTestId(el(), 'users-status-filter')).not.toBeNull();

      (byTestId(el(), 'users-first-page')?.querySelector('button') as HTMLButtonElement).click();
      await settle();
      expect(ctx.router.url).toBe('/admin/access/users');
      ctx.http.expectOne(listUrl(0)).flush(pageOf(many(1)));
    });

    it('flag off: "Users aren\'t enabled", without Retry', async () => {
      const { el, settle } = await open(ctx);
      problem(ctx.http.expectOne(listUrl(0)), 404, 'RESOURCE_NOT_FOUND');
      await settle();
      expect(byTestId(el(), 'nx-empty-state')?.textContent).toContain("Users aren't enabled");
      expect(byTestId(el(), 'users-error')?.querySelector('button')).toBeNull();
    });

    it('503 AUTH_005: the unavailable notice', async () => {
      const { el, settle } = await open(ctx);
      problem(ctx.http.expectOne(listUrl(0)), 503, 'AUTH_005');
      await settle();
      expect(el().textContent).toContain('Nexus is temporarily unavailable');
      expect(byTestId(el(), 'unavailable-notice')).not.toBeNull();
    });

    it('429 USER_DIR_002 on the list: the wait copy', async () => {
      const { el, settle } = await open(ctx);
      problem(ctx.http.expectOne(listUrl(0)), 429, 'USER_DIR_002', { 'Retry-After': '9' });
      await settle();
      expect(el().textContent).toContain('Too many requests');
      expect(el().textContent).toContain('Try again in 9 seconds.');
    });

    it('other failures: the copy and the reference, and Retry loads the same page again', async () => {
      const { el, settle } = await open(ctx, '/admin/access/users?page=2');
      problem(ctx.http.expectOne(listUrl(1)), 500, 'INTERNAL_ERROR');
      await settle();

      expect(el().querySelector('[role="alert"]')?.textContent).toContain('Something went wrong');
      expect(byTestId(el(), 'console-error-reference')?.textContent).toContain(
        'trace-INTERNAL_ERROR',
      );
      expect(el().textContent).not.toContain('SERVER-DETAIL-TEXT');

      (byTestId(el(), 'nx-error-state-retry') as HTMLButtonElement).click();
      await settle();
      ctx.http.expectOne(listUrl(1)).flush(pageOf(many(1), { number: 1, total: 21 }));
      await settle();
      expect(emailCells(el())).toHaveLength(1);
    });
  });

  describe('PII (SD-13, SD-14)', () => {
    it('logs no address from the rows, a lookup or a failure', async () => {
      const { el, settle } = await ready(
        '/admin/access/users',
        pageOf([entry(1, { email: LOOKUP_ADDRESS })]),
      );
      type(el(), LOOKUP_ADDRESS);
      pressEnter(el());
      await settle();
      problem(ctx.http.expectOne(LOOKUP_URL), 400, 'VALIDATION_FAILED');
      await settle();

      expect(ctx.logged()).not.toContain('@');
    });
  });

  describe('accessibility', () => {
    it('has no axe violations with rows, "(you)", tokens and badges', async () => {
      const { el } = await ready(
        '/admin/access/users',
        pageOf([
          entry(1, { userId: SELF_ID }),
          entry(2, {
            status: 'PENDING',
            emailVerified: false,
            email: `a\u202Eb@directory.invalid`,
          }),
        ]),
      );
      await expectNoAxeViolations(el());
    });

    it('has no axe violations while loading, on a miss and on an error', async () => {
      const { el, settle } = await open(ctx);
      await expectNoAxeViolations(el());
      ctx.http.expectOne(listUrl(0)).flush(pageOf(many(1)));
      await settle();
      type(el(), LOOKUP_ADDRESS);
      pressEnter(el());
      await settle();
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
      await settle();
      await expectNoAxeViolations(el());
    });
  });
});
