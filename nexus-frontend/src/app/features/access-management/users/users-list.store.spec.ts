import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ErrorHandler } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthStore } from '../../../core/auth/auth.store';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { apiErrorInterceptor } from '../../../core/http/api-error.interceptor';
import { ServiceAvailabilityNotifier } from '../../../core/http/service-availability-notifier';
import { LoggerService } from '../../../core/logging/logger.service';
import { createAuthSession, createAuthUser } from '../../../shared/testing/auth.fixtures';
import type {
  UserDirectoryEntry,
  UserDirectoryPage,
} from '../../../shared/types/api/user-directory';
import { UsersListStore, UsersQuery } from './users-list.store';

const API = 'http://localhost:1000/api';
const LOOKUP_URL = `${API}/v1/users/lookup`;
const USER_A = '0190a000-0000-7000-8000-000000000001';
const USER_B = '0190a000-0000-7000-8000-000000000002';
const ADDRESS = 'secret.lookup.target@directory.invalid';

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

const FIRST: UsersQuery = { page: 0, size: 20, status: null };

function listUrl(query: UsersQuery): string {
  const status = query.status === null ? '' : `&status=${query.status}`;
  return `${API}/v1/users?page=${query.page}&size=${query.size}${status}`;
}

function entry(index: number, overrides: Partial<UserDirectoryEntry> = {}): UserDirectoryEntry {
  const n = String(index).padStart(12, '0');
  return {
    userId: `0190a000-0000-7000-8000-${n}`,
    email: `row-${index}@directory.invalid`,
    status: 'ACTIVE',
    emailVerified: true,
    createdAt: '2026-01-02T03:04:05Z',
    ...overrides,
  };
}

function pageOf(entries: readonly UserDirectoryEntry[], number = 0, total = entries.length) {
  const body: UserDirectoryPage = {
    data: entries,
    page: { size: 20, number, totalElements: total, totalPages: Math.ceil(total / 20) },
    links: { next: null, prev: null },
  };
  return body;
}

function problem(req: TestRequest, status: number, code: string, headers = {}): void {
  req.flush(
    { code, detail: `server text with ${ADDRESS}`, traceId: `trace-${code}` },
    { status, statusText: 'Error', headers },
  );
}

function setup() {
  const handleError = vi.fn();
  TestBed.configureTestingModule({
    providers: [
      { provide: APP_CONFIG, useValue: CONFIG },
      { provide: ErrorHandler, useValue: { handleError } },
      { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
      provideRouter([]),
      provideHttpClient(withInterceptors([apiErrorInterceptor])),
      provideHttpClientTesting(),
      UsersListStore,
    ],
  });
  const authStore = TestBed.inject(AuthStore);
  authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_A }) }));
  const logger = TestBed.inject(LoggerService);
  const logs = [
    vi.spyOn(logger, 'debug'),
    vi.spyOn(logger, 'info'),
    vi.spyOn(logger, 'warn'),
    vi.spyOn(logger, 'error'),
  ];
  return {
    store: TestBed.inject(UsersListStore),
    http: TestBed.inject(HttpTestingController),
    authStore,
    handleError,
    logged: () => JSON.stringify(logs.flatMap((spy) => spy.mock.calls)),
  };
}

describe('UsersListStore (US-020 design §6.2, §6.5, §7.4)', () => {
  let ctx: ReturnType<typeof setup>;

  beforeEach(() => (ctx = setup()));

  afterEach(() => {
    ctx.http.verify();
    // RC-73: no failure of this store reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
    vi.useRealTimers();
  });

  describe('list', () => {
    it('starts idle and sends one GET per query, then is ready with the page', () => {
      expect(ctx.store.state().status).toBe('idle');

      ctx.store.load(FIRST);
      expect(ctx.store.state().status).toBe('loading');
      ctx.http.expectOne(listUrl(FIRST)).flush(pageOf([entry(1), entry(2)]));

      const state = ctx.store.state();
      expect(state.status).toBe('ready');
      expect(state.status === 'ready' ? state.data.data.map((u) => u.userId) : []).toEqual([
        entry(1).userId,
        entry(2).userId,
      ]);
    });

    it('sends nothing for the same query while it loads or once it is ready', () => {
      ctx.store.load(FIRST);
      ctx.store.load({ ...FIRST });
      const req = ctx.http.expectOne(listUrl(FIRST));
      req.flush(pageOf([entry(1)]));

      ctx.store.load({ ...FIRST });
      ctx.http.expectNone(listUrl(FIRST));
    });

    it('sends the status filter and the page, and a new query replaces the one in flight', () => {
      const locked: UsersQuery = { page: 3, size: 50, status: 'LOCKED' };
      ctx.store.load(FIRST);
      const stale = ctx.http.expectOne(listUrl(FIRST));
      ctx.store.load(locked);

      expect(stale.cancelled).toBe(true);
      ctx.http.expectOne(listUrl(locked)).flush(pageOf([entry(9, { status: 'LOCKED' })], 3, 200));
      const state = ctx.store.state();
      expect(state.status === 'ready' ? state.data.page.number : null).toBe(3);
    });

    it('keeps the previous page shown while the next loads, and drops it on a failure', () => {
      expect(ctx.store.shown()).toBeNull();
      ctx.store.load(FIRST);
      expect(ctx.store.shown()).toBeNull();
      ctx.http.expectOne(listUrl(FIRST)).flush(pageOf([entry(1)]));

      const second: UsersQuery = { ...FIRST, page: 1 };
      ctx.store.load(second);
      expect(ctx.store.state().status).toBe('loading');
      expect(ctx.store.shown()?.data.map((u) => u.userId)).toEqual([entry(1).userId]);

      problem(ctx.http.expectOne(listUrl(second)), 500, 'INTERNAL_ERROR');
      expect(ctx.store.shown()).toBeNull();
    });

    it.each([
      [400, 'VALIDATION_FAILED'],
      [404, 'RESOURCE_NOT_FOUND'],
      [429, 'USER_DIR_002'],
      [500, 'INTERNAL_ERROR'],
      [503, 'AUTH_005'],
    ])('catches a %s %s into the error state', (status, code) => {
      ctx.store.load(FIRST);
      problem(ctx.http.expectOne(listUrl(FIRST)), status, code);

      const state = ctx.store.state();
      expect(state.status).toBe('error');
      expect(state.status === 'error' ? state.error.code : null).toBe(code);
    });

    it('loads the same query again after a failure (Retry)', () => {
      ctx.store.load(FIRST);
      problem(ctx.http.expectOne(listUrl(FIRST)), 500, 'INTERNAL_ERROR');

      ctx.store.load(FIRST);
      ctx.http.expectOne(listUrl(FIRST)).flush(pageOf([entry(1)]));
      expect(ctx.store.state().status).toBe('ready');
    });

    it('never shows one user the list read for another', () => {
      ctx.store.load(FIRST);
      ctx.http.expectOne(listUrl(FIRST)).flush(pageOf([entry(1)]));

      ctx.authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));
      expect(ctx.store.state().status).toBe('idle');

      ctx.store.load(FIRST);
      ctx.http.expectOne(listUrl(FIRST)).flush(pageOf([entry(2)]));
      expect(ctx.store.state().status).toBe('ready');
    });

    it('logs a failure with codes only, never an address or server text', () => {
      ctx.store.load(FIRST);
      problem(ctx.http.expectOne(listUrl(FIRST)), 500, 'INTERNAL_ERROR');

      expect(ctx.logged()).toContain('access_console_users_load_failed');
      expect(ctx.logged()).not.toContain('@');
    });
  });

  describe('lookup (design §7.1, §7.4)', () => {
    it('sends one POST and is a hit with the one entry', () => {
      ctx.store.lookup(ADDRESS);
      expect(ctx.store.lookupState().status).toBe('loading');
      const req = ctx.http.expectOne(LOOKUP_URL);
      expect(req.request.body).toEqual({ email: ADDRESS });
      req.flush({ data: [entry(4)] });

      const state = ctx.store.lookupState();
      expect(state.status).toBe('hit');
      expect(state.status === 'hit' ? state.entry.userId : null).toBe(entry(4).userId);
    });

    it('is a miss when the directory has no such address', () => {
      ctx.store.lookup(ADDRESS);
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
      expect(ctx.store.lookupState().status).toBe('miss');
    });

    it('trims the address and ignores a blank one', () => {
      ctx.store.lookup('   ');
      ctx.http.expectNone(LOOKUP_URL);
      expect(ctx.store.lookupState().status).toBe('idle');

      ctx.store.lookup(`  ${ADDRESS} `);
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
    });

    it('ignores a second lookup while one is in flight (one POST per submit)', () => {
      ctx.store.lookup(ADDRESS);
      ctx.store.lookup(ADDRESS);
      expect(ctx.http.match(LOOKUP_URL)).toHaveLength(1);
    });

    it('sends a new POST for each later submit, the same address included', () => {
      ctx.store.lookup(ADDRESS);
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
      ctx.store.lookup(ADDRESS);
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
    });

    it('clearLookup returns to idle and cancels a lookup in flight', () => {
      ctx.store.lookup(ADDRESS);
      const req = ctx.http.expectOne(LOOKUP_URL);
      ctx.store.clearLookup();
      expect(req.cancelled).toBe(true);
      expect(ctx.store.lookupState().status).toBe('idle');
    });

    it.each(['USER_DIR_001', 'USER_DIR_002'])(
      'a 429 %s waits Retry-After, refuses lookups meanwhile, and never retries by itself',
      async (code) => {
        vi.useFakeTimers();
        ctx.store.lookup(ADDRESS);
        problem(ctx.http.expectOne(LOOKUP_URL), 429, code, { 'Retry-After': '3' });

        const state = ctx.store.lookupState();
        expect(state.status === 'error' ? state.error.code : null).toBe(code);
        expect(ctx.store.lookupWait.active()).toBe(true);
        expect(ctx.store.lookupWait.remaining()).toBe(3);

        ctx.store.lookup(ADDRESS);
        ctx.http.expectNone(LOOKUP_URL);

        await vi.advanceTimersByTimeAsync(3000);
        expect(ctx.store.lookupWait.active()).toBe(false);
        // Nothing was sent at zero: the user decides.
        ctx.http.expectNone(LOOKUP_URL);

        ctx.store.lookup(ADDRESS);
        ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
        expect(ctx.store.lookupState().status).toBe('miss');
      },
    );

    it('waits 30 s when a 429 carries no Retry-After', () => {
      vi.useFakeTimers();
      ctx.store.lookup(ADDRESS);
      problem(ctx.http.expectOne(LOOKUP_URL), 429, 'USER_DIR_001');
      expect(ctx.store.lookupWait.remaining()).toBe(30);
    });

    it.each([
      [400, 'VALIDATION_FAILED'],
      [404, 'RESOURCE_NOT_FOUND'],
      [500, 'INTERNAL_ERROR'],
    ])('catches a %s %s without a wait', (status, code) => {
      ctx.store.lookup(ADDRESS);
      problem(ctx.http.expectOne(LOOKUP_URL), status, code);

      const state = ctx.store.lookupState();
      expect(state.status === 'error' ? state.error.code : null).toBe(code);
      expect(ctx.store.lookupWait.active()).toBe(false);
    });

    it('leaves the list alone', () => {
      ctx.store.load(FIRST);
      ctx.http.expectOne(listUrl(FIRST)).flush(pageOf([entry(1)]));
      ctx.store.lookup(ADDRESS);
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [] });
      ctx.http.expectNone(listUrl(FIRST));
      expect(ctx.store.state().status).toBe('ready');
    });

    it('never shows one user the lookup made by another', () => {
      ctx.store.lookup(ADDRESS);
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [entry(4)] });

      ctx.authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));
      expect(ctx.store.lookupState().status).toBe('idle');
    });

    it('PII: no log context holds the address or the lookup text, on success or failure', () => {
      ctx.store.lookup(ADDRESS);
      ctx.http.expectOne(LOOKUP_URL).flush({ data: [entry(4, { email: ADDRESS })] });
      ctx.store.lookup(ADDRESS);
      problem(ctx.http.expectOne(LOOKUP_URL), 500, 'INTERNAL_ERROR');
      ctx.store.lookup(ADDRESS);
      problem(ctx.http.expectOne(LOOKUP_URL), 400, 'VALIDATION_FAILED');

      const logged = ctx.logged();
      expect(logged).toContain('access_console_user_lookup_failed');
      expect(logged).not.toContain('secret.lookup.target');
      expect(logged).not.toContain('@');
    });
  });
});
