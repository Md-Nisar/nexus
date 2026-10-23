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
import { SKIP_ACCESS_DENIED_REDIRECT } from '../../../core/http/skip-access-denied-redirect';
import { LoggerService } from '../../../core/logging/logger.service';
import { createAuthSession, createAuthUser } from '../../../shared/testing/auth.fixtures';
import type { RoleListResponse, RoleResponse } from '../../../shared/types/api/rbac';
import { RolesStore } from './roles.store';

const API = 'http://localhost:1000/api';
const USER_A = '0190a000-0000-7000-8000-000000000001';
const USER_B = '0190a000-0000-7000-8000-000000000002';

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

function role(index: number): RoleResponse {
  return {
    id: `role-${String(index).padStart(5, '0')}`,
    name: `Role ${String(index).padStart(5, '0')}`,
    description: `Description ${index}`,
    isSystemRole: false,
    createdAt: '2026-01-01T00:00:00Z',
    memberCount: 0,
    permissionCount: 1,
  };
}

/** The server's page `number` of `size` roles out of `total`, in (name, id) order. */
function page(number: number, total: number, size = 100): RoleListResponse {
  const first = number * size;
  const count = Math.max(0, Math.min(size, total - first));
  return {
    data: Array.from({ length: count }, (_, i) => role(first + i)),
    page: { size, number, totalElements: total, totalPages: Math.max(1, Math.ceil(total / size)) },
    links: { next: null, prev: null },
  };
}

function url(pageNumber: number): string {
  return `${API}/v1/roles?page=${pageNumber}&size=100`;
}

function problem(req: TestRequest, status: number, code: string): void {
  req.flush(
    { code, detail: `server text for ${code}, SECRET-ROLE-NAME`, traceId: `trace-${code}` },
    { status, statusText: 'Error' },
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
      RolesStore,
    ],
  });
  const authStore = TestBed.inject(AuthStore);
  authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_A }) }));
  const logger = TestBed.inject(LoggerService);
  const logs = {
    debug: vi.spyOn(logger, 'debug'),
    info: vi.spyOn(logger, 'info'),
    warn: vi.spyOn(logger, 'warn'),
    error: vi.spyOn(logger, 'error'),
  };
  return {
    store: TestBed.inject(RolesStore),
    http: TestBed.inject(HttpTestingController),
    authStore,
    handleError,
    logs,
  };
}

function data(store: RolesStore) {
  const state = store.state();
  if (state.status !== 'ready') throw new Error(`expected ready, got ${state.status}`);
  return state.data;
}

describe('RolesStore (US-020 design §6.4, §6.5)', () => {
  let ctx: ReturnType<typeof setup>;

  beforeEach(() => (ctx = setup()));

  afterEach(() => {
    ctx.http.verify();
    // RC-73: no load failure ever reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
  });

  it('starts idle', () => {
    expect(ctx.store.state()).toEqual({ status: 'idle' });
    expect(ctx.store.progress()).toBeNull();
  });

  describe('one page', () => {
    it('sends one GET with size=100, carrying the console context, and is ready', () => {
      ctx.store.loadAll();
      expect(ctx.store.state().status).toBe('loading');

      const req = ctx.http.expectOne(url(0));
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(page(0, 3));

      expect(ctx.store.state().status).toBe('ready');
      expect(data(ctx.store).roles.map((r) => r.id)).toEqual([
        'role-00000',
        'role-00001',
        'role-00002',
      ]);
      expect(data(ctx.store).total).toBe(3);
      expect(data(ctx.store).truncated).toBe(false);
    });

    it('is ready with an empty list for a tenant without roles', () => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 0));
      expect(data(ctx.store)).toEqual({ roles: [], total: 0, truncated: false });
    });
  });

  describe('many pages', () => {
    it('fetches page 0 first, then the rest in parallel, and keeps server order', () => {
      ctx.store.loadAll();
      // Nothing else is requested before page 0 answers.
      ctx.http.expectOne(url(0)).flush(page(0, 250));
      expect(ctx.store.progress()).toEqual({ loaded: 100, total: 250 });

      const second = ctx.http.expectOne(url(1));
      const third = ctx.http.expectOne(url(2));
      expect(ctx.store.state().status).toBe('loading');
      // Answers arrive out of order.
      third.flush(page(2, 250));
      expect(ctx.store.progress()).toEqual({ loaded: 150, total: 250 });
      second.flush(page(1, 250));

      expect(ctx.store.state().status).toBe('ready');
      const { roles, total, truncated } = data(ctx.store);
      expect(roles).toHaveLength(250);
      expect(roles.map((r) => r.id)).toEqual(Array.from({ length: 250 }, (_, i) => role(i).id));
      expect(total).toBe(250);
      expect(truncated).toBe(false);
    });

    it('drops a role that two pages both carry after a concurrent create shifted them', () => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 150));
      const shifted = page(1, 150);
      ctx.http.expectOne(url(1)).flush({ ...shifted, data: [role(99), ...shifted.data.slice(1)] });

      const ids = data(ctx.store).roles.map((r) => r.id);
      expect(new Set(ids).size).toBe(ids.length);
    });
  });

  describe('request budget (design §6.5 "Roles list")', () => {
    it.each([
      [1, 1],
      [100, 1],
      [101, 2],
      [1000, 10],
      [2000, 20],
    ])('%i roles cost %i GETs', (total, expected) => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, total));
      const rest = ctx.http.match((req) => req.url.startsWith(`${API}/v1/roles`));
      expect(rest).toHaveLength(expected - 1);
      for (const [i, req] of rest.entries()) req.flush(page(i + 1, total));
      expect(ctx.store.state().status).toBe('ready');
    });

    it('sends no request at all when ready and not invalidated', () => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 5));

      ctx.store.loadAll();
      ctx.http.expectNone(`${API}/v1/roles?page=0&size=100`);
      expect(ctx.store.state().status).toBe('ready');
    });

    it('joins a load already in flight instead of sending a second one', () => {
      ctx.store.loadAll();
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 5));
      expect(ctx.store.state().status).toBe('ready');
    });
  });

  describe('the 20-page bound', () => {
    it('fetches at most 20 pages and flags the list as truncated, with the true total', () => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 2500));
      const rest = ctx.http.match((req) => req.url.startsWith(`${API}/v1/roles`));
      expect(rest).toHaveLength(19);
      expect(rest.map((req) => req.request.urlWithParams)).toEqual(
        Array.from({ length: 19 }, (_, i) => expect.stringContaining(`page=${i + 1}&`)),
      );
      for (const [i, req] of rest.entries()) req.flush(page(i + 1, 2500));

      const { roles, total, truncated } = data(ctx.store);
      expect(roles).toHaveLength(2000);
      expect(total).toBe(2500);
      expect(truncated).toBe(true);
    });

    it('logs the truncation once with a count only', () => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 2100));
      ctx.http
        .match((req) => req.url.startsWith(`${API}/v1/roles`))
        .forEach((req, i) => req.flush(page(i + 1, 2100)));

      expect(ctx.logs.warn).toHaveBeenCalledTimes(1);
      expect(ctx.logs.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          event: 'access_console_roles_truncated',
          context: expect.objectContaining({ area: 'roles', count: 2100 }),
        }),
      );
    });

    it('is not truncated at exactly 20 pages', () => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 2000));
      ctx.http
        .match((req) => req.url.startsWith(`${API}/v1/roles`))
        .forEach((req, i) => req.flush(page(i + 1, 2000)));
      expect(data(ctx.store).truncated).toBe(false);
    });
  });

  describe('failure (all or nothing)', () => {
    it('fails the whole load when page 0 fails', () => {
      ctx.store.loadAll();
      problem(ctx.http.expectOne(url(0)), 403, 'RBAC_001');

      const state = ctx.store.state();
      expect(state.status).toBe('error');
      if (state.status === 'error') expect(state.error.code).toBe('RBAC_001');
    });

    it('fails the whole load when a later page fails, with no partial list, and cancels the rest', () => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 300));
      const second = ctx.http.expectOne(url(1));
      const third = ctx.http.expectOne(url(2));
      problem(second, 500, 'INTERNAL_ERROR');

      const state = ctx.store.state();
      expect(state.status).toBe('error');
      if (state.status === 'error') expect(state.error.code).toBe('INTERNAL_ERROR');
      expect(third.cancelled).toBe(true);
      expect(ctx.store.progress()).toBeNull();
    });

    it('turns a network failure into a NETWORK_ERROR state', () => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).error(new ProgressEvent('error'));
      const state = ctx.store.state();
      expect(state.status).toBe('error');
      if (state.status === 'error') expect(state.error.code).toBe('NETWORK_ERROR');
    });

    it('logs the code and ids only, never the server text (PII, RC-73)', () => {
      ctx.store.loadAll();
      problem(ctx.http.expectOne(url(0)), 500, 'INTERNAL_ERROR');

      expect(ctx.logs.warn).toHaveBeenCalledWith(
        'Access console roles load failed',
        expect.objectContaining({
          event: 'access_console_roles_load_failed',
          errorCode: 'INTERNAL_ERROR',
          context: expect.objectContaining({ area: 'roles', traceId: 'trace-INTERNAL_ERROR' }),
        }),
      );
      const all = JSON.stringify(Object.values(ctx.logs).flatMap((spy) => spy.mock.calls));
      expect(all).not.toContain('SECRET-ROLE-NAME');
      expect(all).not.toContain('server text');
    });

    it('can be loaded again after a failure', () => {
      ctx.store.loadAll();
      problem(ctx.http.expectOne(url(0)), 500, 'INTERNAL_ERROR');

      ctx.store.loadAll();
      expect(ctx.store.state().status).toBe('loading');
      ctx.http.expectOne(url(0)).flush(page(0, 2));
      expect(ctx.store.state().status).toBe('ready');
    });
  });

  describe('invalidate', () => {
    it('returns to idle so the next loadAll fetches again', () => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 2));

      ctx.store.invalidate();
      expect(ctx.store.state()).toEqual({ status: 'idle' });

      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 3));
      expect(data(ctx.store).roles).toHaveLength(3);
    });

    it('cancels a load in flight and ignores its late answer', () => {
      ctx.store.loadAll();
      const stale = ctx.http.expectOne(url(0));
      ctx.store.invalidate();
      expect(stale.cancelled).toBe(true);
      expect(ctx.store.state()).toEqual({ status: 'idle' });
    });
  });

  describe('user change (design §6.2)', () => {
    it('hides the previous user’s roles as soon as another user signs in', () => {
      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 2));
      expect(ctx.store.state().status).toBe('ready');

      ctx.authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));
      expect(ctx.store.state()).toEqual({ status: 'idle' });

      ctx.store.loadAll();
      ctx.http.expectOne(url(0)).flush(page(0, 1));
      expect(data(ctx.store).roles).toHaveLength(1);
    });

    it('reads nothing when nobody is signed in', () => {
      ctx.authStore.clearSession();
      ctx.store.loadAll();
      ctx.http.expectNone(url(0));
      expect(ctx.store.state()).toEqual({ status: 'idle' });
    });
  });
});
