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
import type { PermissionPageResponse, PermissionResponse } from '../../../shared/types/api/rbac';
import { PERMISSIONS } from '../../../shared/types/permission';
import { CatalogueStore } from './catalogue.store';

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

function permission(name: string, isSensitive = false): PermissionResponse {
  return { id: `id-${name}`, name, description: `Description of ${name}`, isSensitive };
}

function page(
  names: readonly string[],
  total = names.length,
  number = 0,
  size = 100,
): PermissionPageResponse {
  return {
    data: names.map((name) => permission(name)),
    page: { size, number, totalElements: total, totalPages: Math.max(1, Math.ceil(total / size)) },
    links: { next: null, prev: null },
  };
}

const url = (n: number): string => `${API}/v1/permissions?page=${n}&size=100`;

function problem(req: TestRequest, status: number, code: string): void {
  req.flush(
    { code, detail: 'server text, SECRET-DETAIL', traceId: `trace-${code}` },
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
      CatalogueStore,
    ],
  });
  const authStore = TestBed.inject(AuthStore);
  authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_A }) }));
  const logger = TestBed.inject(LoggerService);
  const warn = vi.spyOn(logger, 'warn');
  return {
    store: TestBed.inject(CatalogueStore),
    http: TestBed.inject(HttpTestingController),
    authStore,
    handleError,
    warn,
  };
}

function data(store: CatalogueStore) {
  const state = store.state();
  if (state.status !== 'ready') throw new Error(`expected ready, got ${state.status}`);
  return state.data;
}

describe('CatalogueStore (US-020 design §6.4, §6.5)', () => {
  let ctx: ReturnType<typeof setup>;

  beforeEach(() => (ctx = setup()));

  afterEach(() => {
    ctx.http.verify();
    // RC-73: no load failure ever reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
  });

  it('starts idle', () => {
    expect(ctx.store.state()).toEqual({ status: 'idle' });
  });

  describe('one GET per session', () => {
    it('sends one GET with size=100 carrying the console context, then is ready', () => {
      ctx.store.load();
      expect(ctx.store.state().status).toBe('loading');
      const req = ctx.http.expectOne(url(0));
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(page(['role:read', 'tenant:read']));

      expect(ctx.store.state().status).toBe('ready');
      expect(data(ctx.store).total).toBe(2);
    });

    it('sends nothing when already ready (warm: 0 requests)', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(['role:read']));
      ctx.store.load();
      ctx.http.expectNone(url(0));
      expect(ctx.store.state().status).toBe('ready');
    });

    it('joins a load in flight instead of sending a second one', () => {
      ctx.store.load();
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(['role:read']));
      expect(ctx.store.state().status).toBe('ready');
    });

    it('reads the whole catalogue in one request today (9 entries)', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(PERMISSIONS));
      expect(ctx.http.match(() => true)).toHaveLength(0);
      expect(data(ctx.store).permissions).toHaveLength(PERMISSIONS.length);
    });
  });

  describe('indexes and groups', () => {
    it('builds byId, byName and total', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(['role:read', 'tenant:read']));
      const d = data(ctx.store);
      expect(d.byName.get('role:read')?.id).toBe('id-role:read');
      expect(d.byId.get('id-tenant:read')?.name).toBe('tenant:read');
      expect(d.total).toBe(2);
    });

    it('groups in the fixed order (tenant, user, role, audit) with codes alphabetical inside', () => {
      ctx.store.load();
      ctx.http
        .expectOne(url(0))
        .flush(
          page([
            'audit:read',
            'user:write',
            'role:write',
            'user:directory:read',
            'tenant:write',
            'user:read',
            'user:role:assign',
            'role:read',
            'tenant:read',
          ]),
        );
      const groups = data(ctx.store).groups;
      expect(groups.map((g) => g.resource)).toEqual(['tenant', 'user', 'role', 'audit']);
      expect(groups.map((g) => g.label)).toEqual(['Tenant', 'Users', 'Roles', 'Audit']);
      expect(groups[1].permissions.map((p) => p.name)).toEqual([
        'user:directory:read',
        'user:read',
        'user:role:assign',
        'user:write',
      ]);
    });

    it('omits empty groups', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(['audit:read']));
      expect(data(ctx.store).groups.map((g) => g.resource)).toEqual(['audit']);
    });

    it('puts a known resource with an unknown code in its group, and an unknown resource under Other, last', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(['zeta:read', 'user:export', 'audit:read', 'alpha']));
      const groups = data(ctx.store).groups;
      expect(groups.map((g) => g.resource)).toEqual(['user', 'audit', 'other']);
      expect(groups[0].permissions.map((p) => p.name)).toEqual(['user:export']);
      expect(groups[2].label).toBe('Other');
      expect(groups[2].permissions.map((p) => p.name)).toEqual(['alpha', 'zeta:read']);
    });
  });

  describe('more than 100 permissions', () => {
    it('fetches the remaining pages and logs a defect signal once, with a count only', () => {
      const names = (from: number, count: number): string[] =>
        Array.from({ length: count }, (_, i) => `res${from + i}:read`);
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(names(0, 100), 250));
      const second = ctx.http.expectOne(url(1));
      const third = ctx.http.expectOne(url(2));
      third.flush(page(names(200, 50), 250, 2));
      second.flush(page(names(100, 100), 250, 1));

      expect(data(ctx.store).permissions).toHaveLength(250);
      expect(data(ctx.store).total).toBe(250);
      const paged = ctx.warn.mock.calls.filter(
        ([, meta]) => meta?.event === 'access_console_catalogue_paged',
      );
      expect(paged).toHaveLength(1);
      expect(paged[0][1]?.context).toEqual({ area: 'permissions', count: 250 });
    });

    it('fails the whole load when a later page fails, without a partial catalogue', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(['a:read'], 150));
      problem(ctx.http.expectOne(url(1)), 500, 'INTERNAL_ERROR');
      expect(ctx.store.state().status).toBe('error');
    });
  });

  describe('unlabelled codes', () => {
    it('warns once per unlabelled code, with the code only', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(['role:read', 'report:export', 'billing:read']));

      const calls = ctx.warn.mock.calls.filter(
        ([, meta]) => meta?.event === 'access_console_permission_unlabelled',
      );
      expect(calls.map(([, meta]) => meta?.context)).toEqual([
        { area: 'permissions', permission: 'billing:read' },
        { area: 'permissions', permission: 'report:export' },
      ]);
      const logged = JSON.stringify(ctx.warn.mock.calls);
      expect(logged).not.toContain('Description of');
    });

    it('does not warn again on a repeat load of a ready catalogue', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(['report:export']));
      ctx.store.load();
      expect(ctx.warn).toHaveBeenCalledTimes(1);
    });

    it('does not warn for a fully labelled catalogue', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(PERMISSIONS));
      expect(ctx.warn).not.toHaveBeenCalled();
    });
  });

  describe('failure', () => {
    it('turns an error response into an error state without reaching ErrorHandler (RC-73)', () => {
      ctx.store.load();
      problem(ctx.http.expectOne(url(0)), 403, 'RBAC_001');
      const state = ctx.store.state();
      expect(state.status).toBe('error');
      if (state.status === 'error') expect(state.error.code).toBe('RBAC_001');
    });

    it('turns a network failure into NETWORK_ERROR', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).error(new ProgressEvent('error'));
      const state = ctx.store.state();
      if (state.status !== 'error') throw new Error('expected error');
      expect(state.error.code).toBe('NETWORK_ERROR');
    });

    it('logs the code and ids only, never server text', () => {
      ctx.store.load();
      problem(ctx.http.expectOne(url(0)), 500, 'INTERNAL_ERROR');
      expect(ctx.warn).toHaveBeenCalledWith(
        'Access console catalogue load failed',
        expect.objectContaining({
          event: 'access_console_catalogue_load_failed',
          errorCode: 'INTERNAL_ERROR',
          context: expect.objectContaining({
            area: 'permissions',
            traceId: 'trace-INTERNAL_ERROR',
          }),
        }),
      );
      expect(JSON.stringify(ctx.warn.mock.calls)).not.toContain('SECRET-DETAIL');
    });

    it('can be loaded again after a failure', () => {
      ctx.store.load();
      problem(ctx.http.expectOne(url(0)), 500, 'INTERNAL_ERROR');
      ctx.store.load();
      expect(ctx.store.state().status).toBe('loading');
      ctx.http.expectOne(url(0)).flush(page(['role:read']));
      expect(ctx.store.state().status).toBe('ready');
    });
  });

  describe('user change', () => {
    it('reads idle for another user, then reloads once for them', () => {
      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(['role:read']));

      ctx.authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));
      expect(ctx.store.state()).toEqual({ status: 'idle' });

      ctx.store.load();
      ctx.http.expectOne(url(0)).flush(page(['tenant:read']));
      expect(data(ctx.store).permissions.map((p) => p.name)).toEqual(['tenant:read']);
    });

    it('ignores a late answer for the previous user', () => {
      ctx.store.load();
      const stale = ctx.http.expectOne(url(0));
      ctx.authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));
      ctx.store.load();
      expect(stale.cancelled).toBe(true);
      ctx.http.expectOne(url(0)).flush(page(['audit:read']));
      expect(data(ctx.store).permissions.map((p) => p.name)).toEqual(['audit:read']);
    });

    it('sends nothing and stays idle when signed out', () => {
      ctx.authStore.clearSession();
      ctx.store.load();
      ctx.http.expectNone(url(0));
      expect(ctx.store.state()).toEqual({ status: 'idle' });
    });
  });
});
