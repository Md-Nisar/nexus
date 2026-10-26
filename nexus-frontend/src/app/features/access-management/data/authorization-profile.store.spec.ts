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
import { authInterceptor } from '../../../core/http/auth.interceptor';
import { correlationIdInterceptor } from '../../../core/http/correlation-id.interceptor';
import { LoggerService } from '../../../core/logging/logger.service';
import { createAuthSession, createAuthUser } from '../../../shared/testing/auth.fixtures';
import type { CallerAuthorizationResponse } from '../../../shared/types/api/rbac';
import { AuthService } from '../../auth/auth.service';
import { AuthorizationProfileStore, ProfileReloadReason } from './authorization-profile.store';

const API = 'http://localhost:1000/api';
const PROFILE_URL = `${API}/v1/users/me/authorization`;
const USER_A = '0190a000-0000-7000-8000-000000000001';
const USER_B = '0190a000-0000-7000-8000-000000000002';
const ROLE_ID = '0190a000-0000-7000-8000-00000000000a';

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

function profile(
  overrides: Partial<CallerAuthorizationResponse> = {},
): CallerAuthorizationResponse {
  return {
    userId: USER_A,
    roles: [{ roleId: ROLE_ID, name: 'Support' }],
    permissions: ['role:read', 'role:write'],
    isAdministrator: false,
    ...overrides,
  };
}

function problem(req: TestRequest, status: number, code: string, headers = {}): void {
  req.flush(
    { code, detail: `server text for ${code}`, traceId: `trace-${code}` },
    { status, statusText: 'Error', headers },
  );
}

/** Shared set-up; `interceptors` installs the production chain (app.config.ts). */
function setup(options: { interceptors?: boolean } = {}) {
  const handleError = vi.fn();
  TestBed.configureTestingModule({
    providers: [
      { provide: APP_CONFIG, useValue: CONFIG },
      { provide: ErrorHandler, useValue: { handleError } },
      // The interceptor's global 503 toast is not under test here.
      { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
      provideRouter([]),
      options.interceptors
        ? provideHttpClient(
            withInterceptors([correlationIdInterceptor, apiErrorInterceptor, authInterceptor]),
          )
        : provideHttpClient(withInterceptors([apiErrorInterceptor])),
      provideHttpClientTesting(),
      AuthorizationProfileStore,
    ],
  });
  const authStore = TestBed.inject(AuthStore);
  authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_A }) }));
  const authService = TestBed.inject(AuthService);
  const refresh = vi.spyOn(authService, 'refresh');
  const logger = TestBed.inject(LoggerService);
  const logs = {
    debug: vi.spyOn(logger, 'debug'),
    info: vi.spyOn(logger, 'info'),
    warn: vi.spyOn(logger, 'warn'),
    error: vi.spyOn(logger, 'error'),
  };
  return {
    store: TestBed.inject(AuthorizationProfileStore),
    http: TestBed.inject(HttpTestingController),
    authStore,
    refresh,
    handleError,
    logs,
  };
}

/** Every argument passed to every logger call, serialised, for PII assertions. */
function allLogText(logs: ReturnType<typeof setup>['logs']): string {
  return JSON.stringify(Object.values(logs).flatMap((spy) => spy.mock.calls));
}

describe('AuthorizationProfileStore (US-020 design §6.3)', () => {
  let ctx: ReturnType<typeof setup>;

  afterEach(() => {
    ctx.http.verify();
    // ADR-0028 / RC-65: the console never starts a session refresh of its own.
    expect(ctx.refresh).not.toHaveBeenCalled();
    // RC-73: no load failure ever reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
  });

  describe('load', () => {
    beforeEach(() => (ctx = setup()));

    it('starts idle with mutations off and nothing held', () => {
      expect(ctx.store.state()).toEqual({ status: 'idle' });
      expect(ctx.store.mutationsEnabled()).toBe(false);
      expect(ctx.store.can('role:read')).toBe(false);
      expect(ctx.store.userId()).toBeNull();
    });

    it('sends exactly one GET and is loading, with mutations off, until it answers', () => {
      ctx.store.load();

      expect(ctx.store.state().status).toBe('loading');
      expect(ctx.store.mutationsEnabled()).toBe(false);
      ctx.http.expectOne(PROFILE_URL).flush(profile());
    });

    it('exposes the profile when ready and turns mutations on', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile({ isAdministrator: true }));

      expect(ctx.store.state().status).toBe('ready');
      expect(ctx.store.mutationsEnabled()).toBe(true);
      expect(ctx.store.userId()).toBe(USER_A);
      expect(ctx.store.isAdministrator()).toBe(true);
      expect([...ctx.store.permissions()]).toEqual(['role:read', 'role:write']);
      expect([...ctx.store.roleIds()]).toEqual([ROLE_ID]);
      expect(ctx.store.can('role:write')).toBe(true);
      expect(ctx.store.can('user:role:assign')).toBe(false);
    });

    it('coalesces a second load while one is in flight (one request, one answer for both)', () => {
      ctx.store.load();
      ctx.store.load();

      const requests = ctx.http.match(PROFILE_URL);
      expect(requests).toHaveLength(1);
      requests[0].flush(profile());
      expect(ctx.store.state().status).toBe('ready');
    });

    it('coalesces a reload that arrives while a load is in flight', () => {
      ctx.store.load();
      ctx.store.reload('own-access-change');

      expect(ctx.http.match(PROFILE_URL)).toHaveLength(1);
    });

    it('reads again on a later load (a new console entry), never while one is in flight', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile());

      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile({ permissions: ['role:read'] }));

      expect(ctx.store.can('role:write')).toBe(false);
    });

    it('drops permission names outside the catalogue and warns once, with the codes only', () => {
      ctx.store.load();
      ctx.http
        .expectOne(PROFILE_URL)
        .flush(profile({ permissions: ['role:read', 'billing:read', 'role:delete'] }));

      expect([...ctx.store.permissions()]).toEqual(['role:read']);
      const unknownWarns = ctx.logs.warn.mock.calls.filter(
        ([, params]) => params?.event === 'access_console_profile_unknown_permissions',
      );
      expect(unknownWarns).toHaveLength(1);
      expect(unknownWarns[0][1]?.context).toEqual({
        area: 'profile',
        count: 2,
        permissions: ['billing:read', 'role:delete'],
      });
    });

    it('does not warn when every permission is in the catalogue', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile());

      expect(ctx.logs.warn).not.toHaveBeenCalled();
    });
  });

  describe('reload', () => {
    beforeEach(() => (ctx = setup()));

    it.each<ProfileReloadReason>(['own-access-change', 'denied-predicted-allowed', 'user-changed'])(
      'reads the profile again for %s, mutations off until it answers',
      (reason) => {
        ctx.store.load();
        ctx.http.expectOne(PROFILE_URL).flush(profile());

        ctx.store.reload(reason);

        expect(ctx.store.mutationsEnabled()).toBe(false);
        ctx.http.expectOne(PROFILE_URL).flush(profile({ permissions: ['role:read'] }));
        expect(ctx.store.can('role:write')).toBe(false);
        expect(ctx.store.mutationsEnabled()).toBe(true);
        expect(ctx.logs.info).toHaveBeenCalledWith(
          'Access console profile reload',
          expect.objectContaining({
            event: 'access_console_profile_reload',
            context: { area: 'profile', reason },
          }),
        );
      },
    );
  });

  describe('reload keeps the last ready profile on screen (MJ-5: stale-while-revalidate)', () => {
    beforeEach(() => (ctx = setup()));

    it('stays ready with the old data while reloading, with mutations off until it answers', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile());
      const before = ctx.store.state();

      ctx.store.reload('denied-predicted-allowed');

      // The same state object: nothing that renders from it unmounts or re-renders.
      expect(ctx.store.state()).toBe(before);
      expect(ctx.store.reloading()).toBe(true);
      expect(ctx.store.settled()).toBe(false);
      expect(ctx.store.mutationsEnabled()).toBe(false);
      expect(ctx.store.can('role:write')).toBe(true);
      expect([...ctx.store.permissions()]).toEqual(['role:read', 'role:write']);

      ctx.http.expectOne(PROFILE_URL).flush(profile({ permissions: ['role:read'] }));

      expect(ctx.store.reloading()).toBe(false);
      expect(ctx.store.settled()).toBe(true);
      expect(ctx.store.mutationsEnabled()).toBe(true);
      expect(ctx.store.can('role:write')).toBe(false);
    });

    it('is loading, not reloading, on the first read and after a failure', () => {
      ctx.store.load();
      expect(ctx.store.state().status).toBe('loading');
      expect(ctx.store.reloading()).toBe(false);
      expect(ctx.store.settled()).toBe(false);
      problem(ctx.http.expectOne(PROFILE_URL), 500, 'INTERNAL_ERROR');

      ctx.store.reload('denied-predicted-allowed');

      expect(ctx.store.state().status).toBe('loading');
      expect(ctx.store.reloading()).toBe(false);
      ctx.http.expectOne(PROFILE_URL).flush(profile());
    });

    it('never shows the previous user’s data as stale-while-revalidate', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile());

      ctx.authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));
      ctx.store.reload('user-changed');

      expect(ctx.store.state().status).toBe('loading');
      expect(ctx.store.reloading()).toBe(false);
      expect(ctx.store.can('role:write')).toBe(false);
      ctx.http.expectOne(PROFILE_URL).flush(profile({ userId: USER_B }));
      expect(ctx.store.userId()).toBe(USER_B);
    });
  });

  describe('the answer must belong to the signed-in user (Low 6, defence in depth)', () => {
    beforeEach(() => (ctx = setup()));

    it('settles to error with mutations off when the body is for another user, and logs a code', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile({ userId: USER_B, isAdministrator: true }));

      const state = ctx.store.state();
      expect(state.status).toBe('error');
      expect(state.status === 'error' && state.error.code).toBe('PROFILE_OWNER_MISMATCH');
      expect(ctx.store.mutationsEnabled()).toBe(false);
      expect(ctx.store.isAdministrator()).toBe(false);
      expect(ctx.store.can('role:write')).toBe(false);
      expect(ctx.logs.warn).toHaveBeenCalledWith(
        'Access console profile belongs to another user',
        expect.objectContaining({
          event: 'access_console_profile_owner_mismatch',
          errorCode: 'PROFILE_OWNER_MISMATCH',
        }),
      );
      expect(allLogText(ctx.logs)).not.toContain(USER_B);
    });
  });

  describe('failure: read-only, never a guess (Q8)', () => {
    beforeEach(() => (ctx = setup()));

    it.each([
      ['404 RESOURCE_NOT_FOUND (us019 switched off)', 404, 'RESOURCE_NOT_FOUND'],
      ['500 INTERNAL_ERROR', 500, 'INTERNAL_ERROR'],
      ['403 ACCESS_DENIED', 403, 'ACCESS_DENIED'],
    ])('%s gives error with mutations off', (_name, status, code) => {
      ctx.store.load();
      problem(ctx.http.expectOne(PROFILE_URL), status, code);

      const state = ctx.store.state();
      expect(state.status).toBe('error');
      expect(state.status === 'error' && state.error.code).toBe(code);
      expect(ctx.store.mutationsEnabled()).toBe(false);
      expect(ctx.store.can('role:read')).toBe(false);
    });

    it('a dropped connection gives error NETWORK_ERROR with mutations off', () => {
      ctx.store.load();
      ctx.http
        .expectOne(PROFILE_URL)
        .error(new ProgressEvent('error'), { status: 0, statusText: '' });

      const state = ctx.store.state();
      expect(state.status === 'error' && state.error.code).toBe('NETWORK_ERROR');
      expect(ctx.store.mutationsEnabled()).toBe(false);
    });

    it('an intermediary answer that is not a problem document gives error HTTP_ERROR', () => {
      ctx.store.load();
      ctx.http
        .expectOne(PROFILE_URL)
        .flush('<html>Bad gateway</html>', { status: 502, statusText: 'Bad Gateway' });

      const state = ctx.store.state();
      expect(state.status === 'error' && state.error.code).toBe('HTTP_ERROR');
      expect(ctx.store.mutationsEnabled()).toBe(false);
    });

    it('503 AUTH_005 gives error with the code, the Retry-After and the failure time', () => {
      vi.useFakeTimers({ now: Date.parse('2026-10-23T10:00:00Z') });
      try {
        ctx.store.load();
        problem(ctx.http.expectOne(PROFILE_URL), 503, 'AUTH_005', { 'Retry-After': '30' });

        const state = ctx.store.state();
        expect(state.status).toBe('error');
        if (state.status !== 'error') return;
        expect(state.error.code).toBe('AUTH_005');
        expect(state.error.retryAfterSeconds).toBe(30);
        expect(state.failedAt).toBe(Date.parse('2026-10-23T10:00:00Z'));
        expect(ctx.store.mutationsEnabled()).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });

    it('a failure after a ready profile drops it (no stale affordances)', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile());
      ctx.store.reload('denied-predicted-allowed');
      problem(ctx.http.expectOne(PROFILE_URL), 500, 'INTERNAL_ERROR');

      expect(ctx.store.can('role:write')).toBe(false);
      expect(ctx.store.userId()).toBeNull();
    });

    it('logs a failure as code and ids only, never the server text (PII, RC-73)', () => {
      ctx.store.load();
      problem(ctx.http.expectOne(PROFILE_URL), 500, 'INTERNAL_ERROR');

      expect(ctx.logs.warn).toHaveBeenCalledWith(
        'Access console profile load failed',
        expect.objectContaining({
          event: 'access_console_profile_load_failed',
          errorCode: 'INTERNAL_ERROR',
          context: expect.objectContaining({ area: 'profile', traceId: 'trace-INTERNAL_ERROR' }),
        }),
      );
      const storeLogs = JSON.stringify(
        ctx.logs.warn.mock.calls.filter(([message]) => message.startsWith('Access console')),
      );
      expect(storeLogs).not.toContain('server text');
    });
  });

  describe('user change (design §6.2, DQ-7)', () => {
    beforeEach(() => (ctx = setup()));

    it('hides the previous user’s profile as soon as another user signs in', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile());

      ctx.authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));

      expect(ctx.store.state()).toEqual({ status: 'idle' });
      expect(ctx.store.mutationsEnabled()).toBe(false);
      expect(ctx.store.can('role:read')).toBe(false);
      expect(ctx.store.roleIds().size).toBe(0);
    });

    it('hides the profile when the session ends', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile());

      ctx.authStore.clearSession();

      expect(ctx.store.state()).toEqual({ status: 'idle' });
      expect(ctx.store.mutationsEnabled()).toBe(false);
    });

    it('cancels the previous user’s request when the new user’s read starts', () => {
      ctx.store.load();
      const first = ctx.http.expectOne(PROFILE_URL);

      ctx.authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));
      ctx.store.reload('user-changed');

      expect(first.cancelled).toBe(true);
      ctx.http
        .expectOne(PROFILE_URL)
        .flush(profile({ userId: USER_B, permissions: ['role:read'] }));
      expect(ctx.store.userId()).toBe(USER_B);
      expect(ctx.store.can('role:write')).toBe(false);
    });

    it('never shows a late answer for the previous user to the new one', () => {
      ctx.store.load();
      const first = ctx.http.expectOne(PROFILE_URL);

      ctx.authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));
      first.flush(profile());

      expect(ctx.store.state()).toEqual({ status: 'idle' });
      expect(ctx.store.mutationsEnabled()).toBe(false);
    });

    it('does not read anything while signed out', () => {
      ctx.authStore.clearSession();

      ctx.store.load();
      ctx.store.reload('user-changed');

      ctx.http.expectNone(PROFILE_URL);
      expect(ctx.store.state()).toEqual({ status: 'idle' });
    });
  });

  describe('PII in logs', () => {
    beforeEach(() => (ctx = setup()));

    it('logs codes, ids and counts only across load, reload and failure', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile({ permissions: ['role:read', 'x:y'] }));
      ctx.store.reload('own-access-change');
      problem(ctx.http.expectOne(PROFILE_URL), 404, 'RESOURCE_NOT_FOUND');

      const text = allLogText(ctx.logs);
      expect(text).not.toContain('Support');
      expect(text).not.toContain('server text');
      expect(text).not.toMatch(/@/);
    });
  });

  describe('own-access reload through the real interceptor chain (ADR-0028 decision 5)', () => {
    beforeEach(() => (ctx = setup({ interceptors: true })));

    afterEach(() => {
      // Restored here so the outer afterEach can assert "never" for every other case.
      ctx.refresh.mockClear();
    });

    it('a 401 on the bumped epoch is renewed by exactly one shared refresh, then replayed', () => {
      ctx.store.load();
      ctx.http.expectOne(PROFILE_URL).flush(profile());

      ctx.store.reload('own-access-change');
      ctx.http
        .expectOne(PROFILE_URL)
        .flush(
          { code: 'AUTH_003', detail: 'stale', traceId: 't-401' },
          { status: 401, statusText: 'Unauthorized' },
        );

      const refreshes = ctx.http.match(
        (req) => req.method === 'POST' && req.url === `${API}/v1/auth/refresh`,
      );
      expect(refreshes).toHaveLength(1);
      refreshes[0].flush({
        accessToken: 'renewed',
        tokenType: 'Bearer',
        expiresIn: 900,
        userId: USER_A,
      });
      ctx.http.expectOne(`${API}/v1/users/me`).flush({
        userId: USER_A,
        tenantId: 'tenant-456',
        emailVerified: true,
        roles: ['USER'],
        permissions: ['role:read'],
        tokenVersion: 2,
      });

      const replay = ctx.http.expectOne(PROFILE_URL);
      expect(replay.request.headers.get('Authorization')).toBe('Bearer renewed');
      replay.flush(profile({ permissions: ['role:read'] }));

      // The one refresh is the interceptor's; the store itself started none.
      expect(ctx.refresh).toHaveBeenCalledTimes(1);
      expect(ctx.store.can('role:write')).toBe(false);
      expect(ctx.store.mutationsEnabled()).toBe(true);
    });
  });
});
