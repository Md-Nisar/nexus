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
import type {
  PermissionListResponse,
  PermissionResponse,
  RoleResponse,
} from '../../../shared/types/api/rbac';
import { RoleDetailStore } from './role-detail.store';

const API = 'http://localhost:1000/api';
const USER_A = '0190a000-0000-7000-8000-000000000001';
const USER_B = '0190a000-0000-7000-8000-000000000002';
const ROLE_ID = '0190a000-0000-7000-8000-0000000000b1';
const OTHER_ROLE_ID = '0190a000-0000-7000-8000-0000000000b2';
/** User-authored text that must never reach a log line. */
const SECRET_NAME = 'Secret Payroll Role';
const SECRET_DESCRIPTION = 'Secret description of the payroll role';

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

function role(id = ROLE_ID, overrides: Partial<RoleResponse> = {}): RoleResponse {
  return {
    id,
    name: SECRET_NAME,
    description: SECRET_DESCRIPTION,
    isSystemRole: false,
    createdAt: '2026-01-01T00:00:00Z',
    memberCount: 3,
    permissionCount: 2,
    ...overrides,
  };
}

function permission(name: string): PermissionResponse {
  return { id: `id-${name}`, name, description: `About ${name}`, isSensitive: false };
}

const SET: PermissionListResponse = { data: [permission('role:read'), permission('user:read')] };

function roleUrl(id = ROLE_ID): string {
  return `${API}/v1/roles/${id}`;
}

function setUrl(id = ROLE_ID): string {
  return `${API}/v1/roles/${id}/permissions`;
}

function problem(req: TestRequest, status: number, code: string): void {
  req.flush(
    { code, detail: `server text for ${code}, ${SECRET_NAME}`, traceId: `trace-${code}` },
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
      RoleDetailStore,
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
    store: TestBed.inject(RoleDetailStore),
    http: TestBed.inject(HttpTestingController),
    authStore,
    handleError,
    logs,
  };
}

function data(store: RoleDetailStore) {
  const state = store.state();
  if (state.status !== 'ready') throw new Error(`expected ready, got ${state.status}`);
  return state.data;
}

describe('RoleDetailStore (US-020 design §6.5, §7.1, §7.2)', () => {
  let ctx: ReturnType<typeof setup>;

  beforeEach(() => (ctx = setup()));

  afterEach(() => {
    ctx.http.verify();
    // RC-73: no failure ever reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
    // PII: role names and descriptions never reach a log line, in the message or the params.
    for (const spy of Object.values(ctx.logs)) {
      const text = JSON.stringify(spy.mock.calls);
      expect(text).not.toContain(SECRET_NAME);
      expect(text).not.toContain(SECRET_DESCRIPTION);
    }
  });

  function flushBoth(etag: string | null, extra: Record<string, string> = {}, id = ROLE_ID) {
    ctx.http.expectOne(roleUrl(id)).flush(role(id));
    ctx.http
      .expectOne(setUrl(id))
      .flush(SET, { headers: { ...(etag === null ? {} : { ETag: etag }), ...extra } });
  }

  it('starts idle', () => {
    expect(ctx.store.state()).toEqual({ status: 'idle' });
    expect(ctx.store.refreshing()).toBe(false);
    expect(ctx.store.refreshError()).toBeNull();
  });

  describe('load', () => {
    it('sends the role GET and the set GET in parallel, both with the console context', () => {
      ctx.store.load(ROLE_ID);
      expect(ctx.store.state().status).toBe('loading');

      // Both are pending at once: the second does not wait for the first.
      const roleReq = ctx.http.expectOne(roleUrl());
      const setReq = ctx.http.expectOne(setUrl());
      expect(roleReq.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      expect(setReq.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);

      roleReq.flush(role());
      expect(ctx.store.state().status).toBe('loading');
      setReq.flush(SET, { headers: { ETag: '"v1"' } });

      expect(ctx.store.state().status).toBe('ready');
      expect(data(ctx.store).role.id).toBe(ROLE_ID);
      expect(data(ctx.store).permissions.map((p) => p.name)).toEqual(['role:read', 'user:read']);
      expect(ctx.store.roleId()).toBe(ROLE_ID);
    });

    it('re-reads both on every load of the same role (warm budget: 2)', () => {
      ctx.store.load(ROLE_ID);
      flushBoth('"v1"');
      ctx.store.load(ROLE_ID);
      flushBoth('"v2"');

      expect(data(ctx.store).etag).toEqual({ kind: 'strong', value: '"v2"' });
    });

    it('cancels the read of the previous role when another role is loaded', () => {
      ctx.store.load(ROLE_ID);
      const stale = [ctx.http.expectOne(roleUrl()), ctx.http.expectOne(setUrl())];

      ctx.store.load(OTHER_ROLE_ID);

      expect(stale.every((req) => req.cancelled)).toBe(true);
      flushBoth('"v1"', {}, OTHER_ROLE_ID);
      expect(data(ctx.store).role.id).toBe(OTHER_ROLE_ID);
    });
  });

  describe('ETag classification and saving availability (design §7.2, SD-8)', () => {
    it('keeps a strong ETag verbatim and makes saving available, with no warning', () => {
      ctx.store.load(ROLE_ID);
      flushBoth('"7d1e"');

      expect(data(ctx.store).etag).toEqual({ kind: 'strong', value: '"7d1e"' });
      expect(data(ctx.store).saveAvailability).toBe('available');
      expect(ctx.logs.warn).not.toHaveBeenCalled();
    });

    it.each([
      ['weak', 'W/"7d1e"'],
      ['missing', null],
      ['missing', '7d1e'],
    ])('marks a %s ETag (%s) etag-unusable and warns once with ids only', (kind, etag) => {
      ctx.store.load(ROLE_ID);
      flushBoth(etag, { 'X-Correlation-Id': 'corr-42' });

      const ready = data(ctx.store);
      expect(ready.saveAvailability).toBe('etag-unusable');
      expect(ready.etag).toEqual({ kind });
      expect(ready.correlationId).toBe('corr-42');
      // The read view is kept: the role and the set are still there.
      expect(ready.role.id).toBe(ROLE_ID);
      expect(ready.permissions).toHaveLength(2);

      expect(ctx.logs.warn).toHaveBeenCalledTimes(1);
      const [, params] = ctx.logs.warn.mock.calls[0];
      expect(params).toEqual({
        event: 'access_console_etag_unusable',
        correlationId: 'corr-42',
        context: { roleId: ROLE_ID, etagKind: kind },
      });
    });

    it('omits the correlation id from the warning when the response had none', () => {
      ctx.store.load(ROLE_ID);
      flushBoth('W/"x"');

      const [, params] = ctx.logs.warn.mock.calls[0];
      expect(params).toEqual({
        event: 'access_console_etag_unusable',
        context: { roleId: ROLE_ID, etagKind: 'weak' },
      });
    });
  });

  describe('refresh (Q24)', () => {
    beforeEach(() => {
      ctx.store.load(ROLE_ID);
      flushBoth('"v1"');
    });

    it('re-reads the role and the set together and keeps the view while it runs', () => {
      const before = data(ctx.store);

      ctx.store.refresh();

      expect(ctx.store.refreshing()).toBe(true);
      expect(ctx.store.state().status).toBe('ready');
      expect(data(ctx.store)).toBe(before);
      ctx.http.expectOne(roleUrl()).flush(role(ROLE_ID, { memberCount: 9 }));
      ctx.http.expectOne(setUrl()).flush({ data: [] }, { headers: { ETag: '"v2"' } });

      expect(ctx.store.refreshing()).toBe(false);
      expect(data(ctx.store).role.memberCount).toBe(9);
      expect(data(ctx.store).permissions).toEqual([]);
      expect(data(ctx.store).etag).toEqual({ kind: 'strong', value: '"v2"' });
    });

    it('ignores a second refresh while one is in flight', () => {
      ctx.store.refresh();
      ctx.store.refresh();

      flushBoth('"v2"');
      expect(ctx.http.match(roleUrl())).toHaveLength(0);
      expect(ctx.http.match(setUrl())).toHaveLength(0);
    });

    it('switches saving off when the refreshed tag is weak', () => {
      ctx.store.refresh();
      flushBoth('W/"v2"');

      expect(data(ctx.store).saveAvailability).toBe('etag-unusable');
      expect(ctx.logs.warn).toHaveBeenCalledTimes(1);
    });

    it('keeps the previous view and records the failure when the refresh fails', () => {
      const before = data(ctx.store);
      ctx.store.refresh();
      ctx.http.expectOne(roleUrl()).flush(role());
      problem(ctx.http.expectOne(setUrl()), 500, 'INTERNAL_ERROR');

      expect(ctx.store.refreshing()).toBe(false);
      expect(data(ctx.store)).toBe(before);
      expect(ctx.store.refreshError()?.code).toBe('INTERNAL_ERROR');
    });

    it('clears the recorded failure on the next successful refresh', () => {
      ctx.store.refresh();
      const stale = ctx.http.expectOne(setUrl());
      problem(ctx.http.expectOne(roleUrl()), 500, 'INTERNAL_ERROR');
      expect(stale.cancelled).toBe(true);
      expect(ctx.store.refreshError()?.code).toBe('INTERNAL_ERROR');
      ctx.store.refresh();
      flushBoth('"v3"');

      expect(ctx.store.refreshError()).toBeNull();
    });

    it.each([
      [404, 'ROLE_NOT_FOUND'],
      [400, 'VALIDATION_FAILED'],
    ])('turns a %s %s on refresh into the error state: the role is gone', (status, code) => {
      ctx.store.refresh();
      ctx.http.expectOne(setUrl()).flush(SET, { headers: { ETag: '"v1"' } });
      problem(ctx.http.expectOne(roleUrl()), status, code);

      const state = ctx.store.state();
      expect(state.status).toBe('error');
      expect(state.status === 'error' && state.error.code).toBe(code);
      expect(ctx.store.refreshError()).toBeNull();
    });

    it('does nothing before anything was loaded', () => {
      TestBed.resetTestingModule();
      ctx = setup();

      ctx.store.refresh();

      expect(ctx.store.state().status).toBe('idle');
    });
  });

  describe('failures (all or nothing)', () => {
    it.each([
      ['the role', 'role'],
      ['the set', 'set'],
    ])('fails the whole load when %s GET fails, and cancels the other', (_name, which) => {
      ctx.store.load(ROLE_ID);
      const roleReq = ctx.http.expectOne(roleUrl());
      const setReq = ctx.http.expectOne(setUrl());

      problem(which === 'role' ? roleReq : setReq, 404, 'ROLE_NOT_FOUND');

      expect((which === 'role' ? setReq : roleReq).cancelled).toBe(true);
      const state = ctx.store.state();
      expect(state.status).toBe('error');
      expect(state.status === 'error' && state.error.code).toBe('ROLE_NOT_FOUND');
    });

    it('logs a failed load with code, ids and reference only', () => {
      ctx.store.load(ROLE_ID);
      ctx.http.expectOne(setUrl());
      problem(ctx.http.expectOne(roleUrl()), 500, 'INTERNAL_ERROR');

      const call = ctx.logs.warn.mock.calls.find(
        ([, params]) => params?.event === 'access_console_role_detail_load_failed',
      );
      expect(call?.[1]).toEqual({
        event: 'access_console_role_detail_load_failed',
        errorCode: 'INTERNAL_ERROR',
        correlationId: undefined,
        context: { area: 'roles', roleId: ROLE_ID, traceId: 'trace-INTERNAL_ERROR' },
      });
    });

    it('turns a non-AppError failure into UNEXPECTED_ERROR', () => {
      ctx.store.load(ROLE_ID);
      ctx.http.expectOne(roleUrl()).flush(role());
      // A 200 without a body: the client refuses to show it as an empty set.
      ctx.http.expectOne(setUrl()).flush(null, { headers: { ETag: '"v1"' } });

      const state = ctx.store.state();
      expect(state.status === 'error' && state.error.code).toBe('UNEXPECTED_ERROR');
    });

    it('loads again after a failure', () => {
      ctx.store.load(ROLE_ID);
      ctx.http.expectOne(setUrl());
      problem(ctx.http.expectOne(roleUrl()), 500, 'INTERNAL_ERROR');

      ctx.store.load(ROLE_ID);
      flushBoth('"v1"');

      expect(ctx.store.state().status).toBe('ready');
    });
  });

  describe('applySet (T-011: the 200 of a save, or the re-read after a 412)', () => {
    const SAVED = {
      permissions: [permission('role:read'), permission('role:write'), permission('tenant:read')],
      etag: { kind: 'strong', value: '"v2"' } as const,
      correlationId: 'corr-2',
    };

    beforeEach(() => {
      ctx.store.load(ROLE_ID);
      flushBoth('"v1"');
    });

    it('replaces the set, its tag and the permission count without a request', () => {
      const before = data(ctx.store);

      ctx.store.applySet(ROLE_ID, SAVED);

      const after = data(ctx.store);
      expect(after.permissions).toBe(SAVED.permissions);
      expect(after.etag).toEqual({ kind: 'strong', value: '"v2"' });
      expect(after.correlationId).toBe('corr-2');
      expect(after.saveAvailability).toBe('available');
      expect(after.role).toEqual({ ...before.role, permissionCount: 3 });
      ctx.http.expectNone(() => true);
    });

    it('switches saving off and warns when the new tag is not strong', () => {
      ctx.store.applySet(ROLE_ID, { ...SAVED, etag: { kind: 'weak' } });

      expect(data(ctx.store).saveAvailability).toBe('etag-unusable');
      expect(ctx.logs.warn).toHaveBeenCalledWith(expect.any(String), {
        event: 'access_console_etag_unusable',
        correlationId: 'corr-2',
        context: { roleId: ROLE_ID, etagKind: 'weak' },
      });
    });

    it('ignores a set for another role', () => {
      const before = data(ctx.store);

      ctx.store.applySet(OTHER_ROLE_ID, SAVED);

      expect(data(ctx.store)).toBe(before);
    });

    it('cancels a Refresh in flight, so an older read cannot overwrite the saved set', () => {
      ctx.store.refresh();
      const stale = [ctx.http.expectOne(roleUrl()), ctx.http.expectOne(setUrl())];

      ctx.store.applySet(ROLE_ID, SAVED);

      expect(stale.every((req) => req.cancelled)).toBe(true);
      expect(ctx.store.refreshing()).toBe(false);
      expect(data(ctx.store).etag).toEqual({ kind: 'strong', value: '"v2"' });
    });

    it('does nothing unless the role is shown', () => {
      TestBed.resetTestingModule();
      ctx = setup();

      ctx.store.applySet(ROLE_ID, SAVED);

      expect(ctx.store.state().status).toBe('idle');
    });
  });

  describe('user change (design §6.2)', () => {
    it("never shows one user's role detail to another user", () => {
      ctx.store.load(ROLE_ID);
      flushBoth('"v1"');

      ctx.authStore.setSession(createAuthSession({ user: createAuthUser({ userId: USER_B }) }));

      expect(ctx.store.state()).toEqual({ status: 'idle' });
    });

    it('reads nothing when signed out', () => {
      ctx.authStore.clearSession();

      ctx.store.load(ROLE_ID);

      expect(ctx.store.state()).toEqual({ status: 'idle' });
    });
  });
});
