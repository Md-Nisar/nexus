import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ErrorHandler } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthStore } from '../../../core/auth/auth.store';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { apiErrorInterceptor } from '../../../core/http/api-error.interceptor';
import { ServiceAvailabilityNotifier } from '../../../core/http/service-availability-notifier';
import { LoggerService } from '../../../core/logging/logger.service';
import {
  AuthStoreStub,
  createAuthSession,
  createAuthStoreStub,
  createAuthUser,
} from '../../../shared/testing/auth.fixtures';
import type {
  RoleAssignmentListResponse,
  RoleAssignmentResponse,
} from '../../../shared/types/api/rbac';
import type { UserDirectoryEntry } from '../../../shared/types/api/user-directory';
import { DirectoryCache } from '../data/directory-cache';
import { UserDetailStore } from './user-detail.store';

const API = 'http://localhost:1000/api';
const USER_ID = '0190a000-0000-7000-8000-000000000042';
const OTHER_ID = '0190a000-0000-7000-8000-000000000043';
const ADDRESS = 'person.detail@directory.invalid';

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

const userUrl = (id = USER_ID): string => `${API}/v1/users/${id}`;
const rolesUrl = (id = USER_ID): string => `${API}/v1/users/${id}/roles?page=0&size=100`;

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

function assignment(index: number): RoleAssignmentResponse {
  return {
    userId: USER_ID,
    roleId: `0190a000-0000-7000-8000-0000000000b${index}`,
    roleName: `Role ${index}`,
    assignedAt: '2026-01-03T00:00:00Z',
    assignedBy: null,
  };
}

function list(
  entries: readonly RoleAssignmentResponse[],
  total = entries.length,
): RoleAssignmentListResponse {
  return {
    data: entries,
    page: { size: 100, number: 0, totalElements: total, totalPages: Math.ceil(total / 100) },
    links: { next: null, prev: null },
  };
}

function problem(req: TestRequest, status: number, code: string): void {
  req.flush(
    { code, detail: `server text with ${ADDRESS}`, traceId: `trace-${code}` },
    { status, statusText: 'Error' },
  );
}

function setup(permissions: readonly string[] = ['user:directory:read', 'user:read']) {
  const handleError = vi.fn();
  const authStore: AuthStoreStub = createAuthStoreStub({
    session: createAuthSession({ user: createAuthUser({ userId: 'caller-1' }) }),
    permissions,
  });
  TestBed.configureTestingModule({
    providers: [
      { provide: APP_CONFIG, useValue: CONFIG },
      { provide: ErrorHandler, useValue: { handleError } },
      { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
      { provide: AuthStore, useValue: authStore },
      provideRouter([]),
      provideHttpClient(withInterceptors([apiErrorInterceptor])),
      provideHttpClientTesting(),
      DirectoryCache,
      UserDetailStore,
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
    store: TestBed.inject(UserDetailStore),
    cache: TestBed.inject(DirectoryCache),
    http: TestBed.inject(HttpTestingController),
    authStore,
    handleError,
    logs,
  };
}

type Ctx = ReturnType<typeof setup>;

function logged(ctx: Ctx): string {
  return JSON.stringify(ctx.logs.flatMap((spy) => spy.mock.calls));
}

describe('UserDetailStore (US-020 design §6.5 "User page", §7.1)', () => {
  let ctx: Ctx;

  afterEach(() => {
    ctx.http.verify();
    // RC-73: no failure ever reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
    // PII (SD-13): no log line carries the address, from the body or the server's detail.
    expect(logged(ctx)).not.toContain(ADDRESS);
  });

  it('request budget with user:read: the user GET and the assignments GET, once each, together', () => {
    ctx = setup();
    ctx.store.load(USER_ID);

    expect(ctx.store.state().status).toBe('loading');
    expect(ctx.store.assignments().status).toBe('loading');
    const userReq = ctx.http.expectOne(userUrl());
    const rolesReq = ctx.http.expectOne(rolesUrl());
    expect(userReq.request.method).toBe('GET');
    expect(rolesReq.request.method).toBe('GET');

    rolesReq.flush(list([assignment(1), assignment(2)]));
    userReq.flush(user());

    const state = ctx.store.state();
    expect(state.status === 'ready' && state.data).toEqual(user());
    const assignments = ctx.store.assignments();
    expect(assignments.status === 'ready' && assignments.data.assignments).toEqual([
      assignment(1),
      assignment(2),
    ]);
    expect(ctx.store.userId()).toBe(USER_ID);
  });

  it('without user:read: no assignments GET, and the assignments stay idle', () => {
    ctx = setup(['user:directory:read']);
    ctx.store.load(USER_ID);

    ctx.http.expectOne(userUrl()).flush(user());
    ctx.http.expectNone((req) => req.url.endsWith('/roles'));
    expect(ctx.store.canReadAssignments()).toBe(false);
    expect(ctx.store.assignments().status).toBe('idle');
  });

  it('keeps the two reads independent: an assignments failure leaves the user shown', () => {
    ctx = setup();
    ctx.store.load(USER_ID);

    ctx.http.expectOne(userUrl()).flush(user());
    problem(ctx.http.expectOne(rolesUrl()), 403, 'RBAC_001');

    expect(ctx.store.state().status).toBe('ready');
    const assignments = ctx.store.assignments();
    expect(assignments.status === 'error' && assignments.error.code).toBe('RBAC_001');
  });

  it('a missing or foreign id is one USER_NOT_FOUND error (SD-20)', () => {
    ctx = setup();
    ctx.store.load(OTHER_ID);

    problem(ctx.http.expectOne(userUrl(OTHER_ID)), 404, 'USER_NOT_FOUND');
    problem(ctx.http.expectOne(rolesUrl(OTHER_ID)), 404, 'USER_NOT_FOUND');

    const state = ctx.store.state();
    expect(state.status === 'error' && state.error.code).toBe('USER_NOT_FOUND');
    expect(state.status === 'error' && state.failedAt).toBeTypeOf('number');
  });

  it('logs a failure with codes and ids only', () => {
    ctx = setup();
    ctx.store.load(USER_ID);

    problem(ctx.http.expectOne(userUrl()), 500, 'INTERNAL_ERROR');
    problem(ctx.http.expectOne(rolesUrl()), 500, 'INTERNAL_ERROR');

    const [, , warn] = ctx.logs;
    expect(warn).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        event: 'access_console_user_load_failed',
        errorCode: 'INTERNAL_ERROR',
        context: expect.objectContaining({ area: 'users', userId: USER_ID }),
      }),
    );
    expect(warn).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        event: 'access_console_user_roles_load_failed',
        errorCode: 'INTERNAL_ERROR',
        context: expect.objectContaining({ area: 'assignments', userId: USER_ID }),
      }),
    );
  });

  it('loadAssignments re-reads only the assignments of the user shown (Retry)', () => {
    ctx = setup();
    ctx.store.load(USER_ID);
    ctx.http.expectOne(userUrl()).flush(user());
    problem(ctx.http.expectOne(rolesUrl()), 500, 'INTERNAL_ERROR');

    ctx.store.loadAssignments();

    ctx.http.expectNone(userUrl());
    ctx.http.expectOne(rolesUrl()).flush(list([assignment(1)]));
    expect(ctx.store.assignments().status).toBe('ready');
  });

  it('loading another user cancels the reads in flight for the first', () => {
    ctx = setup();
    ctx.store.load(USER_ID);
    const first = [ctx.http.expectOne(userUrl()), ctx.http.expectOne(rolesUrl())];

    ctx.store.load(OTHER_ID);

    expect(first.every((req) => req.cancelled)).toBe(true);
    ctx.http.expectOne(userUrl(OTHER_ID)).flush(user({ userId: OTHER_ID }));
    ctx.http.expectOne(rolesUrl(OTHER_ID)).flush(list([]));
    expect(ctx.store.userId()).toBe(OTHER_ID);
  });

  it('hands the user read to the directory cache, so "Assigned by" can show it later', () => {
    ctx = setup();
    ctx.store.load(USER_ID);
    ctx.http.expectOne(userUrl()).flush(user());
    ctx.http.expectOne(rolesUrl()).flush(list([]));

    expect(ctx.cache.email(USER_ID)).toBe(ADDRESS);
  });

  it('warns once, with the count only, when a user holds more roles than one page', () => {
    ctx = setup();
    ctx.store.load(USER_ID);
    ctx.http.expectOne(userUrl()).flush(user());
    ctx.http.expectOne(rolesUrl()).flush(list([assignment(1)], 101));

    const [, , warn] = ctx.logs;
    expect(warn).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        event: 'access_console_user_roles_truncated',
        context: { area: 'assignments', userId: USER_ID, count: 101 },
      }),
    );
    const assignments = ctx.store.assignments();
    expect(assignments.status === 'ready' && assignments.data.total).toBe(101);
  });

  it('shows another signed-in user nothing (design §6.2)', () => {
    ctx = setup();
    ctx.store.load(USER_ID);
    ctx.http.expectOne(userUrl()).flush(user());
    ctx.http.expectOne(rolesUrl()).flush(list([assignment(1)]));

    ctx.authStore.session.set(createAuthSession({ user: createAuthUser({ userId: 'caller-2' }) }));

    expect(ctx.store.state().status).toBe('idle');
    expect(ctx.store.assignments().status).toBe('idle');
    expect(ctx.store.userId()).toBeNull();
  });

  it('reads nothing while signed out', () => {
    ctx = setup();
    ctx.authStore.session.set(null);

    ctx.store.load(USER_ID);

    ctx.http.expectNone(() => true);
    expect(ctx.store.state().status).toBe('idle');
  });
});
