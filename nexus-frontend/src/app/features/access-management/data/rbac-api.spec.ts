import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { apiErrorInterceptor } from '../../../core/http/api-error.interceptor';
import { ServiceAvailabilityNotifier } from '../../../core/http/service-availability-notifier';
import { SKIP_ACCESS_DENIED_REDIRECT } from '../../../core/http/skip-access-denied-redirect';
import type {
  CallerAuthorizationResponse,
  PermissionListResponse,
  PermissionPageResponse,
  RoleAssignmentListResponse,
  RoleAssignmentResponse,
  RoleListResponse,
  RoleResponse,
} from '../../../shared/types/api/rbac';
import type { AppError } from '../../../shared/types/app-error';
import { RbacApi, VersionedPermissionSet } from './rbac-api';

const API = 'http://localhost:1000/api';

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

const PROFILE: CallerAuthorizationResponse = {
  userId: '0190a000-0000-7000-8000-000000000001',
  roles: [{ roleId: '0190a000-0000-7000-8000-00000000000a', name: 'Support' }],
  permissions: ['role:read'],
  isAdministrator: false,
};

describe('RbacApi', () => {
  let api: RbacApi;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        { provide: APP_CONFIG, useValue: CONFIG },
        { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
        provideRouter([]),
        // Errors reach the client as AppError, as in the app, so the retry-once sees codes.
        provideHttpClient(withInterceptors([apiErrorInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    api = TestBed.inject(RbacApi);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  describe('getMyAuthorization', () => {
    it('GETs /v1/users/me/authorization and emits the typed body', () => {
      let received: CallerAuthorizationResponse | undefined;
      api.getMyAuthorization().subscribe((body) => (received = body));

      const req = http.expectOne(`${API}/v1/users/me/authorization`);
      expect(req.request.method).toBe('GET');
      expect(req.request.body).toBeNull();
      req.flush(PROFILE);

      expect(received).toEqual(PROFILE);
    });

    it('carries SKIP_ACCESS_DENIED_REDIRECT, so a 403 stays with the console (FR-F4)', () => {
      api.getMyAuthorization().subscribe();

      const req = http.expectOne(`${API}/v1/users/me/authorization`);
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(PROFILE);
    });

    it('gives each request its own context instance', () => {
      api.getMyAuthorization().subscribe();
      api.getMyAuthorization().subscribe();

      const [first, second] = http.match(`${API}/v1/users/me/authorization`);
      expect(first.request.context).not.toBe(second.request.context);
      first.flush(PROFILE);
      second.flush(PROFILE);
    });
  });

  describe('listRoles', () => {
    const PAGE: RoleListResponse = {
      data: [],
      page: { size: 100, number: 0, totalElements: 0, totalPages: 1 },
      links: { next: null, prev: null },
    };

    it('GETs /v1/roles with the zero-based page and the size, and emits the typed body', () => {
      let received: RoleListResponse | undefined;
      api.listRoles(3, 100).subscribe((body) => (received = body));

      const req = http.expectOne(`${API}/v1/roles?page=3&size=100`);
      expect(req.request.method).toBe('GET');
      expect(req.request.body).toBeNull();
      req.flush(PAGE);

      expect(received).toEqual(PAGE);
    });

    it('carries SKIP_ACCESS_DENIED_REDIRECT, so a 403 stays with the console (FR-F4)', () => {
      api.listRoles(0, 100).subscribe();

      const req = http.expectOne(`${API}/v1/roles?page=0&size=100`);
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(PAGE);
    });
  });

  describe('listPermissions', () => {
    const PAGE: PermissionPageResponse = {
      data: [],
      page: { size: 100, number: 0, totalElements: 0, totalPages: 1 },
      links: { next: null, prev: null },
    };

    it('GETs /v1/permissions with the zero-based page and the size, and emits the typed body', () => {
      let received: PermissionPageResponse | undefined;
      api.listPermissions(1, 100).subscribe((body) => (received = body));

      const req = http.expectOne(`${API}/v1/permissions?page=1&size=100`);
      expect(req.request.method).toBe('GET');
      expect(req.request.body).toBeNull();
      req.flush(PAGE);

      expect(received).toEqual(PAGE);
    });

    it('carries SKIP_ACCESS_DENIED_REDIRECT, so a 403 stays with the console (FR-F4)', () => {
      api.listPermissions(0, 100).subscribe();

      const req = http.expectOne(`${API}/v1/permissions?page=0&size=100`);
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(PAGE);
    });
  });
  describe('getRole', () => {
    const ROLE_ID = '0190a000-0000-7000-8000-0000000000b1';
    const ROLE: RoleResponse = {
      id: ROLE_ID,
      name: 'Support',
      description: 'Handles tickets',
      isSystemRole: false,
      createdAt: '2026-01-01T00:00:00Z',
      memberCount: 2,
      permissionCount: 1,
    };

    it('GETs /v1/roles/{id} and emits the typed body', () => {
      let received: RoleResponse | undefined;
      api.getRole(ROLE_ID).subscribe((body) => (received = body));

      const req = http.expectOne(`${API}/v1/roles/${ROLE_ID}`);
      expect(req.request.method).toBe('GET');
      expect(req.request.body).toBeNull();
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(ROLE);

      expect(received).toEqual(ROLE);
    });

    it('encodes the id as one path segment, so a crafted route parameter cannot change the path', () => {
      api.getRole('../users/me').subscribe();

      http.expectOne(`${API}/v1/roles/%2E%2E%2Fusers%2Fme`).flush(ROLE);
    });

    it('encodes a dot-dot id, so it cannot resolve to the parent path', () => {
      api.getRole('..').subscribe();

      http.expectOne(`${API}/v1/roles/%2E%2E`).flush(ROLE);
    });
  });

  describe('getRolePermissions (design §7.1, §7.2)', () => {
    const ROLE_ID = '0190a000-0000-7000-8000-0000000000b1';
    const URL = `${API}/v1/roles/${ROLE_ID}/permissions`;
    const BODY: PermissionListResponse = {
      data: [{ id: 'p-1', name: 'role:read', description: 'Read roles', isSensitive: false }],
    };

    function read(headers: Record<string, string>, body: PermissionListResponse | null = BODY) {
      let received: VersionedPermissionSet | undefined;
      let failure: unknown;
      api.getRolePermissions(ROLE_ID).subscribe({
        next: (set) => (received = set),
        error: (error: unknown) => (failure = error),
      });
      const req = http.expectOne(URL);
      req.flush(body, { headers });
      return { req, received, failure };
    }

    it('GETs the set with the console context and emits the permissions', () => {
      const { req, received } = read({ ETag: '"v1"' });

      expect(req.request.method).toBe('GET');
      expect(req.request.body).toBeNull();
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      expect(received?.permissions).toEqual(BODY.data);
    });

    it('keeps a strong ETag verbatim, quotes included', () => {
      expect(read({ ETag: '"0123abcd"' }).received?.etag).toEqual({
        kind: 'strong',
        value: '"0123abcd"',
      });
    });

    it('classifies a weak ETag as weak and keeps no value to send back', () => {
      expect(read({ ETag: 'W/"0123abcd"' }).received?.etag).toEqual({ kind: 'weak' });
    });

    it('classifies a response without an ETag as missing', () => {
      expect(read({}).received?.etag).toEqual({ kind: 'missing' });
    });

    it('carries the correlation id the server echoed, or null without one', () => {
      expect(read({ ETag: '"v1"', 'X-Correlation-Id': 'corr-1' }).received?.correlationId).toBe(
        'corr-1',
      );
      expect(read({ ETag: '"v1"' }).received?.correlationId).toBeNull();
    });

    it('treats an empty set as a valid answer', () => {
      expect(read({ ETag: '"v0"' }, { data: [] }).received?.permissions).toEqual([]);
    });

    it('fails a 200 without a body rather than showing an empty set', () => {
      const { received, failure } = read({ ETag: '"v1"' }, null);

      expect(received).toBeUndefined();
      expect((failure as AppError).code).toBe('UNEXPECTED_ERROR');
    });

    it('encodes the id as one path segment', () => {
      api.getRolePermissions('a/b').subscribe();

      http.expectOne(`${API}/v1/roles/a%2Fb/permissions`).flush(BODY);
    });
  });

  describe('replaceRolePermissions (design §7.1, §7.2, §7.3)', () => {
    const ROLE_ID = '0190a000-0000-7000-8000-0000000000b1';
    const URL = `${API}/v1/roles/${ROLE_ID}/permissions`;
    const IDS = ['0190a000-0000-7000-8000-0000000000p1', '0190a000-0000-7000-8000-0000000000p2'];
    const STRONG = '"7f3a-AZ_09!#$%&\'()*+,-./:;<=>?@[]^`{|}~"';
    const BODY: PermissionListResponse = {
      data: [{ id: IDS[0], name: 'role:read', description: 'Read roles', isSensitive: false }],
    };

    function save() {
      let received: VersionedPermissionSet | undefined;
      let failure: unknown;
      api.replaceRolePermissions(ROLE_ID, IDS, STRONG).subscribe({
        next: (set) => (received = set),
        error: (error: unknown) => (failure = error),
      });
      return {
        received: () => received,
        failure: () => failure as AppError | undefined,
      };
    }

    /** Answers a request with the problem document of `code`. */
    function refuse(req: TestRequest, code: string, status: number): void {
      req.flush(
        { code, detail: 'Server detail', traceId: 'trace-1' },
        { status, statusText: code },
      );
    }

    it('PUTs the ids with the strong tag as If-Match, byte for byte', () => {
      save();

      const req = http.expectOne(URL);
      expect(req.request.method).toBe('PUT');
      expect(req.request.body).toEqual({ permissionIds: IDS });
      expect(req.request.headers.getAll('If-Match')).toEqual([STRONG]);
      req.flush(BODY, { headers: { ETag: '"v2"' } });
    });

    it('carries SKIP_ACCESS_DENIED_REDIRECT, so a 403 stays with the editor (FR-F4)', () => {
      save();

      const req = http.expectOne(URL);
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(BODY, { headers: { ETag: '"v2"' } });
    });

    it('emits the new set and its new tag from the 200, with no second request', () => {
      const outcome = save();

      http.expectOne(URL).flush(BODY, { headers: { ETag: '"v2"', 'X-Correlation-Id': 'corr-2' } });

      expect(outcome.received()).toEqual({
        permissions: BODY.data,
        etag: { kind: 'strong', value: '"v2"' },
        correlationId: 'corr-2',
      });
      http.expectNone(URL);
    });

    it('retries an RBAC_012 once with the same body and If-Match (RES-53)', () => {
      const outcome = save();

      const first = http.expectOne(URL);
      refuse(first, 'RBAC_012', 409);
      const second = http.expectOne(URL);
      expect(second.request.body).toEqual(first.request.body);
      expect(second.request.headers.get('If-Match')).toBe(STRONG);
      second.flush(BODY, { headers: { ETag: '"v2"' } });

      expect(outcome.received()?.etag).toEqual({ kind: 'strong', value: '"v2"' });
    });

    it.each([
      ['PRECONDITION_FAILED', 412],
      ['PRECONDITION_REQUIRED', 428],
      ['RBAC_001', 403],
      ['RBAC_003', 409],
      ['RBAC_011', 429],
      ['AUTH_005', 503],
    ] as const)('surfaces %s without retrying', (code, status) => {
      const outcome = save();

      refuse(http.expectOne(URL), code, status);

      http.expectNone(URL);
      expect(outcome.failure()?.code).toBe(code);
    });

    it('encodes the id as one path segment', () => {
      api.replaceRolePermissions('../x', IDS, STRONG).subscribe();

      http
        .expectOne(`${API}/v1/roles/%2E%2E%2Fx/permissions`)
        .flush(BODY, { headers: { ETag: '"v2"' } });
    });
  });

  describe('createRole (design §7.1, §11.3)', () => {
    const URL = `${API}/v1/roles`;
    const CREATED: RoleResponse = {
      id: '0190a000-0000-7000-8000-0000000000c9',
      name: 'Support',
      description: 'Handles tickets',
      isSystemRole: false,
      createdAt: '2026-01-01T00:00:00Z',
      memberCount: 0,
      permissionCount: 0,
    };

    it('POSTs exactly the name and description, with the console context, and emits the 201 body', () => {
      let received: RoleResponse | undefined;
      api
        .createRole({ name: 'Support', description: 'Handles tickets' })
        .subscribe((role) => (received = role));

      const req = http.expectOne(URL);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ name: 'Support', description: 'Handles tickets' });
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(CREATED, { status: 201, statusText: 'Created' });

      expect(received).toEqual(CREATED);
    });

    it.each([
      ['RBAC_006', 409],
      ['RBAC_012', 409],
      ['RBAC_008', 409],
      ['AUTH_005', 503],
    ] as const)('surfaces %s without retrying: a create is never re-sent', (code, status) => {
      let failure: AppError | undefined;
      api.createRole({ name: 'Support', description: '' }).subscribe({
        error: (error: AppError) => (failure = error),
      });

      http.expectOne(URL).flush({ code, detail: 'Server detail' }, { status, statusText: code });

      http.expectNone(URL);
      expect(failure?.code).toBe(code);
    });
  });

  describe('listAssignments (design §7.1, T-016)', () => {
    const USER_ID = '0190a000-0000-7000-8000-000000000042';
    const LIST: RoleAssignmentListResponse = {
      data: [
        {
          userId: USER_ID,
          roleId: '0190a000-0000-7000-8000-0000000000b1',
          roleName: 'Support',
          assignedAt: '2026-01-01T00:00:00Z',
          assignedBy: null,
        },
      ],
      page: { size: 100, number: 0, totalElements: 1, totalPages: 1 },
      links: { next: null, prev: null },
    };

    it('GETs /v1/users/{id}/roles with page and size, the console context, and emits the body', () => {
      let received: RoleAssignmentListResponse | undefined;
      api.listAssignments(USER_ID, 0, 100).subscribe((body) => (received = body));

      const req = http.expectOne(`${API}/v1/users/${USER_ID}/roles?page=0&size=100`);
      expect(req.request.method).toBe('GET');
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(LIST);

      expect(received).toEqual(LIST);
    });

    it('encodes the id as one path segment', () => {
      api.listAssignments('../x/..', 0, 100).subscribe();

      http.expectOne(`${API}/v1/users/%2E%2E%2Fx%2F%2E%2E/roles?page=0&size=100`).flush(LIST);
    });

    it('surfaces a 403 as an AppError, never retrying a read', () => {
      let failure: AppError | undefined;
      api.listAssignments(USER_ID, 0, 100).subscribe({
        error: (error: AppError) => (failure = error),
      });

      const url = `${API}/v1/users/${USER_ID}/roles?page=0&size=100`;
      http.expectOne(url).flush({ code: 'RBAC_001' }, { status: 403, statusText: 'Forbidden' });

      http.expectNone(url);
      expect(failure?.code).toBe('RBAC_001');
    });
  });

  describe('assignRole (design §7.1, §7.3; FR-X6, FR-G3)', () => {
    const USER_ID = '0190a000-0000-7000-8000-000000000042';
    const ROLE_ID = '0190a000-0000-7000-8000-0000000000b1';
    const URL = `${API}/v1/users/${USER_ID}/roles`;
    const CREATED: RoleAssignmentResponse = {
      userId: USER_ID,
      roleId: ROLE_ID,
      roleName: 'Support',
      assignedAt: '2026-01-01T00:00:00Z',
      assignedBy: '0190a000-0000-7000-8000-0000000000ca',
    };

    function assign() {
      let received: RoleAssignmentResponse | undefined;
      let failure: unknown;
      api.assignRole(USER_ID, ROLE_ID).subscribe({
        next: (body) => (received = body),
        error: (error: unknown) => (failure = error),
      });
      return {
        received: () => received,
        failure: () => failure as AppError | undefined,
      };
    }

    function refuse(req: TestRequest, code: string, status: number): void {
      req.flush(
        { code, detail: 'Server detail', traceId: 'trace-1' },
        { status, statusText: code },
      );
    }

    it('POSTs exactly {roleId} with the console context and emits the 201 body', () => {
      const outcome = assign();

      const req = http.expectOne(URL);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ roleId: ROLE_ID });
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(CREATED, { status: 201, statusText: 'Created' });

      expect(outcome.received()).toEqual(CREATED);
      http.expectNone(URL);
    });

    it('re-sends an RBAC_012 once with the same body (RES-53)', () => {
      const outcome = assign();

      const first = http.expectOne(URL);
      refuse(first, 'RBAC_012', 409);
      const second = http.expectOne(URL);
      expect(second.request.body).toEqual(first.request.body);
      second.flush(CREATED, { status: 201, statusText: 'Created' });

      expect(outcome.received()).toEqual(CREATED);
    });

    it('surfaces a second RBAC_012 and sends nothing more', () => {
      const outcome = assign();

      refuse(http.expectOne(URL), 'RBAC_012', 409);
      refuse(http.expectOne(URL), 'RBAC_012', 409);

      http.expectNone(URL);
      expect(outcome.failure()?.code).toBe('RBAC_012');
    });

    it('surfaces a 403 met on the retry (US-019 §0 #29)', () => {
      const outcome = assign();

      refuse(http.expectOne(URL), 'RBAC_012', 409);
      refuse(http.expectOne(URL), 'RBAC_001', 403);

      http.expectNone(URL);
      expect(outcome.failure()?.code).toBe('RBAC_001');
    });

    it.each([
      ['RBAC_001', 403],
      ['PRECONDITION_FAILED', 412],
      ['RBAC_011', 429],
      ['AUTH_005', 503],
      ['RBAC_004', 409],
      ['RBAC_010', 409],
    ] as const)('surfaces %s without retrying', (code, status) => {
      const outcome = assign();

      refuse(http.expectOne(URL), code, status);

      http.expectNone(URL);
      expect(outcome.failure()?.code).toBe(code);
    });

    it('encodes the user id as one path segment', () => {
      api.assignRole('../x', ROLE_ID).subscribe();

      http
        .expectOne(`${API}/v1/users/%2E%2E%2Fx/roles`)
        .flush(CREATED, { status: 201, statusText: 'Created' });
    });
  });

  describe('revokeRole (design §7.1, §11.4; FR-C5, FR-G3)', () => {
    const USER_ID = '0190a000-0000-7000-8000-000000000042';
    const ROLE_ID = '0190a000-0000-7000-8000-0000000000b1';
    const URL = `${API}/v1/users/${USER_ID}/roles/${ROLE_ID}`;

    function revoke() {
      let completed = false;
      let emitted = 0;
      let failure: unknown;
      api.revokeRole(USER_ID, ROLE_ID).subscribe({
        next: () => (emitted += 1),
        complete: () => (completed = true),
        error: (error: unknown) => (failure = error),
      });
      return {
        completed: () => completed,
        emitted: () => emitted,
        failure: () => failure as AppError | undefined,
      };
    }

    it('DELETEs the assignment with the console context and completes on the 204', () => {
      const outcome = revoke();

      const req = http.expectOne(URL);
      expect(req.request.method).toBe('DELETE');
      expect(req.request.body).toBeNull();
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(null, { status: 204, statusText: 'No Content' });

      expect(outcome.emitted()).toBe(1);
      expect(outcome.completed()).toBe(true);
      http.expectNone(URL);
    });

    it.each([
      ['RBAC_002', 409],
      ['ROLE_ASSIGNMENT_NOT_FOUND', 404],
      ['RBAC_001', 403],
      ['RBAC_011', 429],
      ['RBAC_012', 409],
      ['AUTH_005', 503],
    ] as const)('surfaces %s without re-sending', (code, status) => {
      const outcome = revoke();

      http
        .expectOne(URL)
        .flush({ code, detail: 'Server detail', traceId: 'trace-1' }, { status, statusText: code });

      http.expectNone(URL);
      expect(outcome.failure()?.code).toBe(code);
    });

    it('encodes both ids as one path segment each', () => {
      api.revokeRole('../x', 'a/b').subscribe();

      http
        .expectOne(`${API}/v1/users/%2E%2E%2Fx/roles/a%2Fb`)
        .flush(null, { status: 204, statusText: 'No Content' });
    });
  });
});
