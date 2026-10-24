import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { SKIP_ACCESS_DENIED_REDIRECT } from '../../../core/http/skip-access-denied-redirect';
import type {
  CallerAuthorizationResponse,
  PermissionListResponse,
  PermissionPageResponse,
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
        provideHttpClient(),
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
});
