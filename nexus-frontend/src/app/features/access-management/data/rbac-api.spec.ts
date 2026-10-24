import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { SKIP_ACCESS_DENIED_REDIRECT } from '../../../core/http/skip-access-denied-redirect';
import type {
  CallerAuthorizationResponse,
  PermissionPageResponse,
  RoleListResponse,
} from '../../../shared/types/api/rbac';
import { RbacApi } from './rbac-api';

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
});
