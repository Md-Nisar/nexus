import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { apiErrorInterceptor } from '../../../core/http/api-error.interceptor';
import { ServiceAvailabilityNotifier } from '../../../core/http/service-availability-notifier';
import { SKIP_ACCESS_DENIED_REDIRECT } from '../../../core/http/skip-access-denied-redirect';
import type {
  UserDirectoryEntry,
  UserDirectoryPage,
  UserLookupResponse,
} from '../../../shared/types/api/user-directory';
import type { AppError } from '../../../shared/types/app-error';
import { DirectoryApi } from './directory-api';

const API = 'http://localhost:1000/api';
const USERS = `${API}/v1/users`;
const ADDRESS = 'lookup.target@directory.invalid';

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

const ENTRY: UserDirectoryEntry = {
  userId: '0190a000-0000-7000-8000-000000000001',
  email: ADDRESS,
  status: 'ACTIVE',
  emailVerified: true,
  createdAt: '2026-01-02T03:04:05Z',
};

const PAGE: UserDirectoryPage = {
  data: [ENTRY],
  page: { size: 20, number: 0, totalElements: 1, totalPages: 1 },
  links: { next: null, prev: null },
};

describe('DirectoryApi (US-020 design §7.1)', () => {
  let api: DirectoryApi;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        { provide: APP_CONFIG, useValue: CONFIG },
        { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
        provideRouter([]),
        provideHttpClient(withInterceptors([apiErrorInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    api = TestBed.inject(DirectoryApi);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  describe('listUsers', () => {
    it('GETs /v1/users with page and size, and no status when none is given', () => {
      let received: UserDirectoryPage | undefined;
      api.listUsers({ page: 2, size: 20 }).subscribe((body) => (received = body));

      const req = http.expectOne(`${USERS}?page=2&size=20`);
      expect(req.request.method).toBe('GET');
      expect(req.request.params.has('status')).toBe(false);
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(PAGE);

      expect(received).toEqual(PAGE);
    });

    it('sends the status filter as the wire value', () => {
      api.listUsers({ page: 0, size: 50, status: 'LOCKED' }).subscribe();
      http.expectOne(`${USERS}?page=0&size=50&status=LOCKED`).flush(PAGE);
    });

    it('surfaces a 400 as an AppError for the page to explain', () => {
      let failure: AppError | undefined;
      api.listUsers({ page: 600, size: 20 }).subscribe({ error: (e: AppError) => (failure = e) });
      http
        .expectOne(`${USERS}?page=600&size=20`)
        .flush({ code: 'VALIDATION_FAILED' }, { status: 400, statusText: 'Bad Request' });
      expect(failure?.code).toBe('VALIDATION_FAILED');
    });
  });

  describe('getUser', () => {
    it('GETs /v1/users/{id} with the console context', () => {
      let received: UserDirectoryEntry | undefined;
      api.getUser(ENTRY.userId).subscribe((body) => (received = body));

      const req = http.expectOne(`${USERS}/${ENTRY.userId}`);
      expect(req.request.method).toBe('GET');
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush(ENTRY);
      expect(received).toEqual(ENTRY);
    });

    it('encodes an id from the URL as one path segment, dots included', () => {
      api.getUser('../me/x').subscribe({ error: () => undefined });
      const req = http.expectOne(`${USERS}/%2E%2E%2Fme%2Fx`);
      req.flush({ code: 'VALIDATION_FAILED' }, { status: 400, statusText: 'Bad Request' });
    });
  });

  describe('lookupUser', () => {
    it('POSTs the address in the body only, never in the URL', () => {
      let received: UserLookupResponse | undefined;
      api.lookupUser(ADDRESS).subscribe((body) => (received = body));

      const req = http.expectOne(`${USERS}/lookup`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ email: ADDRESS });
      expect(req.request.params.keys()).toEqual([]);
      expect(req.request.urlWithParams).not.toContain('@');
      expect(req.request.context.get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(true);
      req.flush({ data: [ENTRY] });

      expect(received).toEqual({ data: [ENTRY] });
    });

    it('surfaces a 429 USER_DIR_001 with its Retry-After', () => {
      let failure: AppError | undefined;
      api.lookupUser(ADDRESS).subscribe({ error: (e: AppError) => (failure = e) });
      http
        .expectOne(`${USERS}/lookup`)
        .flush(
          { code: 'USER_DIR_001' },
          { status: 429, statusText: 'Too Many Requests', headers: { 'Retry-After': '12' } },
        );
      expect(failure?.code).toBe('USER_DIR_001');
      expect(failure?.retryAfterSeconds).toBe(12);
    });
  });
});
