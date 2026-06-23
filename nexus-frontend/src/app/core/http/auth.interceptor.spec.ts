import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { authInterceptor } from './auth.interceptor';
import { AuthStore } from '../auth/auth.store';
import { Router } from '@angular/router';
import { AuthService } from '../../features/auth/auth.service';
import { AuthSession } from '../../shared/types/auth';
import { of, throwError } from 'rxjs';

const TEST_SESSION: AuthSession = {
  accessToken: 'test-token-abc',
  tokenType: 'Bearer',
  expiresIn: 3600,
  expiresAt: Date.now() + 3600 * 1000,
  user: {
    userId: 'user-1',
    tenantId: 'tenant-1',
    emailVerified: true,
    roles: ['USER'],
    tokenVersion: 1,
  },
};

describe('authInterceptor', () => {
  let http: HttpClient;
  let controller: HttpTestingController;
  let mockAuthStore: {
    accessToken: ReturnType<typeof vi.fn>;
    clearSession: ReturnType<typeof vi.fn>;
    isAuthenticated: ReturnType<typeof vi.fn>;
    setSession: ReturnType<typeof vi.fn>;
    currentUser: ReturnType<typeof vi.fn>;
    session: ReturnType<typeof vi.fn>;
  };
  let mockRouter: { navigate: ReturnType<typeof vi.fn> };
  let mockAuthService: { refresh: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    mockAuthStore = {
      accessToken: vi.fn(() => null),
      clearSession: vi.fn(),
      isAuthenticated: vi.fn(() => false),
      setSession: vi.fn(),
      currentUser: vi.fn(() => null),
      session: vi.fn(() => null),
    };
    mockRouter = { navigate: vi.fn() };
    mockAuthService = { refresh: vi.fn() };

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        { provide: AuthStore, useValue: mockAuthStore },
        { provide: Router, useValue: mockRouter },
        { provide: AuthService, useValue: mockAuthService },
      ],
    });

    http = TestBed.inject(HttpClient);
    controller = TestBed.inject(HttpTestingController);
  });

  afterEach(() => controller.verify());

  it('attaches Authorization header when session has token', () => {
    mockAuthStore.accessToken.mockReturnValue('test-token-abc');

    http.get('/api/resource').subscribe();

    const req = controller.expectOne('/api/resource');
    expect(req.request.headers.get('Authorization')).toBe('Bearer test-token-abc');
    req.flush({});
  });

  it('does not attach Authorization when no session', () => {
    mockAuthStore.accessToken.mockReturnValue(null);

    http.get('/api/resource').subscribe();

    const req = controller.expectOne('/api/resource');
    expect(req.request.headers.has('Authorization')).toBe(false);
    req.flush({});
  });

  it('does not overwrite existing Authorization header', () => {
    mockAuthStore.accessToken.mockReturnValue('store-token');

    http.get('/api/resource', { headers: { Authorization: 'Bearer explicit-token' } }).subscribe();

    const req = controller.expectOne('/api/resource');
    expect(req.request.headers.get('Authorization')).toBe('Bearer explicit-token');
    req.flush({});
  });

  it('on 401, clears session and navigates to /auth/login for non-auth URLs', () => {
    mockAuthStore.accessToken.mockReturnValue('expired-token');
    mockAuthService.refresh.mockReturnValue(throwError(() => new Error('refresh failed')));

    let errorCaptured = false;
    http.get('/api/resource').subscribe({ error: () => (errorCaptured = true) });

    const req = controller.expectOne('/api/resource');
    req.flush(
      { code: 'UNAUTHORIZED', detail: 'Token expired.' },
      { status: 401, statusText: 'Unauthorized' },
    );

    expect(mockAuthStore.clearSession).toHaveBeenCalled();
    expect(mockRouter.navigate).toHaveBeenCalledWith(['/auth/login']);
    expect(errorCaptured).toBe(true);
  });

  it('on 401 to /auth/refresh, does NOT navigate or clear session', () => {
    mockAuthStore.accessToken.mockReturnValue('some-token');

    let errorCaptured = false;
    http.post('/api/v1/auth/refresh', null).subscribe({ error: () => (errorCaptured = true) });

    const req = controller.expectOne('/api/v1/auth/refresh');
    req.flush(
      { code: 'UNAUTHORIZED', detail: 'Invalid refresh.' },
      { status: 401, statusText: 'Unauthorized' },
    );

    expect(mockAuthStore.clearSession).not.toHaveBeenCalled();
    expect(mockRouter.navigate).not.toHaveBeenCalled();
    expect(errorCaptured).toBe(true);
  });

  it('on 401, attempts refresh and retries the original request on success', () => {
    mockAuthStore.accessToken.mockReturnValue('expired-token');
    mockAuthService.refresh.mockReturnValue(of(TEST_SESSION));

    let result: unknown;
    http.get('/api/resource').subscribe({ next: (v) => (result = v) });

    // First attempt — returns 401
    const firstReq = controller.expectOne('/api/resource');
    firstReq.flush(
      { code: 'UNAUTHORIZED', detail: 'Token expired.' },
      { status: 401, statusText: 'Unauthorized' },
    );

    // Retry after refresh
    const retryReq = controller.expectOne('/api/resource');
    expect(retryReq.request.headers.get('Authorization')).toBe('Bearer test-token-abc');
    retryReq.flush({ data: 'ok' });

    expect(result).toEqual({ data: 'ok' });
    expect(mockAuthStore.clearSession).not.toHaveBeenCalled();
    expect(mockRouter.navigate).not.toHaveBeenCalled();
  });
});
