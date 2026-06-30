import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AuthService } from './auth.service';
import { APP_CONFIG } from '../../core/config/app-config';
import { apiErrorInterceptor } from '../../core/http/api-error.interceptor';
import { AppError } from '../../shared/types/app-error';
import { AuthStore } from '../../core/auth/auth.store';
import { AuthSession } from '../../shared/types/auth';

const TEST_CONFIG = { production: false, apiBaseUrl: '/api', logLevel: 'debug' } as const;

const VALID_TOKEN = 'a'.repeat(64);
const USER_PASS = 'Passphrase99!'; // EXAMPLE — not a real credential

describe('AuthService', () => {
  let service: AuthService;
  let controller: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([apiErrorInterceptor])),
        provideHttpClientTesting(),
        { provide: APP_CONFIG, useValue: TEST_CONFIG },
      ],
    });
    service = TestBed.inject(AuthService);
    controller = TestBed.inject(HttpTestingController);
  });

  afterEach(() => controller.verify());

  describe('register', () => {
    it('should POST to /api/v1/auth/register with correct body', () => {
      let completed = false;
      service
        .register('user@example.com', USER_PASS, true)
        .subscribe({ complete: () => (completed = true) });

      const req = controller.expectOne('/api/v1/auth/register');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({
        email: 'user@example.com',
        password: USER_PASS, // EXAMPLE
        consentAccepted: true,
      });
      req.flush({ message: 'Registration successful.' }, { status: 201, statusText: 'Created' });
      expect(completed).toBe(true);
    });

    it('should propagate AppError on 400 validation failure', () => {
      let captured: AppError | undefined;
      service.register('bad', 'x', true).subscribe({ error: (e: AppError) => (captured = e) });

      controller
        .expectOne('/api/v1/auth/register')
        .flush(
          { code: 'VALIDATION_ERROR', detail: 'Email is invalid.' },
          { status: 400, statusText: 'Bad Request' },
        );
      expect(captured?.code).toBe('VALIDATION_ERROR');
      expect(captured?.message).toBe('Email is invalid.');
    });
  });

  describe('verifyEmail', () => {
    it('should POST to /api/v1/auth/verify-email with correct body', () => {
      let completed = false;
      service.verifyEmail(VALID_TOKEN).subscribe({ complete: () => (completed = true) });

      const req = controller.expectOne('/api/v1/auth/verify-email');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ token: VALID_TOKEN });
      req.flush({ message: 'Email verified.' });
      expect(completed).toBe(true);
    });

    it('should propagate AppError on 410 token-expired response', () => {
      let captured: AppError | undefined;
      service.verifyEmail(VALID_TOKEN).subscribe({ error: (e: AppError) => (captured = e) });

      controller
        .expectOne('/api/v1/auth/verify-email')
        .flush(
          { code: 'AUTH_VRF_002', detail: 'The verification link is invalid or has expired.' },
          { status: 410, statusText: 'Gone' },
        );
      expect(captured?.code).toBe('AUTH_VRF_002');
    });
  });

  describe('forgotPassword', () => {
    it('should POST to /api/v1/auth/password/forgot with email body and complete as void', () => {
      let completed = false;
      service.forgotPassword('user@example.com').subscribe({ complete: () => (completed = true) });

      const req = controller.expectOne('/api/v1/auth/password/forgot');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ email: 'user@example.com' });
      req.flush(
        { message: 'If an account with that email exists, a reset link has been sent.' },
        { status: 202, statusText: 'Accepted' },
      );
      expect(completed).toBe(true);
    });

    it('should propagate AppError on 400 validation failure', () => {
      let captured: AppError | undefined;
      service.forgotPassword('bad').subscribe({ error: (e: AppError) => (captured = e) });

      controller
        .expectOne('/api/v1/auth/password/forgot')
        .flush(
          { code: 'VALIDATION_FAILED', detail: 'must be a valid email' },
          { status: 400, statusText: 'Bad Request' },
        );
      expect(captured?.code).toBe('VALIDATION_FAILED');
    });
  });

  describe('resetPassword', () => {
    it('should POST to /api/v1/auth/password/reset with token and newPassword', () => {
      let result: { message: string } | undefined;
      service.resetPassword(VALID_TOKEN, USER_PASS).subscribe({ next: (r) => (result = r) });

      const req = controller.expectOne('/api/v1/auth/password/reset');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ token: VALID_TOKEN, newPassword: USER_PASS });
      req.flush({ message: 'Password reset successfully. Please sign in.' });
      expect(result?.message).toContain('Password reset');
    });

    it('should propagate AppError on 410 token-expired response', () => {
      let captured: AppError | undefined;
      service
        .resetPassword(VALID_TOKEN, USER_PASS)
        .subscribe({ error: (e: AppError) => (captured = e) });

      controller
        .expectOne('/api/v1/auth/password/reset')
        .flush(
          { code: 'AUTH_RST_002', detail: 'This reset link has expired.' },
          { status: 410, statusText: 'Gone' },
        );
      expect(captured?.code).toBe('AUTH_RST_002');
    });

    it('should propagate AppError on 400 same-password response', () => {
      let captured: AppError | undefined;
      service
        .resetPassword(VALID_TOKEN, USER_PASS)
        .subscribe({ error: (e: AppError) => (captured = e) });

      controller
        .expectOne('/api/v1/auth/password/reset')
        .flush(
          { code: 'AUTH_RST_003', detail: 'New password must differ.' },
          { status: 400, statusText: 'Bad Request' },
        );
      expect(captured?.code).toBe('AUTH_RST_003');
    });
  });

  describe('resendVerification', () => {
    it('should POST to /api/v1/auth/resend-verification with correct body', () => {
      let completed = false;
      service
        .resendVerification('user@example.com')
        .subscribe({ complete: () => (completed = true) });

      const req = controller.expectOne('/api/v1/auth/resend-verification');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ email: 'user@example.com' });
      req.flush({ message: 'A new link has been sent.' });
      expect(completed).toBe(true);
    });

    it('should propagate AppError on 429 rate-limit response', () => {
      let captured: AppError | undefined;
      service
        .resendVerification('user@example.com')
        .subscribe({ error: (e: AppError) => (captured = e) });

      controller
        .expectOne('/api/v1/auth/resend-verification')
        .flush(
          { code: 'AUTH_RES_001', detail: 'Too many requests.' },
          { status: 429, statusText: 'Too Many Requests' },
        );
      expect(captured?.code).toBe('AUTH_RES_001');
    });
  });
});

describe('AuthService — login/logout/refresh', () => {
  let service: AuthService;
  let controller: HttpTestingController;
  let mockAuthStore: {
    setSession: ReturnType<typeof vi.fn>;
    clearSession: ReturnType<typeof vi.fn>;
    accessToken: ReturnType<typeof vi.fn>;
    isAuthenticated: ReturnType<typeof vi.fn>;
    currentUser: ReturnType<typeof vi.fn>;
    session: ReturnType<typeof vi.fn>;
  };

  const LOGIN_RESPONSE = {
    accessToken: 'access-token-xyz',
    tokenType: 'Bearer',
    expiresIn: 3600,
    userId: 'user-1',
  };

  const ME_RESPONSE = {
    userId: 'user-1',
    emailVerified: true,
    tenantId: 'tenant-1',
    roles: ['USER'],
    tokenVersion: 1,
  };

  // expiresAt is stamped by buildSession via Date.now() — use a numeric matcher.
  const EXPECTED_SESSION = {
    accessToken: 'access-token-xyz',
    tokenType: 'Bearer',
    expiresIn: 3600,
    expiresAt: expect.any(Number) as number,
    user: {
      userId: 'user-1',
      tenantId: 'tenant-1',
      emailVerified: true,
      roles: ['USER'],
      tokenVersion: 1,
    },
  } satisfies AuthSession;

  beforeEach(() => {
    mockAuthStore = {
      setSession: vi.fn(),
      clearSession: vi.fn(),
      accessToken: vi.fn(() => null),
      isAuthenticated: vi.fn(() => false),
      currentUser: vi.fn(() => null),
      session: vi.fn(() => null),
    };

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([apiErrorInterceptor])),
        provideHttpClientTesting(),
        { provide: APP_CONFIG, useValue: TEST_CONFIG },
        { provide: AuthStore, useValue: mockAuthStore },
      ],
    });

    service = TestBed.inject(AuthService);
    controller = TestBed.inject(HttpTestingController);
  });

  afterEach(() => controller.verify());

  it('login() POSTs to /auth/login, then GETs /users/me, sets session in AuthStore, returns AuthSession', () => {
    let result: AuthSession | undefined;
    service.login('user@example.com', USER_PASS).subscribe({ next: (s) => (result = s) });

    const loginReq = controller.expectOne('/api/v1/auth/login');
    expect(loginReq.request.method).toBe('POST');
    expect(loginReq.request.body).toEqual({ email: 'user@example.com', password: USER_PASS });
    loginReq.flush(LOGIN_RESPONSE);

    const meReq = controller.expectOne('/api/v1/users/me');
    expect(meReq.request.method).toBe('GET');
    expect(meReq.request.headers.get('Authorization')).toBe('Bearer access-token-xyz');
    meReq.flush(ME_RESPONSE);

    expect(result).toEqual(EXPECTED_SESSION);
    expect(mockAuthStore.setSession).toHaveBeenCalledWith(EXPECTED_SESSION);
  });

  it('logout() POSTs to /auth/logout, clears session on success', () => {
    let completed = false;
    service.logout().subscribe({ complete: () => (completed = true) });

    const req = controller.expectOne('/api/v1/auth/logout');
    expect(req.request.method).toBe('POST');
    req.flush(null);

    expect(completed).toBe(true);
    expect(mockAuthStore.clearSession).toHaveBeenCalled();
  });

  it('logout() clears session even if HTTP call fails', () => {
    let errorCaptured = false;
    service.logout().subscribe({ error: () => (errorCaptured = true) });

    controller
      .expectOne('/api/v1/auth/logout')
      .flush(
        { code: 'SERVER_ERROR', detail: 'Internal error.' },
        { status: 500, statusText: 'Internal Server Error' },
      );

    expect(errorCaptured).toBe(true);
    expect(mockAuthStore.clearSession).toHaveBeenCalled();
  });

  it('refresh() POSTs to /auth/refresh, then GETs /users/me, updates session', () => {
    let result: AuthSession | undefined;
    service.refresh().subscribe({ next: (s) => (result = s) });

    const refreshReq = controller.expectOne('/api/v1/auth/refresh');
    expect(refreshReq.request.method).toBe('POST');
    refreshReq.flush(LOGIN_RESPONSE);

    const meReq = controller.expectOne('/api/v1/users/me');
    expect(meReq.request.headers.get('Authorization')).toBe('Bearer access-token-xyz');
    meReq.flush(ME_RESPONSE);

    expect(result).toEqual(EXPECTED_SESSION);
    expect(mockAuthStore.setSession).toHaveBeenCalledWith(EXPECTED_SESSION);
  });
});
