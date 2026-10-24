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
import { ACCESS_DRAFT_PREFIX } from '../../core/storage/session-scoped-storage';

const TEST_CONFIG = {
  production: false,
  apiBaseUrl: '/api',
  logLevel: 'debug',
  accessConsoleEnabled: false,
} as const;

const VALID_TOKEN = 'a'.repeat(64);
const USER_PASS = 'Passphrase99!'; // EXAMPLE — not a real credential

/**
 * Tests for registration, email verification, and password reset flows.
 */
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

/**
 * Tests for session lifecycle: login, logout, and token refresh.
 * Verifies secure HTTP-only cookie handling and AuthStore synchronization.
 */
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
    permissions: ['users:read'],
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
      permissions: ['users:read'],
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

  it('login() defaults permissions to [] when /users/me response omits the field (older backend)', () => {
    let result: AuthSession | undefined;
    service.login('user@example.com', USER_PASS).subscribe({ next: (s) => (result = s) });

    controller.expectOne('/api/v1/auth/login').flush(LOGIN_RESPONSE);

    // Simulates a newly deployed frontend served against an older backend that has not
    // yet shipped US-010's `permissions[]` field — the exact scenario buildSession()'s
    // `?? []` default exists to protect against (US-013 AC-4: must not throw).
    controller.expectOne('/api/v1/users/me').flush({
      userId: 'user-1',
      emailVerified: true,
      tenantId: 'tenant-1',
      roles: ['USER'],
      tokenVersion: 1,
    });

    expect(result?.user.permissions).toEqual([]);
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

/**
 * Draft hygiene (US-020 RC-74 items 1 and 2, D-6): the logout `finalize` sweeps every
 * `nexus.session.` key even when the POST fails, and a session for another user removes the
 * previous user's draft keys. `AuthStore.clearSession()` never sweeps (it also runs on a refresh
 * failure, and FR-G4 restores the draft after the same user signs in again). The refresh request
 * pattern is unchanged (RC-65).
 */
describe('AuthService — session-scoped storage (US-020 RC-74, D-6)', () => {
  const USER_A = '0190a000-0000-7000-8000-0000000000a1';
  const USER_B = '0190a000-0000-7000-8000-0000000000b2';
  const ROLE = '0190a000-0000-7000-8000-0000000000c1';
  const DRAFT_A = `${ACCESS_DRAFT_PREFIX}${USER_A}.${ROLE}`;
  const DRAFT_B = `${ACCESS_DRAFT_PREFIX}${USER_B}.${ROLE}`;
  // Not an address: the service passes the sign-in name through untouched.
  const SIGN_IN = 'sign-in-name';

  let service: AuthService;
  let controller: HttpTestingController;
  let store: AuthStore;

  const loginBody = (userId: string) => ({
    accessToken: 'access-token-xyz',
    tokenType: 'Bearer',
    expiresIn: 3600,
    userId,
  });
  const meBody = (userId: string) => ({
    userId,
    emailVerified: true,
    tenantId: 'tenant-1',
    roles: ['USER'],
    permissions: [],
    tokenVersion: 1,
  });

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
    store = TestBed.inject(AuthStore);
    sessionStorage.setItem(DRAFT_A, '{"v":1}');
    sessionStorage.setItem('nexus.session.other', 'x');
    sessionStorage.setItem('nx-theme', 'dark');
  });

  afterEach(() => {
    controller.verify();
    sessionStorage.clear();
  });

  const keys = (): string[] => Object.keys(sessionStorage).sort();

  it('logout() sweeps every nexus.session. key on success', () => {
    service.logout().subscribe();
    controller.expectOne('/api/v1/auth/logout').flush(null);

    expect(keys()).toEqual(['nx-theme']);
  });

  it('logout() sweeps every nexus.session. key when the POST fails (D-6)', () => {
    let failed = false;
    service.logout().subscribe({ error: () => (failed = true) });
    controller
      .expectOne('/api/v1/auth/logout')
      .flush({ code: 'SERVER_ERROR' }, { status: 500, statusText: 'Internal Server Error' });

    expect(failed).toBe(true);
    expect(store.session()).toBeNull();
    expect(keys()).toEqual(['nx-theme']);
  });

  it('logout() sweeps when the network is down', () => {
    service.logout().subscribe({ error: () => undefined });
    controller.expectOne('/api/v1/auth/logout').error(new ProgressEvent('error'));

    expect(keys()).toEqual(['nx-theme']);
  });

  it("login() as another user removes the previous user's draft keys and keeps the rest", () => {
    sessionStorage.setItem(DRAFT_B, '{"v":1}');

    service.login(SIGN_IN, USER_PASS).subscribe();
    controller.expectOne('/api/v1/auth/login').flush(loginBody(USER_B));
    controller.expectOne('/api/v1/users/me').flush(meBody(USER_B));

    expect(store.currentUser()?.userId).toBe(USER_B);
    expect(keys()).toEqual([DRAFT_B, 'nexus.session.other', 'nx-theme']);
  });

  it("login() as the same user keeps that user's draft (FR-G4)", () => {
    service.login(SIGN_IN, USER_PASS).subscribe();
    controller.expectOne('/api/v1/auth/login').flush(loginBody(USER_A));
    controller.expectOne('/api/v1/users/me').flush(meBody(USER_A));

    expect(keys()).toEqual([DRAFT_A, 'nexus.session.other', 'nx-theme']);
  });

  it('a failed login sweeps nothing', () => {
    service.login(SIGN_IN, USER_PASS).subscribe({ error: () => undefined });
    controller
      .expectOne('/api/v1/auth/login')
      .flush({ code: 'AUTH_001' }, { status: 401, statusText: 'Unauthorized' });

    expect(keys()).toEqual([DRAFT_A, 'nexus.session.other', 'nx-theme']);
  });

  it('refresh() for another user removes the draft keys with exactly one refresh and one me read (RC-65)', () => {
    service.refresh().subscribe();
    const refreshes = controller.match('/api/v1/auth/refresh');
    expect(refreshes).toHaveLength(1);
    refreshes[0].flush(loginBody(USER_B));
    const reads = controller.match('/api/v1/users/me');
    expect(reads).toHaveLength(1);
    reads[0].flush(meBody(USER_B));

    controller.expectNone('/api/v1/auth/refresh');
    expect(keys()).toEqual(['nexus.session.other', 'nx-theme']);
  });

  it('a failed refresh sweeps nothing', () => {
    service.refresh().subscribe({ error: () => undefined });
    controller
      .expectOne('/api/v1/auth/refresh')
      .flush({ code: 'AUTH_002' }, { status: 401, statusText: 'Unauthorized' });

    expect(keys()).toEqual([DRAFT_A, 'nexus.session.other', 'nx-theme']);
  });

  it('AuthStore.clearSession() does not sweep (a draft must survive a session expiry)', () => {
    store.clearSession();
    expect(keys()).toEqual([DRAFT_A, 'nexus.session.other', 'nx-theme']);
  });
});
