import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { authInterceptor } from './auth.interceptor';
import { AuthStore } from '../auth/auth.store';
import { Router } from '@angular/router';
import { AuthService } from '../../features/auth/auth.service';
import { AuthSession } from '../../shared/types/auth';
import { APP_CONFIG } from '../config/app-config';
import { of, Subject, throwError } from 'rxjs';

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
        // Explicit so the interceptor's origin/same-API check resolves consistently against the
        // relative '/api/...' URLs used throughout this spec, regardless of which environment
        // file the unit-test build happens to wire up.
        {
          provide: APP_CONFIG,
          useValue: { production: false, apiBaseUrl: '/api', logLevel: 'debug' },
        },
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

  // ── Proactive refresh tests (AC-4) ──────────────────────────────────────────

  function nearExpirySession(): AuthSession {
    return { ...TEST_SESSION, expiresAt: Date.now() + 60_000 }; // 60s < 120s threshold
  }

  function freshSession(): AuthSession {
    return { ...TEST_SESSION, expiresAt: Date.now() + 900_000 }; // 15 min — well above threshold
  }

  it('P-1: proactive refresh fires when TTL < 2 min; request forwarded with new token', () => {
    const refreshedSession: AuthSession = { ...TEST_SESSION, accessToken: 'new-token-xyz' };
    mockAuthStore.session.mockReturnValue(nearExpirySession());
    mockAuthService.refresh.mockReturnValue(of(refreshedSession));

    let result: unknown;
    http.get('/api/v1/resource').subscribe({ next: (v) => (result = v) });

    const req = controller.expectOne('/api/v1/resource');
    expect(req.request.headers.get('Authorization')).toBe('Bearer new-token-xyz');
    req.flush({ data: 'ok' });

    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);
    expect(result).toEqual({ data: 'ok' });
  });

  it('P-2: no proactive refresh when TTL > 2 min', () => {
    mockAuthStore.session.mockReturnValue(TEST_SESSION); // expiresAt = now + 3600s
    mockAuthStore.accessToken.mockReturnValue('current-token');

    http.get('/api/v1/resource').subscribe();

    const req = controller.expectOne('/api/v1/resource');
    expect(req.request.headers.get('Authorization')).toBe('Bearer current-token');
    req.flush({});

    expect(mockAuthService.refresh).not.toHaveBeenCalled();
  });

  it('P-3: no proactive refresh for /api/v1/auth/refresh (infinite-loop guard)', () => {
    mockAuthStore.session.mockReturnValue(nearExpirySession());

    http.post('/api/v1/auth/refresh', null).subscribe();

    const req = controller.expectOne('/api/v1/auth/refresh');
    req.flush({});

    expect(mockAuthService.refresh).not.toHaveBeenCalled();
  });

  it('P-4: no proactive refresh when session is null', () => {
    // session already returns null by default in beforeEach

    http.get('/api/v1/resource').subscribe();

    const req = controller.expectOne('/api/v1/resource');
    req.flush({});

    expect(mockAuthService.refresh).not.toHaveBeenCalled();
  });

  it('P-5: proactive refresh failure → clearSession + navigate to /auth/login', () => {
    mockAuthStore.session.mockReturnValue(nearExpirySession());
    mockAuthService.refresh.mockReturnValue(throwError(() => new Error('cookie gone')));

    let errorCaptured = false;
    http.get('/api/v1/resource').subscribe({ error: () => (errorCaptured = true) });

    expect(mockAuthStore.clearSession).toHaveBeenCalled();
    expect(mockRouter.navigate).toHaveBeenCalledWith(['/auth/login']);
    expect(errorCaptured).toBe(true);
  });

  it('T2-1: concurrent requests with TTL < 2 min share one refresh call (thundering herd)', () => {
    // Use Subject so both subscriptions register before the refresh emits,
    // ensuring both see the same refreshInFlight observable.
    const refreshSubject = new Subject<AuthSession>();
    mockAuthStore.session.mockReturnValue(nearExpirySession());
    mockAuthStore.accessToken.mockReturnValue('new-token');
    mockAuthService.refresh.mockReturnValue(refreshSubject.asObservable());

    let resultA: unknown;
    let resultB: unknown;
    http.get('/api/v1/a').subscribe({ next: (v) => (resultA = v) });
    http.get('/api/v1/b').subscribe({ next: (v) => (resultB = v) });

    // Both subscribed — refresh must have been called exactly once so far
    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);

    // Emit the refresh result — both requests are now forwarded
    refreshSubject.next(TEST_SESSION);
    refreshSubject.complete();

    const reqA = controller.expectOne('/api/v1/a');
    const reqB = controller.expectOne('/api/v1/b');
    reqA.flush({ a: 1 });
    reqB.flush({ b: 2 });

    expect(resultA).toEqual({ a: 1 });
    expect(resultB).toEqual({ b: 2 });
    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);
  });

  it('T2-2: proactive refresh in flight + concurrent reactive 401 share one refresh call (cross-path guard)', () => {
    // Request A enters the proactive path first (near-expiry session).
    // Request B has already been forwarded (fresh session at that point) but returns 401,
    // entering the reactive path. Both must reuse the same refreshInFlight — one POST /refresh.
    const refreshSubject = new Subject<AuthSession>();
    mockAuthStore.session.mockReturnValue(nearExpirySession());
    mockAuthStore.accessToken.mockReturnValue('new-token');
    mockAuthService.refresh.mockReturnValue(refreshSubject.asObservable());

    // Request A — enters proactive path; refreshInFlight is set but not yet emitted.
    let resultA: unknown;
    http.get('/api/v1/a').subscribe({ next: (v) => (resultA = v) });

    // Request B — bypasses proactive (session reports fresh for this call to simulate
    // a request that was already past the interceptor). We trigger its 401 path by
    // flushing the forwarded request with 401 before refresh emits.
    // In the reactive path it checks refreshInFlight !== null and reuses it.
    mockAuthStore.session.mockReturnValue(freshSession());
    let resultB: unknown;
    http.get('/api/v1/b').subscribe({ next: (v) => (resultB = v) });
    const reqBFirst = controller.expectOne('/api/v1/b');
    reqBFirst.flush(
      { code: 'UNAUTHORIZED', detail: 'Token expired.' },
      { status: 401, statusText: 'Unauthorized' },
    );

    // Both paths have now subscribed to the same refreshInFlight.
    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);

    // Emit the refresh — both forwarded requests should proceed.
    refreshSubject.next(TEST_SESSION);
    refreshSubject.complete();

    const reqA = controller.expectOne('/api/v1/a');
    const reqBRetry = controller.expectOne('/api/v1/b');
    reqA.flush({ a: 1 });
    reqBRetry.flush({ b: 2 });

    expect(resultA).toEqual({ a: 1 });
    expect(resultB).toEqual({ b: 2 });
    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);
  });

  it('T5-1: after proactive refresh failure, next request does not re-enter proactive path', () => {
    // Wire clearSession to flip session to null, simulating real store behaviour.
    let sessionVal: AuthSession | null = nearExpirySession();
    mockAuthStore.session.mockImplementation(() => sessionVal);
    mockAuthStore.clearSession.mockImplementation(() => {
      sessionVal = null;
    });
    mockAuthService.refresh.mockReturnValue(throwError(() => new Error('failed')));

    // First request: proactive fires, refresh fails
    let firstErrorCaptured = false;
    http.get('/api/v1/first').subscribe({ error: () => (firstErrorCaptured = true) });
    expect(firstErrorCaptured).toBe(true);

    expect(mockAuthStore.clearSession).toHaveBeenCalledTimes(1);
    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);

    // Second request: session is now null → proactive = false → forwarded directly
    http.get('/api/v1/second').subscribe();
    const req = controller.expectOne('/api/v1/second');
    req.flush({ ok: true });

    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1); // no second refresh
  });

  it('T3-1: proactive refresh cycle does not write to localStorage or sessionStorage', () => {
    // localStorage and sessionStorage share Storage.prototype — one spy covers both.
    const storageSpy = vi.spyOn(Storage.prototype, 'setItem');

    mockAuthStore.session.mockReturnValue(nearExpirySession());
    mockAuthStore.accessToken.mockReturnValue('new-token');
    mockAuthService.refresh.mockReturnValue(of(TEST_SESSION));

    http.get('/api/v1/resource').subscribe();

    const req = controller.expectOne('/api/v1/resource');
    req.flush({});

    expect(storageSpy).not.toHaveBeenCalled();

    storageSpy.mockRestore();
  });

  // ── Gap: /auth/login 401 should not trigger refresh ────────────────────────

  it('P-3b: no proactive refresh for /api/v1/auth/login (loop guard covers all AUTH_PATHS)', () => {
    // /auth/login is also in AUTH_PATHS; proactive must be suppressed the same way
    // it is for /auth/refresh, to prevent an infinite-login/refresh loop.
    mockAuthStore.session.mockReturnValue(nearExpirySession());

    http.post('/api/v1/auth/login', { email: 'a@b.com', password: 'x' }).subscribe();

    const req = controller.expectOne('/api/v1/auth/login');
    req.flush({});

    expect(mockAuthService.refresh).not.toHaveBeenCalled();
  });

  it('on 401 to /api/v1/auth/login, does NOT trigger reactive refresh or navigate', () => {
    // Mirrors the /auth/refresh guard: a 401 from the login endpoint itself
    // (e.g. wrong credentials) must not be treated as an expired-token 401.
    mockAuthStore.accessToken.mockReturnValue('some-token');

    let errorCaptured = false;
    http
      .post('/api/v1/auth/login', { email: 'a@b.com', password: 'wrong' })
      .subscribe({ error: () => (errorCaptured = true) });

    const req = controller.expectOne('/api/v1/auth/login');
    req.flush(
      { code: 'AUTH_001', detail: 'Invalid credentials.' },
      { status: 401, statusText: 'Unauthorized' },
    );

    expect(mockAuthService.refresh).not.toHaveBeenCalled();
    expect(mockAuthStore.clearSession).not.toHaveBeenCalled();
    expect(mockRouter.navigate).not.toHaveBeenCalled();
    expect(errorCaptured).toBe(true);
  });

  // ── Gap: TTL exactly equal to threshold (boundary value) ───────────────────

  it('B-1: no proactive refresh when TTL is exactly equal to the 2-min threshold (strict less-than)', () => {
    // The condition is `expiresAt - Date.now() < 120_000` (strict).
    // A session expiring in exactly 120 000 ms must NOT trigger proactive refresh.
    // We freeze Date.now() so the arithmetic is deterministic.
    const frozenNow = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(frozenNow);

    const atThresholdSession: AuthSession = {
      ...TEST_SESSION,
      expiresAt: frozenNow + 120_000, // difference === 120 000 — NOT < 120 000
    };
    mockAuthStore.session.mockReturnValue(atThresholdSession);
    mockAuthStore.accessToken.mockReturnValue('current-token');

    http.get('/api/v1/resource').subscribe();

    const req = controller.expectOne('/api/v1/resource');
    expect(req.request.headers.get('Authorization')).toBe('Bearer current-token');
    req.flush({});

    expect(mockAuthService.refresh).not.toHaveBeenCalled();

    vi.restoreAllMocks();
  });

  it('B-2: proactive refresh fires when TTL is 1 ms below the threshold (boundary)', () => {
    // Verify the boundary from the other side: 119 999 ms < 120 000 ms → proactive fires.
    const frozenNow = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(frozenNow);

    const justBelowSession: AuthSession = {
      ...TEST_SESSION,
      expiresAt: frozenNow + 119_999,
    };
    const refreshedSession: AuthSession = { ...TEST_SESSION, accessToken: 'boundary-new-token' };
    mockAuthStore.session.mockReturnValue(justBelowSession);
    mockAuthService.refresh.mockReturnValue(of(refreshedSession));

    http.get('/api/v1/resource').subscribe();

    const req = controller.expectOne('/api/v1/resource');
    expect(req.request.headers.get('Authorization')).toBe('Bearer boundary-new-token');
    req.flush({});

    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);

    vi.restoreAllMocks();
  });

  // ── Gap: third concurrent request joins existing in-flight ─────────────────

  // ── Gap: /auth/logout 401 must not trigger refresh (T-5.4 session resurrection) ──

  it('T5-4: does not issue POST /refresh when POST /logout returns 401', () => {
    // Proactive branch must not fire: seed a far-future session (3600s > 120s threshold).
    // Only the reactive-401 path can trigger refresh — and it must be suppressed for /logout.
    mockAuthStore.session.mockReturnValue(TEST_SESSION);
    mockAuthStore.accessToken.mockReturnValue('valid-token');
    mockAuthService.refresh.mockReturnValue(
      throwError(() => new Error('refresh must not fire on logout')),
    );

    let errorCaptured = false;
    http.post('/api/v1/auth/logout', null).subscribe({ error: () => (errorCaptured = true) });

    controller
      .expectOne('/api/v1/auth/logout')
      .flush(null, { status: 401, statusText: 'Unauthorized' });

    expect(mockAuthService.refresh).not.toHaveBeenCalled();
    expect(errorCaptured).toBe(true);
  });

  it('T2-3: three concurrent proactive requests share exactly one refresh call', () => {
    const refreshSubject = new Subject<AuthSession>();
    mockAuthStore.session.mockReturnValue(nearExpirySession());
    mockAuthService.refresh.mockReturnValue(refreshSubject.asObservable());

    let resultA: unknown;
    let resultB: unknown;
    let resultC: unknown;
    http.get('/api/v1/a').subscribe({ next: (v) => (resultA = v) });
    http.get('/api/v1/b').subscribe({ next: (v) => (resultB = v) });
    http.get('/api/v1/c').subscribe({ next: (v) => (resultC = v) });

    // All three subscribed — only one refresh call must have been made.
    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);

    refreshSubject.next(TEST_SESSION);
    refreshSubject.complete();

    const reqA = controller.expectOne('/api/v1/a');
    const reqB = controller.expectOne('/api/v1/b');
    const reqC = controller.expectOne('/api/v1/c');
    reqA.flush({ a: 1 });
    reqB.flush({ b: 2 });
    reqC.flush({ c: 3 });

    expect(resultA).toEqual({ a: 1 });
    expect(resultB).toEqual({ b: 2 });
    expect(resultC).toEqual({ c: 3 });
    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);
  });
});
