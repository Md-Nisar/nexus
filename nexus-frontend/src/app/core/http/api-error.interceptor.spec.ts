import { TestBed } from '@angular/core/testing';
import { HttpClient, HttpContext, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router } from '@angular/router';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { apiErrorInterceptor } from './api-error.interceptor';
import { LoggerService } from '../logging/logger.service';
import { APP_CONFIG } from '../config/app-config';
import { correlationIdInterceptor } from './correlation-id.interceptor';
import { AppError } from '../../shared/types/app-error';
import { SKIP_ACCESS_DENIED_REDIRECT } from './skip-access-denied-redirect';
import { NxToast } from '../../shared/ui';
import recordedRbac012 from '../../../../../contracts/api/problem-rbac-012.json';

describe('apiErrorInterceptor', () => {
  let loggerSpy: {
    debug: ReturnType<typeof vi.fn>;
    info: ReturnType<typeof vi.fn>;
    warn: ReturnType<typeof vi.fn>;
    error: ReturnType<typeof vi.fn>;
  };
  let routerSpy: { navigate: ReturnType<typeof vi.fn> };
  let toastSpy: { warning: ReturnType<typeof vi.fn> };

  function setup() {
    loggerSpy = {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    };

    routerSpy = { navigate: vi.fn().mockResolvedValue(true) };
    toastSpy = { warning: vi.fn() };

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([correlationIdInterceptor, apiErrorInterceptor])),
        provideHttpClientTesting(),
        { provide: LoggerService, useValue: loggerSpy },
        { provide: Router, useValue: routerSpy },
        { provide: NxToast, useValue: toastSpy },
        {
          provide: APP_CONFIG,
          useValue: { production: false, apiBaseUrl: '/api', logLevel: 'debug' },
        },
      ],
    });
    return {
      http: TestBed.inject(HttpClient),
      controller: TestBed.inject(HttpTestingController),
    };
  }

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('should map an RFC 7807 problem response to AppError and log 404 at DEBUG level', () => {
    const { http, controller } = setup();
    let captured: AppError | undefined;

    http.get('/api/users/42').subscribe({ error: (e: AppError) => (captured = e) });
    const req = controller.expectOne('/api/users/42');
    const correlationId = req.request.headers.get('X-Correlation-Id');

    req.flush(
      { code: 'USER_NOT_FOUND', detail: 'No such user.', traceId: 'abc-123' },
      { status: 404, statusText: 'Not Found' },
    );

    expect(captured).toEqual({
      code: 'USER_NOT_FOUND',
      message: 'No such user.',
      traceId: 'abc-123',
      correlationId: correlationId || undefined,
      details: undefined,
    });

    expect(loggerSpy.debug).toHaveBeenCalledOnce();
    expect(loggerSpy.debug).toHaveBeenCalledWith(
      expect.stringContaining('HTTP request failed: GET /api/users/42 - Status 404'),
      expect.objectContaining({ correlationId, errorCode: 'USER_NOT_FOUND' }),
    );
  });

  it('should map requiredPermission from an RBAC_001 problem response onto AppError', () => {
    const { http, controller } = setup();
    let captured: AppError | undefined;

    http.get('/api/v1/roles').subscribe({ error: (e: AppError) => (captured = e) });
    controller.expectOne('/api/v1/roles').flush(
      {
        code: 'RBAC_001',
        detail: 'You do not have permission to perform this action',
        traceId: 'trace-rbac-1',
        requiredPermission: 'role:read',
      },
      { status: 403, statusText: 'Forbidden' },
    );

    expect(captured?.code).toBe('RBAC_001');
    expect(captured?.requiredPermission).toBe('role:read');
  });

  it('should leave requiredPermission undefined for an ACCESS_DENIED problem response', () => {
    const { http, controller } = setup();
    let captured: AppError | undefined;

    http.get('/api/v1/roles').subscribe({ error: (e: AppError) => (captured = e) });
    controller
      .expectOne('/api/v1/roles')
      .flush(
        { code: 'ACCESS_DENIED', detail: 'You do not have access to this resource.' },
        { status: 403, statusText: 'Forbidden' },
      );

    expect(captured?.code).toBe('ACCESS_DENIED');
    expect(captured?.requiredPermission).toBeUndefined();
  });

  it('should ignore a non-string requiredPermission in a malformed problem response', () => {
    const { http, controller } = setup();
    let captured: AppError | undefined;

    http.get('/api/v1/roles').subscribe({ error: (e: AppError) => (captured = e) });
    controller
      .expectOne('/api/v1/roles')
      .flush(
        { code: 'RBAC_001', detail: 'Malformed.', requiredPermission: 12345 },
        { status: 403, statusText: 'Forbidden' },
      );

    expect(captured?.requiredPermission).toBeUndefined();
  });

  it('should map a 4xx response with no code field to the generic HTTP_ERROR fallback', () => {
    // Regression guard for the RBAC changes: isProblemDocument's `code`-only validation
    // gates both the pre-existing fallback path and the new requiredPermission narrowing,
    // so a body missing `code` entirely must still fall through to HTTP_ERROR rather than
    // throwing or accidentally satisfying isProblemDocument.
    const { http, controller } = setup();
    let captured: AppError | undefined;

    http.get('/api/legacy').subscribe({ error: (e: AppError) => (captured = e) });
    controller
      .expectOne('/api/legacy')
      .flush('Internal error', { status: 400, statusText: 'Bad Request' });

    expect(captured?.code).toBe('HTTP_ERROR');
    expect(captured?.requiredPermission).toBeUndefined();
  });

  it('should map a non-object error body to the generic HTTP_ERROR fallback', () => {
    const { http, controller } = setup();
    let captured: AppError | undefined;

    http.get('/api/legacy').subscribe({ error: (e: AppError) => (captured = e) });
    controller.expectOne('/api/legacy').flush(null, { status: 404, statusText: 'Not Found' });

    expect(captured?.code).toBe('HTTP_ERROR');
    expect(captured?.requiredPermission).toBeUndefined();
  });

  it('should log 429 at WARN level', () => {
    const { http, controller } = setup();

    http.get('/api/limited').subscribe({ error: () => undefined });
    controller
      .expectOne('/api/limited')
      .flush({ code: 'RATE_LIMIT' }, { status: 429, statusText: 'Too Many Requests' });

    expect(loggerSpy.warn).toHaveBeenCalledOnce();
  });

  it('should log 500 at ERROR level', () => {
    const { http, controller } = setup();

    http.get('/api/crash').subscribe({ error: () => undefined });
    controller
      .expectOne('/api/crash')
      .flush({ code: 'SERVER_ERROR' }, { status: 500, statusText: 'Internal Server Error' });

    expect(loggerSpy.error).toHaveBeenCalledOnce();
  });

  it('should map a connection failure (status 0) to NETWORK_ERROR and log as ERROR', () => {
    const { http, controller } = setup();
    let captured: AppError | undefined;

    http.get('/api/ping').subscribe({ error: (e: AppError) => (captured = e) });
    controller.expectOne('/api/ping').error(new ProgressEvent('error'), { status: 0 });

    expect(captured?.code).toBe('NETWORK_ERROR');
    expect(loggerSpy.error).toHaveBeenCalledOnce();
    expect(loggerSpy.error).toHaveBeenCalledWith(
      expect.stringContaining('General network or client-side transport failure.'),
      expect.any(Object),
    );
  });
  describe('403 RBAC_001 redirect (US-018 C6)', () => {
    function failWith(
      status: number,
      body: Record<string, unknown>,
      options: { context?: HttpContext } = {},
    ): { captured: AppError | undefined } {
      const { http, controller } = setup();
      const result: { captured: AppError | undefined } = { captured: undefined };
      http
        .get('/api/v1/roles', { context: options.context })
        .subscribe({ error: (e: AppError) => (result.captured = e) });
      controller.expectOne('/api/v1/roles').flush(body, { status, statusText: 'Error' });
      return result;
    }

    it('should navigate to /access-denied when a request fails with 403 RBAC_001', () => {
      failWith(403, { code: 'RBAC_001', detail: 'Missing permission.' });

      expect(routerSpy.navigate).toHaveBeenCalledOnce();
      expect(routerSpy.navigate).toHaveBeenCalledWith(['/access-denied']);
    });

    it('should navigate without query parameters or extras derived from the server response', () => {
      failWith(403, {
        code: 'RBAC_001',
        detail: 'Missing permission.',
        requiredPermission: 'role:write',
        returnUrl: 'https://evil.example',
      });

      const call = routerSpy.navigate.mock.calls[0];
      expect(call).toEqual([['/access-denied']]);
      expect(JSON.stringify(call)).not.toContain('role:write');
      expect(JSON.stringify(call)).not.toContain('evil.example');
    });

    it('should still propagate the AppError to the subscriber when it redirects', () => {
      const result = failWith(403, { code: 'RBAC_001', detail: 'Missing permission.' });

      expect(result.captured?.code).toBe('RBAC_001');
    });

    it('should not navigate for the filter-level ACCESS_DENIED 403', () => {
      const result = failWith(403, { code: 'ACCESS_DENIED', detail: 'No access.' });

      expect(routerSpy.navigate).not.toHaveBeenCalled();
      expect(result.captured?.code).toBe('ACCESS_DENIED');
    });

    it('should not navigate on a 401', () => {
      failWith(401, { code: 'AUTH_003', detail: 'Token rejected.' });

      expect(routerSpy.navigate).not.toHaveBeenCalled();
    });

    it('should not navigate on a 404', () => {
      failWith(404, { code: 'ROLE_NOT_FOUND', detail: 'No such role.' });

      expect(routerSpy.navigate).not.toHaveBeenCalled();
    });

    it('should not navigate on a RBAC_001 code carried by a non-403 status', () => {
      failWith(409, { code: 'RBAC_001', detail: 'Odd.' });

      expect(routerSpy.navigate).not.toHaveBeenCalled();
    });

    it('should not navigate when the request carries SKIP_ACCESS_DENIED_REDIRECT, yet still propagate', () => {
      const result = failWith(
        403,
        { code: 'RBAC_001', detail: 'Missing permission.' },
        { context: new HttpContext().set(SKIP_ACCESS_DENIED_REDIRECT, true) },
      );

      expect(routerSpy.navigate).not.toHaveBeenCalled();
      expect(result.captured?.code).toBe('RBAC_001');
    });

    it('should default the opt-out token to false', () => {
      expect(new HttpContext().get(SKIP_ACCESS_DENIED_REDIRECT)).toBe(false);
    });
  });

  describe('caller-facing reason and Retry-After (US-019 B7)', () => {
    function failWith(
      status: number,
      body: Record<string, unknown>,
      headers: Record<string, string> = {},
    ): { captured: AppError | undefined; controller: HttpTestingController } {
      const { http, controller } = setup();
      const result: { captured: AppError | undefined; controller: HttpTestingController } = {
        captured: undefined,
        controller,
      };
      http.post('/api/v1/users/u-1/roles', {}).subscribe({
        error: (e: AppError) => (result.captured = e),
      });
      controller
        .expectOne('/api/v1/users/u-1/roles')
        .flush(body, { status, statusText: 'Error', headers });
      return result;
    }

    it('should map reason from an RBAC_001 problem response onto AppError', () => {
      const { captured } = failWith(403, {
        code: 'RBAC_001',
        detail: 'You do not have permission to perform this action',
        requiredPermission: 'user:role:assign',
        reason: 'GRANT_EXCEEDS_CALLER',
      });

      expect(captured?.reason).toBe('GRANT_EXCEEDS_CALLER');
    });

    it('should ignore a non-string reason in a malformed RBAC_001 response', () => {
      const { captured } = failWith(403, { code: 'RBAC_001', reason: 7 });

      expect(captured?.reason).toBeUndefined();
    });

    it('should never carry a reason on a non-RBAC_001 response', () => {
      const { captured } = failWith(403, { code: 'ACCESS_DENIED', reason: 'UNSPECIFIED' });

      expect(captured?.reason).toBeUndefined();
    });

    it('should surface a 429 RBAC_011 as an AppError with retryAfterSeconds and no redirect', () => {
      const { captured } = failWith(
        429,
        { code: 'RBAC_011', detail: 'Too many denied role changes; try again later' },
        { 'Retry-After': '42' },
      );

      expect(captured).toEqual(
        expect.objectContaining({
          code: 'RBAC_011',
          message: 'Too many denied role changes; try again later',
          retryAfterSeconds: 42,
        }),
      );
      expect(captured?.reason).toBeUndefined();
      expect(routerSpy.navigate).not.toHaveBeenCalled();
    });

    it('should never auto-retry a 429 RBAC_011, even after its Retry-After has passed', () => {
      vi.useFakeTimers();
      const { controller } = failWith(429, { code: 'RBAC_011' }, { 'Retry-After': '1' });

      vi.advanceTimersByTime(120_000);

      controller.expectNone('/api/v1/users/u-1/roles');
      controller.verify();
    });

    it('should surface the recorded 409 RBAC_012 as a plain AppError, with no navigation', () => {
      const { captured } = failWith(409, recordedRbac012);

      expect(captured).toEqual(
        expect.objectContaining({ code: 'RBAC_012', message: recordedRbac012.detail }),
      );
      expect(captured?.reason).toBeUndefined();
      expect(captured?.retryAfterSeconds).toBeUndefined();
      expect(routerSpy.navigate).not.toHaveBeenCalled();
    });

    it('should never retry a 409 RBAC_012, even after time has passed', () => {
      vi.useFakeTimers();
      const { controller } = failWith(409, recordedRbac012);

      vi.advanceTimersByTime(120_000);

      controller.expectNone('/api/v1/users/u-1/roles');
      controller.verify();
    });

    it.each([
      ['99999999', 300],
      ['300', 300],
      ['299', 299],
      ['9'.repeat(400), 300],
    ])('should cap Retry-After %j at 300 seconds', async (value, expected) => {
      const { captured } = failWith(503, { code: 'AUTH_005' }, { 'Retry-After': value });
      // The 503 also raises the availability toast through a lazy import; let it settle inside
      // the test, or it resolves after TestBed teardown and rejects with NG0205.
      await vi.dynamicImportSettled();

      expect(captured?.retryAfterSeconds).toBe(expected);
    });

    it.each(['', 'soon', '-5', '0', '1.5', 'Wed, 21 Oct 2026 07:28:00 GMT'])(
      'should leave retryAfterSeconds undefined for Retry-After %j',
      (value) => {
        const { captured } = failWith(429, { code: 'RBAC_011' }, { 'Retry-After': value });

        expect(captured?.retryAfterSeconds).toBeUndefined();
      },
    );

    it('should map a 503 AUTH_005 Retry-After and show one availability toast, never navigating', async () => {
      const { captured } = failWith(503, { code: 'AUTH_005' }, { 'Retry-After': '30' });
      await vi.dynamicImportSettled();

      expect(captured?.retryAfterSeconds).toBe(30);
      expect(toastSpy.warning).toHaveBeenCalledOnce();
      expect(toastSpy.warning).toHaveBeenCalledWith(
        'Nexus is temporarily unavailable. Try again in 30 seconds.',
      );
      expect(routerSpy.navigate).not.toHaveBeenCalled();
    });

    it('should show one toast for two 503 AUTH_005 responses within the window', async () => {
      const { http, controller } = setup();
      for (const url of ['/api/a', '/api/b']) {
        http.get(url).subscribe({ error: () => undefined });
        controller.expectOne(url).flush(
          { code: 'AUTH_005' },
          {
            status: 503,
            statusText: 'Service Unavailable',
            headers: { 'Retry-After': '30' },
          },
        );
      }
      await vi.dynamicImportSettled();

      expect(toastSpy.warning).toHaveBeenCalledOnce();
      expect(routerSpy.navigate).not.toHaveBeenCalled();
    });

    it('should not show the availability toast for a 503 with another code', async () => {
      failWith(503, { code: 'SERVICE_UNAVAILABLE' }, { 'Retry-After': '30' });
      await vi.dynamicImportSettled();

      expect(toastSpy.warning).not.toHaveBeenCalled();
    });
  });
});
