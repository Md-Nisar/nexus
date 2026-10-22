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

describe('apiErrorInterceptor', () => {
  let loggerSpy: {
    debug: ReturnType<typeof vi.fn>;
    info: ReturnType<typeof vi.fn>;
    warn: ReturnType<typeof vi.fn>;
    error: ReturnType<typeof vi.fn>;
  };
  let routerSpy: { navigate: ReturnType<typeof vi.fn> };

  function setup() {
    loggerSpy = {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    };

    routerSpy = { navigate: vi.fn().mockResolvedValue(true) };

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([correlationIdInterceptor, apiErrorInterceptor])),
        provideHttpClientTesting(),
        { provide: LoggerService, useValue: loggerSpy },
        { provide: Router, useValue: routerSpy },
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
});
