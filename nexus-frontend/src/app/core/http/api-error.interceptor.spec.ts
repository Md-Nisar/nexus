import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { apiErrorInterceptor } from './api-error.interceptor';
import { LoggerService } from '../logging/logger.service';
import { APP_CONFIG } from '../config/app-config';
import { correlationIdInterceptor } from './correlation-id.interceptor';
import { AppError } from '../../shared/types/app-error';

describe('apiErrorInterceptor', () => {
  let loggerSpy: {
    debug: ReturnType<typeof vi.fn>;
    info: ReturnType<typeof vi.fn>;
    warn: ReturnType<typeof vi.fn>;
    error: ReturnType<typeof vi.fn>;
  };

  function setup() {
    loggerSpy = {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    };

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([correlationIdInterceptor, apiErrorInterceptor])),
        provideHttpClientTesting(),
        { provide: LoggerService, useValue: loggerSpy },
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
});
