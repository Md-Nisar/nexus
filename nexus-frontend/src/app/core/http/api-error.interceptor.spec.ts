import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { describe, it, expect } from 'vitest';
import { apiErrorInterceptor } from './api-error.interceptor';
import { AppError, isAppError } from '../../shared/types/app-error';

describe('apiErrorInterceptor', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([apiErrorInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    return {
      http: TestBed.inject(HttpClient),
      controller: TestBed.inject(HttpTestingController),
    };
  }

  it('should map an RFC 7807 problem response to AppError', () => {
    const { http, controller } = setup();
    let captured: AppError | undefined;

    http.get('/api/users/42').subscribe({ error: (e: AppError) => (captured = e) });
    controller
      .expectOne('/api/users/42')
      .flush(
        { code: 'USER_NOT_FOUND', detail: 'No such user.', traceId: 'abc-123' },
        { status: 404, statusText: 'Not Found' },
      );

    expect(captured).toEqual({
      code: 'USER_NOT_FOUND',
      message: 'No such user.',
      traceId: 'abc-123',
      details: undefined,
    });
  });

  it('should map a connection failure to NETWORK_ERROR', () => {
    const { http, controller } = setup();
    let captured: AppError | undefined;

    http.get('/api/ping').subscribe({ error: (e: AppError) => (captured = e) });
    controller.expectOne('/api/ping').error(new ProgressEvent('error'), { status: 0 });

    expect(captured?.code).toBe('NETWORK_ERROR');
  });

  it('should map a non-problem error body to HTTP_ERROR with the status', () => {
    const { http, controller } = setup();
    let captured: AppError | undefined;

    http.get('/api/legacy').subscribe({ error: (e: AppError) => (captured = e) });
    controller
      .expectOne('/api/legacy')
      .flush('<html>Bad Gateway</html>', { status: 502, statusText: 'Bad Gateway' });

    expect(captured?.code).toBe('HTTP_ERROR');
    expect(captured?.message).toContain('502');
    expect(captured && isAppError(captured)).toBe(true);
  });
});
