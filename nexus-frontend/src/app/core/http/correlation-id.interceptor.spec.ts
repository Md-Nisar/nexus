import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { describe, it, expect, afterEach } from 'vitest';
import { CORRELATION_HEADER, correlationIdInterceptor } from './correlation-id.interceptor';

describe('correlationIdInterceptor', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([correlationIdInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    return {
      http: TestBed.inject(HttpClient),
      controller: TestBed.inject(HttpTestingController),
    };
  }

  afterEach(() => {
    TestBed.inject(HttpTestingController).verify();
  });

  it('should attach a correlation id header to every request', () => {
    const { http, controller } = setup();

    http.get('/api/ping').subscribe();

    const request = controller.expectOne('/api/ping');
    expect(request.request.headers.get(CORRELATION_HEADER)).toBeTruthy();
    request.flush({});
  });

  it('should generate a fresh id per request', () => {
    const { http, controller } = setup();

    http.get('/api/one').subscribe();
    http.get('/api/two').subscribe();

    const first = controller.expectOne('/api/one').request.headers.get(CORRELATION_HEADER);
    const second = controller.expectOne('/api/two').request.headers.get(CORRELATION_HEADER);
    expect(first).not.toEqual(second);
    controller.expectNone('/api/one');
  });
});
