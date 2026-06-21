import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AuthService } from './auth.service';
import { APP_CONFIG } from '../../core/config/app-config';
import { apiErrorInterceptor } from '../../core/http/api-error.interceptor';
import { AppError } from '../../shared/types/app-error';

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
