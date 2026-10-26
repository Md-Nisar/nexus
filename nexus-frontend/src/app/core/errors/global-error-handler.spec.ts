import { HttpErrorResponse } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { GlobalErrorHandler } from './global-error-handler';
import { LoggerService } from '../logging/logger.service';
import { APP_CONFIG } from '../config/app-config';

describe('GlobalErrorHandler', () => {
  let loggerSpy: { error: ReturnType<typeof vi.fn> };

  function setup(production: boolean) {
    loggerSpy = {
      error: vi.fn(),
    };

    TestBed.configureTestingModule({
      providers: [
        GlobalErrorHandler,
        { provide: LoggerService, useValue: loggerSpy },
        {
          provide: APP_CONFIG,
          useValue: {
            production,
            apiBaseUrl: '/api',
            logLevel: 'debug',
            accessConsoleEnabled: false,
          },
        },
      ],
    });

    return TestBed.inject(GlobalErrorHandler);
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should log uncaught errors to LoggerService', () => {
    const errorHandler = setup(false);
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const err = new TypeError('Cannot read property of undefined');

    errorHandler.handleError(err);

    expect(loggerSpy.error).toHaveBeenCalledOnce();
    expect(loggerSpy.error).toHaveBeenCalledWith('Unhandled runtime exception', {
      event: 'unhandled_exception',
      outcome: 'FAILURE',
      errorType: 'TypeError',
      context: {
        stack: err.stack,
      },
    });
    expect(consoleSpy).toHaveBeenCalledWith(err);
  });

  it('should suppress raw console error in production', () => {
    const errorHandler = setup(true);
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const err = new Error('production fail');

    errorHandler.handleError(err);

    expect(loggerSpy.error).toHaveBeenCalledOnce();
    expect(consoleSpy).not.toHaveBeenCalled();
  });

  describe('AppError-shaped values (RC-73)', () => {
    const appError = {
      code: 'RBAC_001',
      message: 'synthetic-server-message',
      details: [{ field: 'email', message: 'synthetic-field-message' }],
      requiredPermission: 'SYNTHETIC_PERMISSION',
      correlationId: 'corr-1',
      traceId: 'trace-1',
    };

    it('logs only code, correlationId and traceId', () => {
      const errorHandler = setup(true);

      errorHandler.handleError(appError);

      expect(loggerSpy.error).toHaveBeenCalledOnce();
      const [message, params] = loggerSpy.error.mock.calls[0];
      expect(params.context).toEqual({
        code: 'RBAC_001',
        correlationId: 'corr-1',
        traceId: 'trace-1',
      });
      const logged = JSON.stringify([message, params]);
      for (const forbidden of [
        'synthetic-server-message',
        'synthetic-field-message',
        'SYNTHETIC_PERMISSION',
        'details',
        'requiredPermission',
      ]) {
        expect(logged).not.toContain(forbidden);
      }
    });

    it('does not print the raw AppError to the console in development', () => {
      const errorHandler = setup(false);
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);

      errorHandler.handleError(appError);

      expect(consoleSpy).not.toHaveBeenCalled();
    });

    it('keeps correlationId and traceId keys when absent', () => {
      const errorHandler = setup(true);

      errorHandler.handleError({ code: 'NETWORK', message: 'synthetic' });

      const [, params] = loggerSpy.error.mock.calls[0];
      expect(Object.keys(params.context)).toEqual(['code', 'correlationId', 'traceId']);
    });

    it('logs an object without a string code by type only, never its content', () => {
      const errorHandler = setup(true);

      errorHandler.handleError({ code: 42, other: 'synthetic-object-content' });

      const [message, params] = loggerSpy.error.mock.calls[0];
      expect(message).toBe('Unhandled runtime exception');
      expect(params.errorType).toBe('Object');
      expect(JSON.stringify([message, params])).not.toContain('synthetic-object-content');
    });

    it('keeps an Error that carries a code on the runtime path, without its message', () => {
      const errorHandler = setup(true);
      const err = Object.assign(new Error('synthetic-error-message'), { code: 'E_SYNTHETIC' });

      errorHandler.handleError(err);

      const [message, params] = loggerSpy.error.mock.calls[0];
      expect(message).toBe('Unhandled runtime exception');
      expect(params.errorType).toBe('Error');
      expect(JSON.stringify([message, params.errorType])).not.toContain('synthetic-error-message');
    });
  });

  describe('runtime errors never put their message into the log text (MN-7, Low 4)', () => {
    it('logs a fixed message for an Error whose message embeds data', () => {
      const errorHandler = setup(true);

      errorHandler.handleError(new TypeError('failed for /api/v1/users?term=synthetic-term'));

      const [message, params] = loggerSpy.error.mock.calls[0];
      expect(message).toBe('Unhandled runtime exception');
      expect(params.errorType).toBe('TypeError');
    });

    it('logs a thrown string by type only', () => {
      const errorHandler = setup(true);

      errorHandler.handleError('synthetic-thrown-string');

      const [message, params] = loggerSpy.error.mock.calls[0];
      expect(message).toBe('Unhandled runtime exception');
      expect(params.errorType).toBe('string');
      expect(JSON.stringify([message, params])).not.toContain('synthetic-thrown-string');
    });

    it('logs an escaped HttpErrorResponse as status and URL path, without query or body', () => {
      const errorHandler = setup(true);

      errorHandler.handleError(
        new HttpErrorResponse({
          status: 500,
          url: '/api/v1/users?term=synthetic-term',
          error: { detail: 'synthetic-server-body' },
        }),
      );

      const [message, params] = loggerSpy.error.mock.calls[0];
      expect(message).toBe('Unhandled HTTP error response');
      expect(params.errorType).toBe('HttpErrorResponse');
      expect(params.context).toEqual({ status: 500, path: '/api/v1/users' });
      const logged = JSON.stringify([message, params]);
      expect(logged).not.toContain('synthetic-term');
      expect(logged).not.toContain('synthetic-server-body');
    });

    it('keeps the path of an absolute HttpErrorResponse URL and drops its fragment', () => {
      const errorHandler = setup(true);

      errorHandler.handleError(
        new HttpErrorResponse({ status: 0, url: 'https://nexus.invalid/api/v1/roles#frag' }),
      );

      expect(loggerSpy.error.mock.calls[0][1].context).toEqual({
        status: 0,
        path: '/api/v1/roles',
      });
    });
  });
});
