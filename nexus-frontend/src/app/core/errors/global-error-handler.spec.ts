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
    expect(loggerSpy.error).toHaveBeenCalledWith(
      'Unhandled runtime exception: Cannot read property of undefined',
      {
        event: 'unhandled_exception',
        outcome: 'FAILURE',
        errorType: 'TypeError',
        context: {
          stack: err.stack,
        },
      },
    );
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

    it('keeps the existing path for an object without a string code', () => {
      const errorHandler = setup(true);

      errorHandler.handleError({ code: 42, other: 'x' });

      expect(loggerSpy.error.mock.calls[0][0]).toBe(
        'Unhandled runtime exception: {"code":42,"other":"x"}',
      );
    });

    it('keeps the existing path for an Error that carries a code', () => {
      const errorHandler = setup(true);
      const err = Object.assign(new Error('boom'), { code: 'E_SYNTHETIC' });

      errorHandler.handleError(err);

      expect(loggerSpy.error.mock.calls[0][0]).toBe('Unhandled runtime exception: boom');
    });
  });
});
