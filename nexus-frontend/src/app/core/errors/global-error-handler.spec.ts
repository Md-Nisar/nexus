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
        { provide: APP_CONFIG, useValue: { production, apiBaseUrl: '/api', logLevel: 'debug' } },
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
});
