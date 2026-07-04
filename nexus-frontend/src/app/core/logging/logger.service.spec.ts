import { TestBed } from '@angular/core/testing';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { LoggerService } from './logger.service';
import { APP_CONFIG, AppConfig } from '../config/app-config';

describe('LoggerService', () => {
  function setup(logLevel: AppConfig['logLevel'], production = false) {
    TestBed.configureTestingModule({
      providers: [{ provide: APP_CONFIG, useValue: { production, apiBaseUrl: '/api', logLevel } }],
    });
    return TestBed.inject(LoggerService);
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should emit debug output when level is debug', () => {
    const logger = setup('debug');
    const spy = vi.spyOn(console, 'debug').mockImplementation(() => undefined);

    logger.debug('verbose detail', { event: 'test_event' });

    expect(spy).toHaveBeenCalledOnce();
    expect(spy).toHaveBeenCalledWith('[DEBUG] verbose detail', {
      event: 'test_event',
      operation: undefined,
      correlationId: undefined,
      outcome: undefined,
      errorCode: undefined,
      errorType: undefined,
      context: undefined,
    });
  });

  it('should suppress debug and info when level is warn', () => {
    const logger = setup('warn');
    const debugSpy = vi.spyOn(console, 'debug').mockImplementation(() => undefined);
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => undefined);

    logger.debug('hidden');
    logger.info('hidden');

    expect(debugSpy).not.toHaveBeenCalled();
    expect(infoSpy).not.toHaveBeenCalled();
  });

  it('should always emit errors', () => {
    const logger = setup('error');
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    logger.error('boom', { errorCode: 'FAIL_CODE' });

    expect(spy).toHaveBeenCalledOnce();
  });

  it('should scrub sensitive data recursively in dev mode', () => {
    const logger = setup('debug', false);
    const spy = vi.spyOn(console, 'debug').mockImplementation(() => undefined);

    logger.debug('sensitive log', {
      context: {
        password: 'my-secret-password',
        nested: {
          token: 'token-123',
          safeKey: 'safe-value',
        },
      },
    });

    expect(spy).toHaveBeenCalledOnce();
    const loggedParams = spy.mock.calls[0][1] as {
      context: { password?: string; nested?: { token?: string; safeKey?: string } };
    };
    expect(loggedParams.context?.password).toBe('[REDACTED]');
    expect(loggedParams.context?.nested?.token).toBe('[REDACTED]');
    expect(loggedParams.context?.nested?.safeKey).toBe('safe-value');
  });

  it('should strip stack traces from context in production mode', () => {
    const logger = setup('warn', true);
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    logger.warn('error log', {
      context: {
        stack: 'Error: boom\n  at Object.run...',
        safeKey: 'safe-value',
      },
    });

    expect(spy).toHaveBeenCalledOnce();
    const loggedParams = spy.mock.calls[0][1] as { context: { stack?: string; safeKey?: string } };
    expect(loggedParams.context?.stack).toBeUndefined();
    expect(loggedParams.context?.safeKey).toBe('safe-value');
  });
});
