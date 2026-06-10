import { TestBed } from '@angular/core/testing';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { LoggerService } from './logger.service';
import { APP_CONFIG, AppConfig } from '../config/app-config';

describe('LoggerService', () => {
  function setup(logLevel: AppConfig['logLevel']) {
    TestBed.configureTestingModule({
      providers: [
        { provide: APP_CONFIG, useValue: { production: false, apiBaseUrl: '/api', logLevel } },
      ],
    });
    return TestBed.inject(LoggerService);
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should emit debug output when level is debug', () => {
    const logger = setup('debug');
    const spy = vi.spyOn(console, 'debug').mockImplementation(() => undefined);

    logger.debug('verbose detail');

    expect(spy).toHaveBeenCalledOnce();
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

    logger.error('boom', { cause: 'test' });

    expect(spy).toHaveBeenCalledOnce();
  });
});
