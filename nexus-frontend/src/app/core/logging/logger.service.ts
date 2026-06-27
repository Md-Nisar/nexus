import { Service, inject } from '@angular/core';
import { APP_CONFIG, LogLevel } from '../config/app-config';

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

/**
 * Level-aware logger — the only sanctioned way to log in this codebase (bare console.log
 * is an ESLint error). The minimum level comes from APP_CONFIG, so production builds stay
 * quiet while development builds are verbose.
 */
@Service()
export class LoggerService {
  private readonly minLevel = LEVEL_ORDER[inject(APP_CONFIG).logLevel];

  debug(message: string, ...context: unknown[]): void {
    if (this.enabled('debug')) {
      // eslint-disable-next-line no-console
      console.debug(`[debug] ${message}`, ...context);
    }
  }

  info(message: string, ...context: unknown[]): void {
    if (this.enabled('info')) {
      // eslint-disable-next-line no-console
      console.info(`[info] ${message}`, ...context);
    }
  }

  warn(message: string, ...context: unknown[]): void {
    if (this.enabled('warn')) {
      console.warn(`[warn] ${message}`, ...context);
    }
  }

  error(message: string, ...context: unknown[]): void {
    if (this.enabled('error')) {
      console.error(`[error] ${message}`, ...context);
    }
  }

  private enabled(level: LogLevel): boolean {
    return LEVEL_ORDER[level] >= this.minLevel;
  }
}
