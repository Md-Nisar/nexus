import { Service, inject } from '@angular/core';
import { APP_CONFIG, LogLevel } from '../config/app-config';

/**
 * Maps log level names to numeric values for comparison.
 * Used to determine if a message at a given level should be logged.
 *
 * @example
 * LEVEL_ORDER['debug'] = 0   // lowest priority, logged first
 * LEVEL_ORDER['error'] = 3   // highest priority, logged last
 */
const LEVEL_ORDER: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

/**
 * Level-aware logger — the only sanctioned way to log in this codebase (bare console.log
 * is an ESLint error). The minimum level comes from APP_CONFIG, so production builds stay
 * quiet while development builds are verbose.
 *
 * @example
 * constructor(private logger: LoggerService) {}
 *
 * doSomething() {
 *   this.logger.debug('Starting operation');
 *   this.logger.info('Operation complete');
 *   if (error) this.logger.error('Operation failed', error);
 * }
 *
 * @note
 * - In production, minLevel is typically 'warn', so only warn and error messages appear.
 * - In development, minLevel is typically 'debug', so all messages appear.
 * - Each log method prepends a [level] prefix to the message for easy console filtering.
 */
@Service()
export class LoggerService {
  /**
   * The minimum log level threshold. Messages below this level are suppressed.
   * Derived from APP_CONFIG.logLevel at construction time.
   */
  private readonly minLevel = LEVEL_ORDER[inject(APP_CONFIG).logLevel];

  /**
   * Logs a debug message (lowest priority).
   *
   * @param message - The message to log
   * @param context - Optional additional context data to include
   *
   * @example
   * this.logger.debug('User clicked button', { userId: 123 });
   */
  debug(message: string, ...context: unknown[]): void {
    if (this.enabled('debug')) {
      // eslint-disable-next-line no-console
      console.debug(`[debug] ${message}`, ...context);
    }
  }

  /**
   * Logs an informational message.
   *
   * @param message - The message to log
   * @param context - Optional additional context data to include
   *
   * @example
   * this.logger.info('Login successful', { username: 'john@example.com' });
   */
  info(message: string, ...context: unknown[]): void {
    if (this.enabled('info')) {
      // eslint-disable-next-line no-console
      console.info(`[info] ${message}`, ...context);
    }
  }

  /**
   * Logs a warning message.
   *
   * @param message - The message to log
   * @param context - Optional additional context data to include
   *
   * @example
   * this.logger.warn('Deprecated API used', { method: 'oldMethod' });
   */
  warn(message: string, ...context: unknown[]): void {
    if (this.enabled('warn')) {
      console.warn(`[warn] ${message}`, ...context);
    }
  }

  /**
   * Logs an error message (highest priority).
   *
   * @param message - The message to log
   * @param context - Optional additional context data to include (e.g., Error objects, stack traces)
   *
   * @example
   * this.logger.error('Request failed', { error: err, statusCode: 500 });
   */
  error(message: string, ...context: unknown[]): void {
    if (this.enabled('error')) {
      console.error(`[error] ${message}`, ...context);
    }
  }

  /**
   * Determines if a message at the given level should be logged.
   *
   * Complex logic note:
   * - Compares numeric level values: only logs if the message level >= minLevel.
   * - This allows selective suppression: if minLevel is 'warn' (2), only 'warn' (2) and 'error' (3) pass through.
   *
   * @param level - The log level to check
   * @returns true if the level meets or exceeds the minimum threshold
   */
  private enabled(level: LogLevel): boolean {
    return LEVEL_ORDER[level] >= this.minLevel;
  }
}
