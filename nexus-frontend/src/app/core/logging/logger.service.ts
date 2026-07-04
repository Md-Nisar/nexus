import { Service, inject } from '@angular/core';
import { APP_CONFIG, LogLevel } from '../config/app-config';

/**
 * Structured parameters for logging metadata.
 */
export interface LogParams {
  event?: string;
  operation?: string;
  correlationId?: string;
  outcome?: 'SUCCESS' | 'FAILURE';
  errorCode?: string;
  errorType?: string;
  context?: Record<string, unknown>;
}

/**
 * Maps log level names to numeric values for comparison.
 */
const LEVEL_ORDER: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

/**
 * Regular expression to identify sensitive keys that should be redacted.
 */
const SENSITIVE_KEYS = /password|token|secret|authorization|cookie|apiKey|session/i;

/**
 * Checks if a value is a plain object to avoid recursing on DOM elements or class instances.
 */
function isPlainObject(val: unknown): val is Record<string, unknown> {
  return Object.prototype.toString.call(val) === '[object Object]';
}

/**
 * Deep-scrubs sensitive keys (e.g. passwords, tokens) from log parameters.
 */
function scrubSensitiveData(val: unknown): unknown {
  if (val === null || val === undefined) {
    return val;
  }
  if (Array.isArray(val)) {
    return val.map(scrubSensitiveData);
  }
  if (isPlainObject(val)) {
    const scrubbed: Record<string, unknown> = {};
    for (const key of Object.keys(val)) {
      if (SENSITIVE_KEYS.test(key)) {
        scrubbed[key] = '[REDACTED]';
      } else {
        scrubbed[key] = scrubSensitiveData(val[key]);
      }
    }
    return scrubbed;
  }
  return val;
}

/**
 * Level-aware structured logger.
 * Handles environment-based log filtering and sensitive data scrubbing.
 */
@Service()
export class LoggerService {
  private readonly config = inject(APP_CONFIG);
  private readonly minLevel = LEVEL_ORDER[this.config.logLevel];
  private readonly isProduction = this.config.production;

  /**
   * Logs a debug message.
   */
  debug(message: string, params?: LogParams): void {
    if (this.enabled('debug')) {
      const sanitized = params ? this.sanitizeParams(params) : undefined;
      console.debug(`[DEBUG] ${message}`, sanitized || '');
    }
  }

  /**
   * Logs an informational message.
   */
  info(message: string, params?: LogParams): void {
    if (this.enabled('info')) {
      const sanitized = params ? this.sanitizeParams(params) : undefined;
      console.info(`[INFO] ${message}`, sanitized || '');
    }
  }

  /**
   * Logs a warning message.
   */
  warn(message: string, params?: LogParams): void {
    if (this.enabled('warn')) {
      const sanitized = params ? this.sanitizeParams(params) : undefined;
      console.warn(`[WARN] ${message}`, sanitized || '');
    }
  }

  /**
   * Logs an error message.
   */
  error(message: string, params?: LogParams): void {
    if (this.enabled('error')) {
      const sanitized = params ? this.sanitizeParams(params) : undefined;
      console.error(`[ERROR] ${message}`, sanitized || '');
    }
  }

  /**
   * Sanitizes logging parameters by scrubbing sensitive values and removing stack traces in production.
   */
  private sanitizeParams(params: LogParams): LogParams {
    const cleanContext = params.context
      ? (scrubSensitiveData(params.context) as Record<string, unknown>)
      : undefined;

    // Secondary defensive safeguard: remove stack traces from the log context in production
    if (cleanContext && this.isProduction && 'stack' in cleanContext) {
      delete cleanContext['stack'];
    }

    return {
      event: params.event,
      operation: params.operation,
      correlationId: params.correlationId,
      outcome: params.outcome,
      errorCode: params.errorCode,
      errorType: params.errorType,
      context: cleanContext,
    };
  }

  /**
   * Determines if a message at the given level should be logged.
   */
  private enabled(level: LogLevel): boolean {
    return LEVEL_ORDER[level] >= this.minLevel;
  }
}
