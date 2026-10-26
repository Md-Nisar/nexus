import { HttpErrorResponse } from '@angular/common/http';
import { ErrorHandler, inject, Service } from '@angular/core';
import { LoggerService } from '../logging/logger.service';
import { APP_CONFIG } from '../config/app-config';

/**
 * Global ErrorHandler that intercepts uncaught runtime exceptions across the application.
 * Normalizes error context and logs the failure to the centralized LoggerService.
 *
 * @security The log text is a fixed message: an error's message, a thrown value's content, a
 * response body or a query string can carry user data, and the logger's redaction only sees
 * context keys, never the message (RC-73, T-I27). The stack stays in context, which the logger
 * drops in production.
 */
@Service()
export class GlobalErrorHandler implements ErrorHandler {
  private readonly logger = inject(LoggerService);
  private readonly config = inject(APP_CONFIG);

  /**
   * Processes the uncaught error.
   *
   * @param error - The unhandled error object/exception.
   */
  handleError(error: unknown): void {
    // An AppError carries server text (message, details, requiredPermission) that must never reach
    // the log or the console (RC-73): log its code and correlation ids only.
    if (this.isAppErrorShaped(error)) {
      this.logger.error('Unhandled application error', {
        event: 'unhandled_exception',
        outcome: 'FAILURE',
        errorType: 'AppError',
        context: {
          code: error.code,
          correlationId: error.correlationId,
          traceId: error.traceId,
        },
      });
      return;
    }

    // In development mode, print the raw error to console for standard developer debugging.
    if (!this.config.production) {
      // eslint-disable-next-line no-console
      console.error(error);
    }

    // An HTTP failure that escaped its subscription: status and path only, never the query
    // string or the server's body.
    if (error instanceof HttpErrorResponse) {
      this.logger.error('Unhandled HTTP error response', {
        event: 'unhandled_exception',
        outcome: 'FAILURE',
        errorType: 'HttpErrorResponse',
        context: { status: error.status, path: this.pathOf(error.url) },
      });
      return;
    }

    this.logger.error('Unhandled runtime exception', {
      event: 'unhandled_exception',
      outcome: 'FAILURE',
      errorType: this.getErrorType(error),
      context: {
        stack: this.getErrorStack(error) || undefined,
      },
    });
  }

  /** The path of a request URL, without its origin, query or fragment; `null` when unparsable. */
  private pathOf(url: string | null): string | null {
    if (url === null) return null;
    try {
      return new URL(url, 'http://path.invalid').pathname;
    } catch {
      return null;
    }
  }

  /**
   * An object (not an Error instance) with a string `code`: the shape of the normalized AppError.
   */
  private isAppErrorShaped(
    error: unknown,
  ): error is { code: string; correlationId?: unknown; traceId?: unknown } {
    return (
      typeof error === 'object' &&
      error !== null &&
      !(error instanceof Error) &&
      typeof (error as { code?: unknown }).code === 'string'
    );
  }

  /**
   * Identifies the specific error class name or type.
   */
  private getErrorType(error: unknown): string {
    if (error instanceof Error) {
      return error.name || error.constructor.name;
    }
    if (typeof error === 'object' && error !== null) {
      return error.constructor.name || 'Object';
    }
    return typeof error;
  }

  /**
   * Captures the stack trace of the exception if available.
   */
  private getErrorStack(error: unknown): string | undefined {
    if (error instanceof Error) {
      return error.stack;
    }
    return undefined;
  }
}
