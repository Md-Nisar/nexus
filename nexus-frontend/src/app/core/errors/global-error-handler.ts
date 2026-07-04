import { ErrorHandler, inject, Service } from '@angular/core';
import { LoggerService } from '../logging/logger.service';
import { APP_CONFIG } from '../config/app-config';

/**
 * Global ErrorHandler that intercepts uncaught runtime exceptions across the application.
 * Normalizes error context and logs the failure to the centralized LoggerService.
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
    const errorType = this.getErrorType(error);
    const message = this.getErrorMessage(error);
    const stack = this.getErrorStack(error);

    // In development mode, print the raw error to console for standard developer debugging.
    if (!this.config.production) {
      // eslint-disable-next-line no-console
      console.error(error);
    }

    // Log the error through the structured logging service
    this.logger.error(`Unhandled runtime exception: ${message}`, {
      event: 'unhandled_exception',
      outcome: 'FAILURE',
      errorType,
      context: {
        stack: stack || undefined,
      },
    });
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
   * Extracts a safe descriptive message from the error.
   */
  private getErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }
    if (typeof error === 'string') {
      return error;
    }
    try {
      return JSON.stringify(error);
    } catch {
      return String(error);
    }
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
