import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, throwError } from 'rxjs';
import { AppError, isAppError } from '../../shared/types/app-error';
import { LoggerService } from '../logging/logger.service';
import { CORRELATION_HEADER } from './correlation-id.interceptor';

/**
 * HTTP interceptor that normalizes every HTTP failure into a standardized AppError.
 */
export const apiErrorInterceptor: HttpInterceptorFn = (req, next) => {
  const logger = inject(LoggerService);

  return next(req).pipe(
    catchError((error: unknown) => {
      const correlationId = req.headers.get(CORRELATION_HEADER) || undefined;
      const appError = toAppError(error, correlationId);

      let status = -1;
      if (error instanceof HttpErrorResponse) {
        status = error.status;
      }

      const logParams = {
        event: 'http_request_failed',
        operation: `${req.method} ${req.url}`,
        correlationId,
        outcome: 'FAILURE' as const,
        errorCode: appError.code,
        errorType: error instanceof HttpErrorResponse ? 'HttpErrorResponse' : 'Error',
        context: {
          status: status !== -1 ? status : undefined,
          errorMessage: error instanceof HttpErrorResponse ? error.message : undefined,
          url: req.url,
        },
      };

      const logMsg = `HTTP request failed: ${req.method} ${req.url} - Status ${status}`;

      if (status >= 500) {
        logger.error(logMsg, logParams);
      } else if (status === 0) {
        // Angular status 0 represents general network/client-side transport failure
        logger.error(
          `HTTP request failed: ${req.method} ${req.url} - General network or client-side transport failure.`,
          logParams,
        );
      } else if (status === 429) {
        logger.warn(logMsg, logParams);
      } else {
        // 400, 401, 403, 404, 409 etc. represent expected application behaviors (low noise)
        logger.debug(logMsg, logParams);
      }

      return throwError(() => appError);
    }),
  );
};

/**
 * Converts an HTTP error (or other error type) into a standardized AppError.
 */
function toAppError(error: unknown, correlationId?: string): AppError {
  if (error instanceof HttpErrorResponse) {
    const body: unknown = error.error;
    if (isProblemDocument(body)) {
      return {
        code: body.code,
        message: body.detail ?? 'Request failed.',
        traceId: body.traceId,
        correlationId,
        details: body.details,
        // `isProblemDocument` validates only `code`, so this field is otherwise
        // unvalidated — guard against a malformed/non-string value rather than passing
        // it through unchecked.
        requiredPermission:
          typeof body.requiredPermission === 'string' ? body.requiredPermission : undefined,
      };
    }
    if (error.status === 0) {
      return { code: 'NETWORK_ERROR', message: 'Could not reach the server.', correlationId };
    }
    return {
      code: 'HTTP_ERROR',
      message: `Request failed with status ${error.status}.`,
      correlationId,
    };
  }
  if (isAppError(error)) {
    return correlationId ? { ...error, correlationId } : error;
  }
  return { code: 'UNEXPECTED_ERROR', message: 'An unexpected error occurred.', correlationId };
}

/**
 * RFC 7807 Problem Details for HTTP APIs (https://tools.ietf.org/html/rfc7807).
 */
interface ProblemDocument {
  readonly code: string;
  readonly detail?: string;
  readonly traceId?: string;
  readonly details: AppError['details'];
  /** Set only by the backend's RBAC_001 403 branch; absent on ACCESS_DENIED. */
  readonly requiredPermission?: string;
}

/**
 * Type guard that validates whether an object conforms to the RFC 7807 ProblemDocument shape.
 */
function isProblemDocument(body: unknown): body is ProblemDocument {
  return (
    typeof body === 'object' && body !== null && typeof (body as ProblemDocument).code === 'string'
  );
}
