import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { AppError, isAppError } from '../../shared/types/app-error';
import { LoggerService } from '../logging/logger.service';
import { CORRELATION_HEADER } from './correlation-id.interceptor';
import { ServiceAvailabilityNotifier } from './service-availability-notifier';
import { SKIP_ACCESS_DENIED_REDIRECT } from './skip-access-denied-redirect';

/**
 * HTTP interceptor that normalizes every HTTP failure into a standardized AppError.
 *
 * A 403 with code `RBAC_001` (the caller lacks a permission the backend checked) also sends the
 * user to `/access-denied`, unless the request opted out with `SKIP_ACCESS_DENIED_REDIRECT`
 * (US-018 C6). The navigation carries no query parameters: nothing derived from the server
 * response may reach the URL, which keeps this out of the open-redirect class. The `AppError` is
 * still rethrown, so components that handle 403 inline keep working. The filter-level
 * `ACCESS_DENIED`, 401 and 404 never redirect.
 *
 * US-019 B7: `RBAC_001` carries a caller-facing `reason`, and a delta-seconds `Retry-After`
 * becomes `retryAfterSeconds`. A 429 (including `RBAC_011`) is surfaced once and never retried
 * here. A 503 `AUTH_005` additionally shows one availability toast per `Retry-After` window
 * through {@link ServiceAvailabilityNotifier}; it never navigates.
 */
export const apiErrorInterceptor: HttpInterceptorFn = (req, next) => {
  const logger = inject(LoggerService);
  const router = inject(Router);
  const availabilityNotifier = inject(ServiceAvailabilityNotifier);

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

      if (
        status === 403 &&
        appError.code === 'RBAC_001' &&
        !req.context.get(SKIP_ACCESS_DENIED_REDIRECT)
      ) {
        void router.navigate(['/access-denied']);
      }

      if (status === 503 && appError.code === 'AUTH_005') {
        availabilityNotifier.notifyUnavailable(appError.retryAfterSeconds);
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
        // RC-63(l): only RBAC_001 carries a reason; anything else is ignored.
        reason:
          body.code === 'RBAC_001' && typeof body.reason === 'string' ? body.reason : undefined,
        retryAfterSeconds: parseRetryAfterSeconds(error.headers?.get('Retry-After')),
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
  /** Set only by the backend's RBAC_001 403 branch (US-019 B7). */
  readonly reason?: unknown;
}

/**
 * Reads a delta-seconds `Retry-After` value. Anything else (absent, an HTTP date, a fraction,
 * zero or a negative number) yields `undefined`.
 */
function parseRetryAfterSeconds(raw: string | null | undefined): number | undefined {
  const value = raw?.trim() ?? '';
  if (!/^\d+$/.test(value)) {
    return undefined;
  }
  const seconds = Number(value);
  return seconds > 0 ? seconds : undefined;
}

/**
 * Type guard that validates whether an object conforms to the RFC 7807 ProblemDocument shape.
 */
function isProblemDocument(body: unknown): body is ProblemDocument {
  return (
    typeof body === 'object' && body !== null && typeof (body as ProblemDocument).code === 'string'
  );
}
