import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { catchError, throwError } from 'rxjs';
import { AppError, isAppError } from '../../shared/types/app-error';

/**
 * Normalizes every HTTP failure into an AppError before it reaches application code.
 * Backend errors arrive as RFC 7807 problem documents carrying `code`, `detail` and
 * `traceId`; network-level failures get a synthetic NETWORK_ERROR.
 */
export const apiErrorInterceptor: HttpInterceptorFn = (req, next) =>
  next(req).pipe(catchError((error: unknown) => throwError(() => toAppError(error))));

function toAppError(error: unknown): AppError {
  if (error instanceof HttpErrorResponse) {
    const body: unknown = error.error;
    if (isProblemDocument(body)) {
      return {
        code: body.code,
        message: body.detail ?? 'Request failed.',
        traceId: body.traceId,
        details: body.details,
      };
    }
    if (error.status === 0) {
      return { code: 'NETWORK_ERROR', message: 'Could not reach the server.' };
    }
    return { code: 'HTTP_ERROR', message: `Request failed with status ${error.status}.` };
  }
  if (isAppError(error)) {
    return error;
  }
  return { code: 'UNEXPECTED_ERROR', message: 'An unexpected error occurred.' };
}

interface ProblemDocument {
  readonly code: string;
  readonly detail?: string;
  readonly traceId?: string;
  readonly details?: AppError['details'];
}

function isProblemDocument(body: unknown): body is ProblemDocument {
  return (
    typeof body === 'object' && body !== null && typeof (body as ProblemDocument).code === 'string'
  );
}
