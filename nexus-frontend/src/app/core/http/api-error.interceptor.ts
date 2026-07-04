import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { catchError, throwError } from 'rxjs';
import { AppError, isAppError } from '../../shared/types/app-error';

/**
 * HTTP interceptor that normalizes every HTTP failure into a standardized AppError.
 *
 * Responsibilities:
 * - **RFC 7807 parsing**: Converts backend RFC 7807 problem documents into AppError objects,
 *   extracting `code`, `detail` (message), `traceId`, and nested `details` (validation errors).
 * - **Network error synthesis**: Creates synthetic NETWORK_ERROR entries for network failures
 *   (status === 0), allowing uniform error handling across all error types.
 * - **Fallback handling**: Maps HTTP errors without a valid problem document to generic
 *   HTTP_ERROR or UNEXPECTED_ERROR entries.
 *
 * All errors reaching application code are guaranteed to be AppError instances, enabling
 * components and services to avoid HttpErrorResponse checks and use consistent error
 * handling logic.
 *
 * @security Preserves backend-issued traceId for error tracking without leaking sensitive
 *           implementation details (backend handles this via problem document filtering).
 */
export const apiErrorInterceptor: HttpInterceptorFn = (req, next) =>
  next(req).pipe(catchError((error: unknown) => throwError(() => toAppError(error))));

/**
 * Converts an HTTP error (or other error type) into a standardized AppError.
 *
 * Conversion flow:
 * 1. If HttpErrorResponse with valid RFC 7807 problem document: extract code, detail, traceId.
 * 2. If HttpErrorResponse with status === 0 (network failure): create synthetic NETWORK_ERROR.
 * 3. If HttpErrorResponse (non-zero status, no problem doc): create generic HTTP_ERROR.
 * 4. If already an AppError: pass through unchanged.
 * 5. Otherwise: create UNEXPECTED_ERROR.
 *
 * @param error - The error to normalize (typically HttpErrorResponse, but may be any type).
 * @returns A standardized AppError object with code, message, optional traceId and details.
 */
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

/**
 * RFC 7807 Problem Details for HTTP APIs (https://tools.ietf.org/html/rfc7807).
 * The backend uses this format to communicate structured error information.
 *
 * @property code - Machine-readable error code (e.g., 'INVALID_CREDENTIALS', 'ACCOUNT_LOCKED').
 * @property detail - Human-readable error description.
 * @property traceId - Unique request identifier for end-to-end error tracking.
 * @property details - Optional nested validation errors (field-level details).
 */
interface ProblemDocument {
  readonly code: string;
  readonly detail?: string;
  readonly traceId?: string;
  readonly details?: AppError['details'];
}

/**
 * Type guard that validates whether an object conforms to the RFC 7807 ProblemDocument shape.
 * Only checks for the presence of a `code` property; the backend guarantees the structure
 * of other optional fields.
 *
 * @param body - The object to validate.
 * @returns True if body is a valid problem document; false otherwise.
 */
function isProblemDocument(body: unknown): body is ProblemDocument {
  return (
    typeof body === 'object' && body !== null && typeof (body as ProblemDocument).code === 'string'
  );
}
