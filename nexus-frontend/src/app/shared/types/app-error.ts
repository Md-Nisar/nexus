/**
 * Normalized application error. The API error interceptor converts every HTTP failure
 * (backend RFC 7807 problem responses, network failures) into this shape — components
 * never inspect HttpErrorResponse or status codes directly.
 */
export interface AppError {
  readonly code: string;
  readonly message: string;
  readonly traceId?: string;
  readonly details?: readonly FieldError[];
}

export interface FieldError {
  readonly field: string;
  readonly message: string;
}

export function isAppError(value: unknown): value is AppError {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as AppError).code === 'string' &&
    typeof (value as AppError).message === 'string'
  );
}
