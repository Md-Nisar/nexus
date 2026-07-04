import { HttpInterceptorFn } from '@angular/common/http';

/**
 * HTTP header name for request correlation tracking.
 * Backend echoes this value in responses and stamps it on all server-side logs
 * (MDC traceId) for end-to-end request tracing.
 */
export const CORRELATION_HEADER = 'X-Correlation-Id';

/**
 * HTTP interceptor that attaches a unique correlation ID to every outgoing request.
 *
 * Responsibilities:
 * - **ID generation**: Creates a new UUID4 correlation ID for each request via crypto.randomUUID().
 * - **Header attachment**: Injects the ID into the X-Correlation-Id header.
 * - **Backend echo**: The backend receives the header, echoes it back in response headers,
 *   and stamps it on all server-side logs (MDC traceId for Logback/SLF4J).
 *
 * End-to-end tracing: A single correlation ID traces a user action across both frontend
 * (browser console, network tab) and backend (server logs) tiers, enabling efficient
 * debugging and request tracking across distributed logs.
 *
 * @security Each request receives a cryptographically random UUID4, ensuring no correlation
 *           ID is predictable or reusable across requests.
 */
export const correlationIdInterceptor: HttpInterceptorFn = (req, next) =>
  next(req.clone({ setHeaders: { [CORRELATION_HEADER]: crypto.randomUUID() } }));
