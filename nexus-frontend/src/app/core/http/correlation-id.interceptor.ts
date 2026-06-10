import { HttpInterceptorFn } from '@angular/common/http';

export const CORRELATION_HEADER = 'X-Correlation-Id';

/**
 * Attaches a unique correlation id to every outgoing request. The backend echoes it back
 * and stamps it on all server-side logs (MDC traceId), so one id traces a user action
 * end-to-end across both tiers.
 */
export const correlationIdInterceptor: HttpInterceptorFn = (req, next) =>
  next(req.clone({ setHeaders: { [CORRELATION_HEADER]: crypto.randomUUID() } }));
