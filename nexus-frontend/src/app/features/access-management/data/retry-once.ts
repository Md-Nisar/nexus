import { Observable, catchError, defer, throwError } from 'rxjs';
import type { LoggerService } from '../../../core/logging/logger.service';
import { isAppError } from '../../../shared/types/app-error';

/** The two writes that can meet a role reclassification race (design §7.3). */
export type ClassificationRetryOperation = 'assign' | 'replace';

/** What the retry log line names: the operation and the role, ids only. */
export interface ClassificationRetryAttempt {
  readonly operation: ClassificationRetryOperation;
  readonly roleId: string;
}

/** 409: the role's classification changed while the request waited; nothing was applied. */
const CLASSIFICATION_CHANGED = 'RBAC_012';

/**
 * Re-sends a write **once**, immediately, when it fails with `RBAC_012` (US-020 design §7.3, Gate 1
 * Q14; threat model SD-10, RES-53 accepted including the PUT).
 *
 * - `send` is called again, so the retry carries the same body and the same `If-Match`. A 409
 *   `RBAC_012` applied nothing, and the same strong tag can only succeed against the version the
 *   user reviewed: a changed set answers 412, which the caller handles without resubmitting.
 * - Any other failure, including 403, 412, 428, 429 and 503, and a second `RBAC_012`, is rethrown
 *   unchanged. There is no delay and no further attempt.
 * - Logs `access_console_retry_rbac_012` (info) with the operation and the role id only.
 *
 * Lives here, not in an interceptor: the interceptors stay free of business-code retries.
 */
export function retryOnceOnClassificationChange<T>(
  send: () => Observable<T>,
  attempt: ClassificationRetryAttempt,
  logger: LoggerService,
): Observable<T> {
  return defer(send).pipe(
    catchError((error: unknown) => {
      if (!isAppError(error) || error.code !== CLASSIFICATION_CHANGED) {
        return throwError(() => error);
      }
      logger.info('Access console write retried after a role classification change', {
        event: 'access_console_retry_rbac_012',
        context: { operation: attempt.operation, roleId: attempt.roleId },
      });
      return defer(send);
    }),
  );
}
