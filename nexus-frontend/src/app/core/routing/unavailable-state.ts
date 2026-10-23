import { Service, Signal, signal } from '@angular/core';
import { AppError } from '../../shared/types/app-error';

/** What the unavailable view needs from the last failed cold-start refresh. */
export interface UnavailableRecord {
  /** `traceId` when the backend issued one, else the request's `correlationId`. */
  readonly reference: string | undefined;
  /** The parsed, capped `Retry-After` of the failure, when it carried one. */
  readonly retryAfterSeconds: number | undefined;
  /** `Date.now()` when the failure was recorded; the cool-down is measured from here (RC-75). */
  readonly recordedAt: number;
}

/**
 * In-memory record of the last cold-start refresh that nobody authoritative answered (US-020
 * design §4.5). `authGuard` writes it before redirecting to `/unavailable`; the view reads it.
 *
 * Each {@link record} call stores a new object, so a consumer can tell a second failure from the
 * first even when the router ignores the same-URL redirect and the view stays mounted.
 *
 * Deliberately Material-free and HTTP-free: `authGuard` is in the initial bundle.
 *
 * @security Memory only. The reference is never written to storage or the URL (`AppError.traceId`
 * must not appear in public URLs), and nothing else from the error (message, details, permission)
 * is kept.
 */
@Service()
export class UnavailableState {
  private readonly current = signal<UnavailableRecord | null>(null);

  /** The last recorded failure, or `null` when none was recorded in this page load. */
  readonly latest: Signal<UnavailableRecord | null> = this.current.asReadonly();

  record(error: AppError): void {
    this.current.set({
      reference: error.traceId ?? error.correlationId,
      retryAfterSeconds: error.retryAfterSeconds,
      recordedAt: Date.now(),
    });
  }
}
