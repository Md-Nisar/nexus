import { Injector, Service, inject } from '@angular/core';

/** Window used when a 503 `AUTH_005` carries no usable `Retry-After` (the backend sends 30). */
const DEFAULT_RETRY_AFTER_S = 30;

/** Longest window honoured, whatever the caller passes. */
const MAX_RETRY_AFTER_S = 300;

/**
 * Tells the user that Nexus is temporarily unavailable (503 `AUTH_005`, design §12.10).
 *
 * Shows **one** warning toast per `Retry-After` window, so a burst of failing requests does not
 * stack toasts. It never navigates and never retries: the session and the current page stay as
 * they are, and the user decides when to try again.
 *
 * `NxToast` (and with it the Material snack bar) is loaded on first use, because this service is
 * reached from an app-wide interceptor and would otherwise put the snack bar in the initial bundle.
 */
@Service()
export class ServiceAvailabilityNotifier {
  private readonly injector = inject(Injector);
  private suppressUntilMs = 0;

  /**
   * @param retryAfterSeconds the response's `Retry-After` in whole seconds, if it had a valid one
   */
  notifyUnavailable(retryAfterSeconds: number | undefined): void {
    const now = Date.now();
    if (now < this.suppressUntilMs) {
      return;
    }
    const seconds = Math.min(retryAfterSeconds ?? DEFAULT_RETRY_AFTER_S, MAX_RETRY_AFTER_S);
    this.suppressUntilMs = now + seconds * 1000;
    const unit = seconds === 1 ? 'second' : 'seconds';
    const message = `Nexus is temporarily unavailable. Try again in ${seconds} ${unit}.`;
    void import('../../shared/ui/toast/toast').then(({ NxToast }) =>
      this.injector.get(NxToast).warning(message),
    );
  }
}
