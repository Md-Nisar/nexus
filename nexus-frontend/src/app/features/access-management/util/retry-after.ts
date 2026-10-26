import { DestroyRef, Signal, computed, signal } from '@angular/core';
import type { AppError } from '../../../shared/types/app-error';

/** Wait when a 429 or 503 carried no usable `Retry-After` (design §7.4). */
export const DEFAULT_RETRY_AFTER_SECONDS = 30;

/** Seconds to wait before the refused action may be tried again (design §7.4). */
export function retryAfterSeconds(error: AppError): number {
  return error.retryAfterSeconds ?? DEFAULT_RETRY_AFTER_SECONDS;
}

/** A whole-second countdown that re-enables a control at zero. */
export interface RetryCountdown {
  /** Seconds left; `0` when not counting. */
  readonly remaining: Signal<number>;
  /** True while there is time left. */
  readonly active: Signal<boolean>;
  /** Starts (or restarts) from `seconds`; a non-positive value ends any countdown. */
  start(seconds: number): void;
  /** Ends the countdown at once. */
  stop(): void;
}

const TICK_MS = 1000;

/**
 * A countdown for the control a 429 or 503 refused (design §7.4, FR-X2, FR-X3). There is no
 * automatic retry (RC-63(l)): at zero the control is simply usable again. The seconds left are
 * computed from a deadline on every tick, so a throttled background tab shows the true wait and
 * never outlasts the server's window. The timer is cleared when `destroyRef` is destroyed.
 */
export function createRetryCountdown(destroyRef: DestroyRef): RetryCountdown {
  const remaining = signal(0);
  let handle: ReturnType<typeof setTimeout> | undefined;
  /** When the wait ends (epoch ms). Every tick reads the clock, so late ticks never drift. */
  let deadline = 0;

  const clear = (): void => {
    if (handle !== undefined) clearTimeout(handle);
    handle = undefined;
  };
  const tick = (): void => {
    const next = Math.max(Math.ceil((deadline - Date.now()) / TICK_MS), 0);
    remaining.set(next);
    handle = next > 0 ? setTimeout(tick, TICK_MS) : undefined;
  };

  destroyRef.onDestroy(clear);

  return {
    remaining: remaining.asReadonly(),
    active: computed(() => remaining() > 0),
    start(seconds: number): void {
      clear();
      const whole = Math.max(Math.ceil(seconds), 0);
      deadline = Date.now() + whole * TICK_MS;
      remaining.set(whole);
      if (whole > 0) handle = setTimeout(tick, TICK_MS);
    },
    stop(): void {
      clear();
      remaining.set(0);
    },
  };
}
