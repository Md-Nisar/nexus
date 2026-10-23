import {
  Component,
  InjectionToken,
  computed,
  effect,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { NxAnnouncer } from '../../ui';

/** Cool-down without a `Retry-After` (RC-75). */
const DEFAULT_COOL_DOWN_SECONDS = 10;
/** Upper bound on an honoured `Retry-After` (RC-75). */
const MAX_COOL_DOWN_SECONDS = 60;
/** Jitter added on top, so tabs behind one NAT do not retry in step (T-D31). */
const MAX_JITTER_SECONDS = 5;

const READY_MESSAGE = 'You can retry now.';

/**
 * Source of the jitter fraction in `[0, 1)`. Non-cryptographic by design (TM §12.4); a token so
 * specs can seed it.
 */
export const COOL_DOWN_RANDOM = new InjectionToken<() => number>('COOL_DOWN_RANDOM', {
  providedIn: 'root',
  factory: () => Math.random,
});

/**
 * RC-75 cool-down in milliseconds: `min(retryAfterSeconds ?? 10, 60)` seconds plus
 * `jitterFraction × 5` seconds. A fraction outside `[0, 1]` (or NaN) is clamped.
 */
export function coolDownMs(retryAfterSeconds: number | undefined, jitterFraction: number): number {
  const base = Math.min(retryAfterSeconds ?? DEFAULT_COOL_DOWN_SECONDS, MAX_COOL_DOWN_SECONDS);
  const fraction = Number.isNaN(jitterFraction) ? 0 : Math.min(Math.max(jitterFraction, 0), 1);
  return Math.round((base + fraction * MAX_JITTER_SECONDS) * 1000);
}

let nextId = 0;

/**
 * "Nexus is unavailable" notice body: the reference, a cooled-down Retry and its countdown
 * (US-020 design §4.5, §12.11). Dumb: it emits `retry` and never navigates or calls HTTP itself.
 * The host owns the `h1` (the route page) or the page header (console pages), so this renders no
 * heading.
 *
 * ## Cool-down (RC-75)
 * Retry stays focusable but `aria-disabled` until `recordedAt` + {@link coolDownMs}. A new
 * `recordedAt` (a second failure) restarts it with fresh jitter. There is no automatic retry.
 *
 * ## Accessibility
 * - The countdown is plain text linked by `aria-describedby`, not a live region, so it is not
 *   announced every second. One polite announcement, "You can retry now.", fires at zero.
 * - While `retrying`, the button is `aria-busy` and `aria-disabled`; presses are ignored.
 */
@Component({
  selector: 'nx-unavailable-notice',
  template: `
    <div class="unavailable-notice" data-testid="unavailable-notice">
      @if (reference(); as ref) {
        <p class="unavailable-notice__reference" data-testid="unavailable-reference">
          Reference: <span class="unavailable-notice__id">{{ ref }}</span>
        </p>
      }
      <div class="unavailable-notice__retry-row">
        <button
          type="button"
          class="unavailable-notice__retry"
          [attr.aria-disabled]="blocked() ? 'true' : null"
          [attr.aria-busy]="retrying() ? 'true' : null"
          [attr.aria-describedby]="countdownId"
          (click)="onRetry()"
          data-testid="unavailable-retry"
        >
          {{ retrying() ? 'Retrying…' : 'Retry' }}
        </button>
        <p
          [id]="countdownId"
          class="unavailable-notice__countdown"
          data-testid="unavailable-countdown"
        >
          {{ countdownText() }}
        </p>
      </div>
    </div>
  `,
  styleUrl: './unavailable-notice.scss',
})
export class UnavailableNotice {
  private readonly announcer = inject(NxAnnouncer);
  private readonly random = inject(COOL_DOWN_RANDOM);

  /** `traceId` or `correlationId` of the failure; omitted when unknown. */
  readonly reference = input<string | undefined>();
  /** `Retry-After` of the failure, when it carried one. */
  readonly retryAfterSeconds = input<number | undefined>();
  /** Epoch ms the failure was recorded; the cool-down runs from here. */
  readonly recordedAt = input.required<number>();
  /** True while the host's retry is in flight. */
  readonly retrying = input(false);
  /** False for a countdown of exactly the base seconds (RC-75: 10 s with no recorded state). */
  readonly jitter = input(true);

  /** The user pressed Retry after the cool-down. */
  readonly retry = output<void>();

  protected readonly countdownId = `nx-unavailable-countdown-${nextId++}`;

  /** Epoch ms when Retry becomes available; new jitter whenever its inputs change. */
  private readonly retryAt = computed(
    () =>
      this.recordedAt() + coolDownMs(this.retryAfterSeconds(), this.jitter() ? this.random() : 0),
  );

  private readonly remainingMs = signal(Number.POSITIVE_INFINITY);

  private readonly coolingDown = computed(() => this.remainingMs() > 0);

  protected readonly blocked = computed(() => this.coolingDown() || this.retrying());

  protected readonly countdownText = computed(() =>
    this.coolingDown() ? `Retry in ${Math.ceil(this.remainingMs() / 1000)} s` : READY_MESSAGE,
  );

  constructor() {
    // One timer chain per deadline, ticking on whole-second boundaries of the remaining time.
    // The cleanup clears it when the deadline changes or the component is destroyed.
    effect((onCleanup) => {
      const at = this.retryAt();
      let handle: ReturnType<typeof setTimeout> | undefined;
      const tick = (): void => {
        const left = at - Date.now();
        this.remainingMs.set(Math.max(left, 0));
        if (left > 0) {
          handle = setTimeout(tick, left % 1000 || 1000);
        } else {
          void this.announcer.announce(READY_MESSAGE, 'polite');
        }
      };
      tick();
      onCleanup(() => clearTimeout(handle));
    });
  }

  protected onRetry(): void {
    if (this.blocked()) return;
    this.retry.emit();
  }
}
