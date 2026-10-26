import {
  afterNextRender,
  Component,
  computed,
  ElementRef,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { LoggerService } from '../../../core/logging/logger.service';
import { safeReturnUrl } from '../../../core/routing/safe-return-url';
import { UnavailableRecord, UnavailableState } from '../../../core/routing/unavailable-state';
import { UnavailableNotice } from './unavailable-notice';

/** Marker for "no retry in flight" (distinct from a retry started while no state was recorded). */
const IDLE = Symbol('idle');

/**
 * The cold-start "Nexus is temporarily unavailable" view at `/unavailable` (US-020 design §4.5,
 * §12.11; Gate 1 Q4 as amended). `authGuard` sends a user here when the session refresh got no
 * authoritative answer.
 *
 * - Public, under `PublicLayout`, outside the shell: a child of the shell would re-run the failing
 *   `authGuard`. The route carries no guard and only `data.selfManagedFocus`.
 * - **No HTTP**: the page injects no `HttpClient` and issues no request. Retry only navigates, so
 *   the single refresh of the next attempt comes from `authGuard` (RC-65). No automatic retry.
 * - `returnUrl` is read once and passed through `safeReturnUrl`; Retry navigates to exactly that
 *   validated string, and "Go to sign-in" carries it to the login page.
 * - The reference comes from {@link UnavailableState} (memory), never from the URL.
 * - Focus moves to the `h1` on render.
 *
 * @security Static copy plus an in-memory reference; nothing from the URL is rendered.
 */
@Component({
  selector: 'nx-unavailable-page',
  imports: [RouterLink, UnavailableNotice],
  template: `
    <main class="unavailable" data-testid="unavailable-root">
      <h1 #heading class="unavailable__heading" tabindex="-1" data-testid="unavailable-heading">
        Nexus is temporarily unavailable
      </h1>
      <p class="unavailable__body">
        We couldn't confirm your sign-in because Nexus isn't responding. Your session may still be
        valid.
      </p>

      <nx-unavailable-notice
        [reference]="record()?.reference"
        [retryAfterSeconds]="record()?.retryAfterSeconds"
        [recordedAt]="recordedAt()"
        [jitter]="hasRecord()"
        [retrying]="retrying()"
        (retry)="retry()"
      />

      <a
        class="unavailable__sign-in"
        routerLink="/auth/login"
        [queryParams]="signInQuery"
        data-testid="unavailable-sign-in"
      >
        Go to sign-in
      </a>
    </main>
  `,
  styleUrl: './unavailable.page.scss',
})
export class UnavailablePage {
  private readonly heading = viewChild.required<ElementRef<HTMLHeadingElement>>('heading');
  private readonly router = inject(Router);
  private readonly state = inject(UnavailableState);
  private readonly logger = inject(LoggerService);

  /** Validated once; the only string Retry will ever navigate to. */
  private readonly target = safeReturnUrl(
    inject(ActivatedRoute).snapshot.queryParamMap.get('returnUrl'),
  );

  protected readonly signInQuery = { returnUrl: this.target } as const;

  /** When nothing was recorded (a reload or a direct visit), the cool-down runs from render. */
  private readonly renderedAt = Date.now();

  protected readonly record = this.state.latest;

  protected readonly hasRecord = computed(() => this.record() !== null);

  /** With no record, exactly 10 s from render and no jitter (RC-75). */
  protected readonly recordedAt = computed(() => this.record()?.recordedAt ?? this.renderedAt);

  /**
   * The record that was current when Retry was pressed, or {@link IDLE}. A retry is in flight
   * while that record is still the latest: a new failure recorded by `authGuard` ends it even when
   * the router ignores the same-URL redirect and this page stays mounted.
   */
  private readonly retriedFrom = signal<UnavailableRecord | null | typeof IDLE>(IDLE);

  protected readonly retrying = computed(() => {
    const from = this.retriedFrom();
    return from !== IDLE && from === this.record();
  });

  constructor() {
    afterNextRender(() => this.heading().nativeElement.focus());
  }

  protected retry(): void {
    if (this.retrying()) return;
    const from = this.record();
    this.retriedFrom.set(from);
    this.router
      .navigateByUrl(this.target)
      .catch((error: unknown) => {
        // For example the shell's chunk failed to load during the outage. The user stays here
        // and can press Retry again; the URL is not logged (it can carry query text).
        this.logger.warn('Retry from the unavailable view failed to navigate', {
          event: 'unavailable_retry_navigation_failed',
          outcome: 'FAILURE',
          errorType: error instanceof Error ? error.name : typeof error,
        });
      })
      .finally(() => {
        // Only clear our own attempt; a later press may already have started another.
        if (this.retriedFrom() === from) this.retriedFrom.set(IDLE);
      });
  }
}
