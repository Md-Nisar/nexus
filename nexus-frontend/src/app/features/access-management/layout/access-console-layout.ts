import {
  Component,
  OnInit,
  computed,
  effect,
  inject,
  linkedSignal,
  untracked,
} from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { AuthStore } from '../../../core/auth/auth.store';
import { UnavailableNotice } from '../../../shared/pages/unavailable/unavailable-notice';
import { NavTab, NxBanner, NxButton, NxTabs } from '../../../shared/ui';
import { CONSOLE_COPY } from '../copy/console-copy';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CONSOLE_AREAS } from './console-areas';

/**
 * Why the console is read-only, from the profile failure (US-020 design §6.3, §12.0):
 * - `not-enabled`: 404 `RESOURCE_NOT_FOUND`, the us019 flag is off. A retry cannot help.
 * - `unavailable`: 503 `AUTH_005`. The notice replaces the page; Retry after the cool-down.
 * - `failed`: any other failure (5xx, `NETWORK_ERROR`, `HTTP_ERROR`, …). Reference and Retry.
 */
type ProfileNotice =
  | { readonly kind: 'not-enabled' }
  | { readonly kind: 'failed'; readonly reference: string | undefined }
  | {
      readonly kind: 'unavailable';
      readonly reference: string | undefined;
      readonly retryAfterSeconds: number | undefined;
      readonly recordedAt: number;
    };

/**
 * Layout of every console page (US-020 design §6.1, §12.1): the area sub-nav, the read-only banner
 * and the routed page.
 *
 * - **Areas** come from `AuthStore` (the JWT, like nav and guards; ADR-0028 decision 3): a tab is
 *   shown only when the user holds its route permission.
 * - **Profile:** reads the live profile once on init, i.e. once per console entry; child
 *   navigation keeps this component and reads nothing. Another user signing in while it is open
 *   reloads it (`user-changed`). It never refreshes the session (RC-65).
 * - **Read-only (Q8):** when the profile cannot be read, a status banner says changes are off and
 *   pages see `mutationsEnabled() === false`. Read pages keep working, except on 503 `AUTH_005`,
 *   where the inline `UnavailableNotice` takes the page's place.
 * - **Headings and focus:** pages own the single `h1` (their `nx-page-header`); route focus moves
 *   to it. Only when the notice replaces the page does the layout render the `h1`.
 *
 * @security UX only. The server decides every request.
 */
@Component({
  selector: 'app-access-console-layout',
  imports: [RouterOutlet, NxBanner, NxButton, NxTabs, UnavailableNotice],
  templateUrl: './access-console-layout.html',
  styleUrl: './access-console-layout.scss',
})
export class AccessConsoleLayout implements OnInit {
  private readonly authStore = inject(AuthStore);
  private readonly profile = inject(AuthorizationProfileStore);

  protected readonly copy = CONSOLE_COPY;

  protected readonly areas = computed<readonly NavTab[]>(() => {
    const held = this.authStore.permissions();
    return CONSOLE_AREAS.filter((area) => held.includes(area.permission)).map((area) => ({
      label: CONSOLE_COPY.areas[area.id].label,
      path: area.path,
      testId: `access-area-${area.id}`,
    }));
  });

  /** The failure as the layout presents it, while the profile is in `error`. */
  private readonly settledNotice = computed<ProfileNotice | null>(() => {
    const state = this.profile.state();
    if (state.status !== 'error') return null;
    const reference = state.error.traceId ?? state.error.correlationId;
    switch (state.error.code) {
      case 'RESOURCE_NOT_FOUND':
        return { kind: 'not-enabled' };
      case 'AUTH_005':
        return {
          kind: 'unavailable',
          reference,
          retryAfterSeconds: state.error.retryAfterSeconds,
          recordedAt: state.failedAt,
        };
      default:
        return { kind: 'failed', reference };
    }
  });

  /**
   * The notice a Retry started from. It keeps the banner (and the notice) on screen, busy, while
   * the retried read is in flight, and resets whenever the profile state changes after that.
   */
  private readonly retriedNotice = linkedSignal<unknown, ProfileNotice | null>({
    source: this.profile.state,
    computation: () => null,
  });

  protected readonly retrying = computed(
    () => this.profile.state().status === 'loading' && this.retriedNotice() !== null,
  );

  protected readonly notice = computed<ProfileNotice | null>(
    () => this.settledNotice() ?? (this.retrying() ? this.retriedNotice() : null),
  );

  protected readonly failure = computed(() => {
    const notice = this.notice();
    return notice?.kind === 'failed' ? notice : null;
  });

  protected readonly failureReference = computed(() => this.failure()?.reference ?? null);

  protected readonly unavailable = computed(() => {
    const notice = this.notice();
    return notice?.kind === 'unavailable' ? notice : null;
  });

  constructor() {
    // Another user signing in while the console is open (DQ-7). The store already hides the
    // previous user's profile; this reads the new one. A sign-out reads nothing.
    let previousUserId: string | null | undefined;
    effect(() => {
      const userId = this.authStore.currentUser()?.userId ?? null;
      untracked(() => {
        if (previousUserId !== undefined && userId !== previousUserId && userId !== null) {
          this.profile.reload('user-changed');
        }
        previousUserId = userId;
      });
    });
  }

  ngOnInit(): void {
    this.profile.load();
  }

  /** Retry from the banner or the notice: one more read, ignored while one is in flight. */
  protected retry(): void {
    const notice = this.notice();
    if (notice === null || notice.kind === 'not-enabled' || this.retrying()) return;
    this.profile.load();
    this.retriedNotice.set(notice);
  }
}
