import { Component, input, output } from '@angular/core';
import { UnavailableNotice } from '../../../shared/pages/unavailable/unavailable-notice';
import { NxEmptyState, NxErrorState } from '../../../shared/ui';
import { CONSOLE_COPY } from '../copy/console-copy';
import type { ConsoleErrorView } from '../copy/resolve-console-error';

/**
 * A failed page load as the user sees it (US-020 design §6.1, §12.0): copy-module title and body,
 * the reference line, and Retry. Dumb: it renders the {@link ConsoleErrorView} it is given and
 * emits `retry`; the page owns the retry.
 *
 * - **Not enabled** (`RESOURCE_NOT_FOUND`): an empty state with no Retry, since a retry cannot help.
 * - **A wait** (503 `AUTH_005`): the title and body, then the `UnavailableNotice` with its reference
 *   and a Retry that stays off through the cool-down (RC-75). `recordedAt` is when the failure was
 *   recorded; it defaults to when the panel appeared.
 * - **Anything else**: an alert (`NxErrorState`) with the reference and, unless the view says a
 *   retry cannot help, a Retry.
 *
 * It has no input that accepts `AppError`, so server text cannot reach it.
 */
@Component({
  selector: 'app-console-error-panel',
  imports: [NxEmptyState, NxErrorState, UnavailableNotice],
  template: `
    @if (view().notEnabled) {
      <nx-empty-state icon="toggle_off" [title]="view().title" [description]="view().body" />
    } @else if (view().showsWait) {
      <section class="console-error-panel" data-testid="console-error-wait">
        <h2 class="console-error-panel__title">{{ view().title }}</h2>
        <p class="console-error-panel__body">{{ view().body }}</p>
        <nx-unavailable-notice
          [reference]="view().reference"
          [retryAfterSeconds]="view().retryAfterSeconds"
          [recordedAt]="recordedAt() ?? shownAt"
          (retry)="retry.emit()"
        />
      </section>
    } @else {
      <nx-error-state
        [title]="view().title"
        [message]="view().body"
        [showRetry]="view().retryable"
        (retry)="retry.emit()"
      >
        @if (view().reference; as reference) {
          <p class="console-error-panel__reference" data-testid="console-error-reference">
            {{ copy.reference }} <span class="console-error-panel__id">{{ reference }}</span>
          </p>
        }
      </nx-error-state>
    }
  `,
  styleUrl: './console-error-panel.scss',
})
export class ConsoleErrorPanel {
  readonly view = input.required<ConsoleErrorView>();
  /** Epoch ms the failure was recorded, for the cool-down of a wait. */
  readonly recordedAt = input<number | undefined>();

  readonly retry = output<void>();

  protected readonly copy = CONSOLE_COPY;
  protected readonly shownAt = Date.now();
}
