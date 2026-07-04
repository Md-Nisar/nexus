import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';

/**
 * Error state presentation component for displaying failures and error conditions.
 *
 * `<nx-error-state>` displays a centered, visually prominent error UI with optional
 * title, detailed error message, and retry button. Commonly used when:
 * - A data load fails (network error, server 5xx, timeout)
 * - A critical operation fails (save, delete, fetch)
 * - A feature is temporarily unavailable
 *
 * Automatically marked as an alert region (`role="alert"`) for immediate announcement
 * to screen readers without requiring aria-live.
 *
 * Use `NxErrorState` for **failures and error paths**; use `NxEmptyState` instead
 * for zero-data results (which are not errors, just no-data states).
 *
 * ## Features
 * - **Alert role**: Marked `role="alert"` for immediate screen reader announcement
 * - **Prominent icon**: Large error icon (Material `error_outline`) draws attention
 * - **Flexible message**: Title + optional detailed message for context
 * - **Retry action**: Optional "Try again" button with easy click target
 * - **Extensible**: ng-content slot for additional actions (contact support, go home, etc.)
 * - **Centered layout**: Works in full-height containers
 * - **Accessible**: High-contrast icon, semantic HTML, keyboard navigation
 *
 * @example
 * // Basic API load error with retry
 * ```typescript
 * @if (loadError(); else showData) {
 *   <nx-error-state
 *     title="Failed to load data"
 *     message="The server encountered an error. Please try again."
 *     (retry)="reload()"
 *   />
 * }
 * @template #showData { ... }
 * ```
 *
 * @example
 * // Network timeout with custom actions
 * ```html
 * <nx-error-state
 *   title="Connection timeout"
 *   message="The request took too long. Check your internet connection and try again."
 *   [showRetry]="true"
 *   (retry)="retryWithBackoff()"
 * >
 *   <a nx-button variant="secondary" routerLink="/">Go home</a>
 *   <button nx-button variant="outlined" (click)="openSupport()">Contact support</button>
 * </nx-error-state>
 * ```
 *
 * @example
 * // Access denied — no retry, show alternatives
 * ```html
 * <nx-error-state
 *   title="Access denied"
 *   message="You don't have permission to view this resource."
 *   [showRetry]="false"
 * >
 *   <button nx-button variant="secondary" (click)="requestAccess()">Request access</button>
 *   <a nx-button variant="outlined" routerLink="/help">Learn more</a>
 * </nx-error-state>
 * ```
 *
 * @example
 * // Feature unavailable (maintenance)
 * ```html
 * <nx-error-state
 *   title="Feature unavailable"
 *   message="This feature is temporarily under maintenance. We'll be back soon."
 *   [showRetry]="false"
 * >
 *   <button nx-button variant="secondary" (click)="goBack()">Go back</button>
 * </nx-error-state>
 * ```
 *
 * @design-system
 * Uses design tokens for error-focused styling:
 * - `--nx-color-error` — icon color (red, semantic error variant)
 * - `--nx-color-on-surface` / `--nx-color-on-surface-muted` — text colors
 * - `--nx-text-lg` / `--nx-text-base` / `--nx-text-sm` — typography for title/message
 * - `--nx-space-6`, `--nx-space-12` — padding and spacing
 * - Material button styles via `mat-flat-button` for retry action
 * - Icon size and color respond to light/dark theme automatically
 *
 * ## Best Practices
 * - **Clear title**: Use 3–6 words; be specific ("Failed to load tasks" not just "Error")
 * - **Explain why**: Provide actionable message ("Check internet connection" not "Server error")
 * - **Show retry only for transient failures**: Network errors, timeouts, 5xx errors
 * - **Hide retry for permanent failures**: Permission denied, not found (404), validation errors
 * - **Use custom actions for context-specific recovery**: "Request access", "Go home", "Contact support"
 * - **Keep message concise**: Aim for 1–2 sentences; users are already frustrated
 * - **Avoid jargon**: Don't show stack traces, error codes, or internal messages
 * - **Use slot for secondary actions**: Avoid cluttering with too many buttons
 *
 * @accessibility
 * - Root has `role="alert"` — immediately announced to screen readers without aria-live
 * - Icon is `aria-hidden="true"` (decorative; message conveyed by text)
 * - Title announces error condition; always visible and first in reading order
 * - Message provides detail and next steps
 * - Buttons are semantic `<button>` with keyboard focus and ARIA labels
 * - Tab order: Retry button first, then custom ng-content actions
 * - Sufficient color contrast (Material ensures ≥4.5:1 WCAG AA)
 * - Do not rely on icon color alone; text must be clear
 * - Keyboard-operable: Tab to buttons, Enter/Space to activate
 *
 * @event retry - Emits when user clicks the "Try again" button (only if `showRetry=true`)
 *
 * @see {@link NxEmptyState} — for zero-data states (not errors)
 * @see {@link NxToast} — for temporary error notifications
 */
@Component({
  selector: 'nx-error-state',
  standalone: true,
  imports: [MatIconModule, MatButtonModule],
  template: `
    <div class="nx-error-state" role="alert" data-testid="nx-error-state">
      <mat-icon class="nx-error-state__icon" aria-hidden="true">error_outline</mat-icon>
      <p class="nx-error-state__title">{{ title() }}</p>
      @if (message()) {
        <p class="nx-error-state__message">{{ message() }}</p>
      }
      @if (showRetry()) {
        <button
          mat-flat-button
          class="nx-error-state__retry"
          (click)="retry.emit()"
          data-testid="nx-error-state-retry"
        >
          Try again
        </button>
      }
      <ng-content />
    </div>
  `,
  styleUrl: './error-state.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxErrorState {
  /**
   * Error headline displayed in large, bold typography.
   * Announces the error to screen readers via `role="alert"`.
   * Keep concise (3–6 words) and specific:
   * - Good: "Failed to load data", "Connection timeout", "Access denied"
   * - Avoid: "Error", "Error 500", "Something went wrong"
   *
   * @default 'Something went wrong'
   * @example 'Failed to load data'
   * @example 'Connection timeout'
   * @example 'Access denied'
   * @example 'Service temporarily unavailable'
   */
  readonly title = input('Something went wrong');

  /**
   * Optional detailed error explanation or context.
   * Displayed below title in secondary text color.
   * Use to explain what happened and suggest next steps:
   * - Why: "The server encountered an error"
   * - How to fix: "Check your internet connection and try again"
   * - What's next: "If the problem persists, contact support"
   *
   * When empty string, the message paragraph is not rendered.
   * Keep message concise (1–2 sentences); users are already frustrated.
   * Avoid jargon, stack traces, and error codes.
   *
   * @default '' (empty — message is hidden if not provided)
   * @example 'The server encountered an error. Please try again.'
   * @example 'Check your internet connection and try again.'
   * @example 'This feature is temporarily under maintenance.'
   * @example "You don't have permission to view this resource."
   */
  readonly message = input<string>('');

  /**
   * If true, displays a prominent "Try again" button below the message.
   * Use for transient/retryable failures: network errors, timeouts, 5xx errors.
   * Set to false for permanent/user-caused errors: permissions, not found (404), validation.
   * Clicking the button emits the `retry` event.
   *
   * @default true
   * @example [showRetry]="error.retryable"
   * @example [showRetry]="error.statusCode >= 500 || error.statusCode === 0"
   * @example [showRetry]="false" for permission/validation errors
   */
  readonly showRetry = input(true);

  /**
   * Emits when user clicks the "Try again" button.
   * Only fired if `showRetry=true`.
   * Use to re-trigger the failed operation (reload, refetch, retry API call).
   * Parent typically implements exponential backoff or timeout logic.
   *
   * @example (retry)="loadData()"
   * @example (retry)="reload()"
   * @example (retry)="retryWithBackoff()"
   */
  readonly retry = output<void>();
}
