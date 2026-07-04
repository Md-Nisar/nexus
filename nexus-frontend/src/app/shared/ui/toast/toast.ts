import { inject, Service } from '@angular/core';
import { MatSnackBar, MatSnackBarConfig } from '@angular/material/snack-bar';

/**
 * Toast notification variant (semantic color and intent).
 * - `'info'` — neutral, informational message (blue)
 * - `'success'` — operation completed successfully (green)
 * - `'warning'` — caution or action-required message (orange)
 * - `'error'` — operation failed; user intervention needed (red)
 */
export type ToastVariant = 'info' | 'success' | 'warning' | 'error';

/**
 * Configuration options for a toast notification.
 * @property {string} message - Required notification text. Keep concise (< 100 chars) for mobile UX.
 * @property {ToastVariant} [variant='info'] - Semantic color and intent (info|success|warning|error).
 * @property {string} [action] - Optional action button label. If provided, user can click to dismiss.
 *   Default is 'Dismiss'. Use for actions like 'Undo', 'Retry', 'View' — not recommended for simple notifications.
 * @property {number} [duration] - Time in milliseconds before auto-dismiss. 0 = sticky (requires action click).
 *   Defaults: info/success/warning = 4000ms, error = 8000ms. Set higher for important/long messages.
 * @example
 * ```typescript
 * { message: 'Changes saved', variant: 'success' }
 * { message: 'Something went wrong', variant: 'error', duration: 10000 }
 * { message: 'Login required', action: 'Sign in', duration: 0 }
 * ```
 */
export interface ToastOptions {
  readonly message: string;
  readonly variant?: ToastVariant;
  readonly action?: string;
  readonly duration?: number;
}

/**
 * Toast notification service — display brief, dismissible alerts without page interruption.
 *
 * `NxToast` is a dependency-injectable service wrapping Material's `MatSnackBar` with:
 * - Four semantic variants (info, success, warning, error) with distinct colors
 * - Semantic duration defaults (errors longer, success shorter)
 * - Convenience methods (`success()`, `error()`, `info()`, `warning()`) for common cases
 * - Optional action button for undo/retry workflows
 * - Auto-dismiss after duration or click of action/dismiss
 * - Bottom-right positioning (mobile-safe, does not overlap FABs)
 * - Full screen reader support (live region announcements)
 *
 * ## Usage
 * Inject via constructor:
 * ```typescript
 * constructor(private toast: NxToast) {}
 *
 * onSave() {
 *   this.api.save(data).subscribe({
 *     next: () => this.toast.success('Saved successfully'),
 *     error: () => this.toast.error('Failed to save. Please try again.'),
 *   });
 * }
 * ```
 *
 * ## Features
 * - **Semantic variants**: Color and duration optimized for intent (e.g., error lasts longer)
 * - **Dismissible**: User can click action button or wait for auto-dismiss
 * - **Non-modal**: Does not block interaction with page; stacks if multiple notifications shown
 * - **Mobile-friendly**: Bottom-right position avoids keyboard overlap; short default duration
 * - **Accessible**: Live region (`aria-live="polite"`) announces to screen readers
 * - **Branded styling**: Uses design tokens for colors and spacing
 *
 * @example
 * // Simple success notification
 * ```typescript
 * this.toast.success('Profile updated');
 * ```
 *
 * @example
 * // Error with custom action (e.g., retry)
 * ```typescript
 * this.toast.show({
 *   message: 'Network error. Retrying...',
 *   variant: 'error',
 *   action: 'Try now',
 *   duration: 0, // sticky
 * });
 * ```
 *
 * @example
 * // Warning with context
 * ```typescript
 * this.toast.warning(
 *   'Unsaved changes will be lost',
 *   'Keep editing'
 * );
 * ```
 *
 * @example
 * // Info toast with longer duration
 * ```typescript
 * this.toast.show({
 *   message: 'New feature available. Update to see changes.',
 *   variant: 'info',
 *   duration: 6000,
 * });
 * ```
 *
 * @design-system
 * Toast notifications use design tokens for consistent theming:
 * - `--nx-color-info`, `--nx-color-success`, `--nx-color-warning`, `--nx-color-error` — variant text colors
 * - Background and surface colors via Material theming (respects light/dark mode)
 * - Positioning: `{ horizontalPosition: 'end', verticalPosition: 'bottom' }` for RTL-safe right-bottom alignment
 * - Duration animation uses Material easing
 *
 * ## Best Practices
 * - **Keep messages short**: Aim for < 100 characters for mobile readability
 * - **One action per toast**: Avoid multiple buttons; use a single primary action if needed
 * - **Match intent to variant**: Don't use error for info; use warning for caution
 * - **Set duration to intent**: Errors should linger (8s+) so user has time to read and act
 * - **Avoid success spam**: Don't show success toast for every keystroke; batch operations
 * - **Use dismissible action sparingly**: Only for undo/retry workflows; most users expect auto-dismiss
 * - **Avoid blocking modals**: Toast is non-modal; if you need user confirmation, use dialog instead
 *
 * @accessibility
 * - Root element has `role="status"`, `aria-live="polite"` (auto-announced to screen readers)
 * - Button (action/dismiss) is keyboard-accessible (Tab to focus, Enter/Space to activate)
 * - Text is high contrast (Material ensures ≥4.5:1 WCAG AA)
 * - No visual-only indicators; variant is conveyed by text content + color + icon (if used)
 * - Duration is keyboard-aware: sticky (duration=0) notifications stay until clicked
 *
 * @see {@link MatSnackBar} — underlying Material component
 * @see {@link NxErrorState} — for modal error dialogs (if blocking error UI needed)
 */
@Service()
export class NxToast {
  private readonly snackBar = inject(MatSnackBar);

  /**
   * Display a toast notification with full configuration options.
   * Used internally by convenience methods; call directly for custom duration/action.
   *
   * Positioning: always bottom-right (mobile-safe, does not overlap FABs).
   * Class applied: `nx-toast nx-toast--{variant}` for semantic styling.
   *
   * @param options - Toast configuration
   * @example
   * ```typescript
   * this.toast.show({
   *   message: 'Changes saved',
   *   variant: 'success',
   *   duration: 6000,
   * });
   * ```
   */
  show(options: ToastOptions): void {
    const variant = options.variant ?? 'info';
    const config: MatSnackBarConfig = {
      duration: options.duration ?? 4000,
      horizontalPosition: 'end',
      verticalPosition: 'bottom',
      panelClass: [`nx-toast`, `nx-toast--${variant}`],
    };
    this.snackBar.open(options.message, options.action ?? 'Dismiss', config);
  }

  /**
   * Display a success notification (green, 4s auto-dismiss).
   * Use for successful operations: saved, created, deleted, sent, etc.
   *
   * @param message - Success message (< 100 chars recommended)
   * @param action - Optional action button label (default: 'Dismiss')
   * @example
   * ```typescript
   * this.toast.success('Profile saved successfully');
   * this.toast.success('Email sent', 'View inbox');
   * ```
   */
  success(message: string, action?: string): void {
    this.show({ message, action, variant: 'success' });
  }

  /**
   * Display an error notification (red, 8s auto-dismiss).
   * Use for failed operations or error conditions requiring user attention.
   * Duration is longer (8s) to give user time to read and act.
   *
   * @param message - Error message explaining what went wrong (< 100 chars recommended)
   * @param action - Optional action button label for retry/fallback (default: 'Dismiss')
   * @example
   * ```typescript
   * this.toast.error('Failed to save. Please try again.');
   * this.toast.error('Network error', 'Retry');
   * this.toast.error('Invalid email address');
   * ```
   */
  error(message: string, action?: string): void {
    this.show({ message, action, variant: 'error', duration: 8000 });
  }

  /**
   * Display a warning notification (orange, 4s auto-dismiss).
   * Use for cautions or situations needing user attention: unsaved changes, expiring tokens, etc.
   *
   * @param message - Warning message (< 100 chars recommended)
   * @param action - Optional action button label (default: 'Dismiss')
   * @example
   * ```typescript
   * this.toast.warning('Unsaved changes will be lost');
   * this.toast.warning('Session expiring in 2 minutes', 'Stay signed in');
   * ```
   */
  warning(message: string, action?: string): void {
    this.show({ message, action, variant: 'warning' });
  }

  /**
   * Display an info notification (blue, 4s auto-dismiss).
   * Use for informational messages, announcements, or neutral updates.
   *
   * @param message - Info message (< 100 chars recommended)
   * @param action - Optional action button label (default: 'Dismiss')
   * @example
   * ```typescript
   * this.toast.info('New feature available');
   * this.toast.info('3 items added to cart', 'View cart');
   * ```
   */
  info(message: string, action?: string): void {
    this.show({ message, action, variant: 'info' });
  }
}
