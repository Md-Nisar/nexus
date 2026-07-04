import { ChangeDetectionStrategy, Component, input } from '@angular/core';

/**
 * Compact status badge for displaying semantic labels, tags, and state indicators.
 *
 * `<nx-badge>` is a small, inline semantic component that communicates status,
 * category, or progress state using color and text. It is configured as a live region
 * (`role="status"`, `aria-live="polite"`) to announce dynamic state changes to screen readers.
 *
 * ## Features
 * - Five semantic variants: success, error, warning, neutral, primary
 * - Live region announcements for status changes
 * - Color contrast ≥4.5:1 (WCAG AA)
 * - Inline display for use within text, tables, or lists
 * - Text content fully user-provided (supports any text or icon)
 *
 * @example
 * Display a success status:
 * ```html
 * <nx-badge variant="success">Active</nx-badge>
 * ```
 *
 * @example
 * Show error state in a form:
 * ```html
 * <label>
 *   Email
 *   <nx-badge variant="error">Invalid format</nx-badge>
 * </label>
 * ```
 *
 * @example
 * Announce dynamic status updates:
 * ```html
 * <nx-badge [variant]="status.type">{{ status.label }}</nx-badge>
 * ```
 * When status changes, screen readers announce the new text immediately via aria-live.
 *
 * @design-system
 * Uses semantic color token families:
 * - `--nx-color-success` and `--nx-color-success-surface` — for success variant
 * - `--nx-color-error` and `--nx-color-error-surface` — for error/destructive variant
 * - `--nx-color-warning` and `--nx-color-warning-surface` — for warning/caution variant
 * - `--nx-color-primary` and `--nx-color-primary-surface` — for primary/highlight variant
 * - `--nx-color-surface-variant` — for neutral/metadata variant
 *
 * Spacing and typography use:
 * - `--nx-space-xs` / `--nx-space-sm` — padding within badge
 * - `--nx-text-sm` — badge font-size and line-height
 * - `--nx-radius-sm` — border-radius for subtle rounding
 *
 * @accessibility
 * - `role="status"` marks the component as a status region
 * - `aria-live="polite"` announces text changes to screen readers
 * - **Do not rely on color alone** — always pair color with text label
 * - Color contrast ≥4.5:1 (WCAG AA) enforced by design tokens
 * - No focus management (purely presentational; not interactive)
 * - Icon glyphs (if added as text content) should be labeled or aria-hidden
 */
export type BadgeVariant = 'success' | 'error' | 'warning' | 'neutral' | 'primary';

@Component({
  selector: 'nx-badge',
  standalone: true,
  host: {
    '[class]': '"nx-badge nx-badge--" + variant()',
    role: 'status',
    'aria-live': 'polite',
  },
  template: `<ng-content />`,
  styleUrl: './badge.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxBadge {
  /**
   * Semantic color variant that signals the badge's visual meaning and intent.
   *
   * - `'success'` — positive state or completion (green) — use for "Active", "Verified", "Completed"
   * - `'error'` — failure or destructive state (red) — use for "Failed", "Deleted", "Blocked"
   * - `'warning'` — caution or attention-needed state (orange) — use for "Pending", "Review Required", "Expired"
   * - `'primary'` — highlight or emphasized state (blue) — use for "New", "Featured", "In Progress"
   * - `'neutral'` — metadata or unstateful label (gray) — use for "Archived", "Draft", "Other"
   *
   * The variant determines both text color and background color via design tokens.
   * **Important:** Variant color should always be paired with descriptive text;
   * do not rely on color alone to convey meaning (WCAG 2.1 SC 1.4.1).
   *
   * @default 'neutral'
   *
   * @example
   * ```html
   * <!-- Success state -->
   * <nx-badge variant="success">Verified Email</nx-badge>
   *
   * <!-- Error state -->
   * <nx-badge variant="error">Payment Failed</nx-badge>
   *
   * <!-- Warning state -->
   * <nx-badge variant="warning">Requires Action</nx-badge>
   * ```
   */
  readonly variant = input<BadgeVariant>('neutral');
}
