import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';

/**
 * Customizable button component with multiple variants, sizes, and loading states.
 *
 * `<nx-button>` is a token-driven, semantic HTML button element (not a MatButton wrapper)
 * that applies full visual semantics via Nexus design tokens. Material icons are used
 * for optional leading, trailing, and loading glyphs.
 *
 * ## Features
 * - Six visual variants: primary, secondary, tertiary, danger, ghost, inverse
 * - Three size options: sm, md, lg
 * - Loading state with spinner and aria-busy announcement
 * - Optional leading and trailing Material icons
 * - Full-width layout option
 * - ARIA-labeling for icon-only or complex buttons
 *
 * @example
 * Basic primary button:
 * ```html
 * <nx-button variant="primary" size="md" (clicked)="handleClick()">
 *   Save Changes
 * </nx-button>
 * ```
 *
 * @example
 * Loading button with icon:
 * ```html
 * <nx-button [loading]="isSaving" leadingIcon="save">
 *   Save
 * </nx-button>
 * ```
 *
 * @example
 * Danger button for destructive actions:
 * ```html
 * <nx-button variant="danger" (clicked)="handleDelete()">
 *   Delete Account
 * </nx-button>
 * ```
 *
 * @design-system
 * Uses the following token families:
 * - `--nx-color-*` — foreground and background colors per variant
 * - `--nx-space-*` — padding and gaps around text/icons
 * - `--nx-radius-*` — border-radius for rounded corners
 * - `--nx-shadow-*` — elevation and depth effects (with `:hover`, `:active`)
 * - `--nx-duration-*` — transition animations (hover/active state changes)
 * - `--nx-text-*` — typography (font-size, line-height, weight)
 *
 * Never override visual properties with inline styles; use variant and size inputs instead.
 *
 * @accessibility
 * - Native `<button>` element provides automatic keyboard navigation (Tab, Space, Enter)
 * - `[aria-busy]="loading()"` announces async operations to assistive technologies
 * - `[aria-label]` optional input supports icon-only or context-extended buttons
 * - Disabled state prevents all interaction (keyboard, pointer, touch)
 * - Icon glyphs marked `aria-hidden="true"` prevent semantic duplication
 * - Focus ring via `:focus-visible` pseudo-class ensures visible focus indicator
 * - Loading spinner icon marked `aria-hidden` to avoid duplication of busy state
 */
export type ButtonVariant = 'primary' | 'secondary' | 'tertiary' | 'danger' | 'ghost' | 'inverse';
export type ButtonSize = 'sm' | 'md' | 'lg';

@Component({
  selector: 'nx-button',
  standalone: true,
  imports: [MatIconModule],
  host: {
    '[class.nx-btn-host--full-width]': 'fullWidth()',
  },
  template: `
    <button
      [class]="buttonClass()"
      [type]="type()"
      [disabled]="disabled()"
      [attr.aria-busy]="loading() ? true : null"
      [attr.aria-label]="ariaLabel() || null"
      (click)="clicked.emit()"
      data-testid="nx-button"
    >
      @if (loading()) {
        <mat-icon class="nx-btn__spinner" aria-hidden="true">sync</mat-icon>
      }
      @if (leadingIcon() && !loading()) {
        <mat-icon aria-hidden="true">{{ leadingIcon() }}</mat-icon>
      }
      <span class="nx-btn__label"><ng-content /></span>
      @if (trailingIcon()) {
        <mat-icon aria-hidden="true">{{ trailingIcon() }}</mat-icon>
      }
    </button>
  `,
  styleUrl: './button.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxButton {
  /**
   * Visual variant that determines button color and style.
   *
   * - `'primary'` — default action (blue)
   * - `'secondary'` — alternative action (gray)
   * - `'tertiary'` — low-emphasis action (outlined)
   * - `'danger'` — destructive action (red) — use only for delete/logout/irreversible ops
   * - `'ghost'` — minimal style, text only (for toolbar/inline contexts)
   * - `'inverse'` — contrast variant for dark backgrounds
   *
   * @default 'primary'
   */
  readonly variant = input<ButtonVariant>('primary');

  /**
   * Spatial sizing of the button, affecting padding and font-size.
   *
   * - `'sm'` — small, 32px height (compact UI, secondary actions)
   * - `'md'` — medium, 40px height (default, recommended for most use cases)
   * - `'lg'` — large, 48px height (primary CTA, mobile-friendly)
   *
   * @default 'md'
   */
  readonly size = input<ButtonSize>('md');

  /**
   * Native HTML button type, controlling form submission behavior.
   *
   * - `'button'` — standard button (no form submission)
   * - `'submit'` — submits the nearest `<form>`
   * - `'reset'` — clears form inputs
   *
   * @default 'button'
   */
  readonly type = input<'button' | 'submit' | 'reset'>('button');

  /**
   * Whether the button is disabled and non-interactive.
   *
   * When true:
   * - Click events are not fired
   * - Keyboard navigation (Tab) skips the button
   * - Cursor appears as `not-allowed`
   * - Visual opacity reduced to show disabled state
   *
   * @default false
   */
  readonly disabled = input(false);

  /**
   * Whether the button is in a loading/processing state.
   *
   * When true:
   * - A spinning icon replaces the `leadingIcon`
   * - The button may become disabled (via parent logic)
   * - `aria-busy="true"` is set for assistive tech
   * - Typically used during async operations (API calls, form submission)
   *
   * @default false
   */
  readonly loading = input(false);

  /**
   * Whether the button fills its container width (100%).
   *
   * Useful for:
   * - Mobile layouts (full-width CTAs)
   * - Form buttons spanning a column
   * - Stack in vertical layouts
   *
   * @default false
   */
  readonly fullWidth = input(false);

  /**
   * Material Design icon name to display before the button label.
   *
   * - Icon is hidden when `loading()` is true (replaced by spinner)
   * - Icon is marked `aria-hidden="true"` (label provides context)
   * - Only rendered if non-empty string
   *
   * @example `leadingIcon="save"` renders the Material `save` icon
   * @default '' (no icon)
   */
  readonly leadingIcon = input<string>('');

  /**
   * Material Design icon name to display after the button label.
   *
   * - Always visible (not replaced during loading)
   * - Common for indicating navigation direction (e.g. `arrow_forward`)
   * - Marked `aria-hidden="true"` (label provides context)
   * - Only rendered if non-empty string
   *
   * @example `trailingIcon="arrow_forward"` renders the trailing chevron
   * @default '' (no icon)
   */
  readonly trailingIcon = input<string>('');

  /**
   * ARIA label for assistive technologies (screen readers, voice control).
   *
   * Use when:
   * - Button is icon-only (no visible text label)
   * - Visible text is ambiguous (e.g. generic "Edit")
   * - Additional context needed beyond the label
   *
   * If omitted, the button's text content is used as the implicit ARIA label.
   *
   * @example `ariaLabel="Delete user account permanently"` for a trash icon button
   * @default '' (use visible text label)
   */
  readonly ariaLabel = input<string>('');

  /**
   * Emitted when the button is clicked by user action (pointer, keyboard, or touch).
   *
   * The output fires *after* the browser's click event handlers, so DOM updates
   * from (click) bindings occur before clicked emits.
   *
   * @returns void — no value is emitted
   *
   * @example
   * ```html
   * <nx-button (clicked)="handleClick()">Click me</nx-button>
   * ```
   */
  readonly clicked = output<void>();

  /**
   * Builds the CSS class string for the button element.
   *
   * Combines base class (`nx-btn`) with variant and size modifiers,
   * plus a loading modifier when in loading state. Classes are whitespace-separated.
   *
   * @returns CSS class string applied to the native `<button>` element
   * @internal
   */
  protected buttonClass(): string {
    return [
      'nx-btn',
      `nx-btn--${this.variant()}`,
      `nx-btn--${this.size()}`,
      this.loading() ? 'nx-btn--loading' : '',
    ]
      .filter(Boolean)
      .join(' ');
  }
}
