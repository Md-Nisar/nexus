import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { MatCardModule } from '@angular/material/card';

/**
 * Container component for grouping related content with semantic structure and optional header/footer.
 *
 * `<nx-card>` wraps Angular Material's `<mat-card>` with Nexus design tokens
 * to provide a unified card experience across the application. It supports three elevation
 * levels for visual hierarchy and includes optional title, subtitle, header actions, and footer actions.
 *
 * ## Features
 * - Three elevation variants: flat, raised, outlined
 * - Optional semantic title and subtitle
 * - Header action slot (right-aligned, typically for edit/menu buttons)
 * - Content area for the main card body
 * - Footer action slot (right-aligned, typically for primary/secondary actions)
 * - ARIA labeling for semantic clarity
 *
 * @example
 * Basic card with title and content:
 * ```html
 * <nx-card title="User Profile">
 *   <p>John Doe (john@example.com)</p>
 * </nx-card>
 * ```
 *
 * @example
 * Card with header and footer actions:
 * ```html
 * <nx-card
 *   title="Project Details"
 *   subtitle="Active Project"
 *   elevation="raised"
 *   ariaLabel="Project information and controls"
 * >
 *   <p>This project contains important files...</p>
 *
 *   <button slot="header-actions" mat-icon-button>
 *     <mat-icon>more_vert</mat-icon>
 *   </button>
 *
 *   <nx-button slot="actions" variant="primary">
 *     View Details
 *   </nx-button>
 *   <nx-button slot="actions" variant="secondary">
 *     Archive
 *   </nx-button>
 * </nx-card>
 * ```
 *
 * @slots
 * - `(default)` — main card content, placed in `<mat-card-content>`
 * - `[slot="header-actions"]` — action controls (icons/buttons) displayed right-aligned in header
 * - `[slot="actions"]` — footer action buttons, displayed right-aligned in `<mat-card-actions>`
 *
 * @design-system
 * Uses token families:
 * - `--nx-color-surface` and `--nx-color-surface-variant` — background colors
 * - `--nx-color-outline` — optional border for outlined elevation
 * - `--nx-shadow-*` — elevation shadows (sm/md/lg; disabled in dark mode via outline fallback)
 * - `--nx-space-md` / `--nx-space-lg` — padding and margins
 * - `--nx-radius-lg` — border-radius for card corners
 * - `--nx-text-body` / `--nx-text-title` — typography hierarchy
 *
 * All visual properties are token-driven; never override with inline styles.
 *
 * @accessibility
 * - Optional `ariaLabel` input provides semantic labeling for screen readers
 * - Title text (if present) implicitly provides an accessible name
 * - Typography hierarchy (title/subtitle) allows keyboard navigation via heading structure
 * - Outline elevation improves visibility for users with contrast sensitivity or color blindness
 * - Content within card inherits document flow semantics (form fields, links, etc.)
 * - No focus management required; card is not interactive (actions are in buttons)
 */
export type CardElevation = 'flat' | 'raised' | 'outlined';

@Component({
  selector: 'nx-card',
  standalone: true,
  imports: [MatCardModule],
  template: `
    <mat-card [class]="cardClass()" [attr.aria-label]="ariaLabel() || null" data-testid="nx-card">
      @if (title() || subtitle()) {
        <mat-card-header>
          @if (title()) {
            <mat-card-title>{{ title() }}</mat-card-title>
          }
          @if (subtitle()) {
            <mat-card-subtitle>{{ subtitle() }}</mat-card-subtitle>
          }
          <div class="nx-card__header-actions">
            <ng-content select="[slot=header-actions]" />
          </div>
        </mat-card-header>
      }
      <mat-card-content>
        <ng-content />
      </mat-card-content>
      <mat-card-actions align="end">
        <ng-content select="[slot=actions]" />
      </mat-card-actions>
    </mat-card>
  `,
  styleUrl: './card.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxCard {
  /**
   * Main heading text displayed in the card header (semantic h3 level).
   *
   * - Rendered as `<mat-card-title>` if non-empty
   * - Omitting this input hides the entire header section (including subtitle)
   * - Provide semantic context for the card's content
   * - Text is wrapped in Material card title styles
   *
   * @default '' (no title rendered; header section hidden)
   *
   * @example
   * ```html
   * <nx-card title="Billing Information">
   *   <!-- content -->
   * </nx-card>
   * ```
   */
  readonly title = input<string>('');

  /**
   * Subheading text displayed below the title (semantic h4 level).
   *
   * - Rendered as `<mat-card-subtitle>` if non-empty
   * - Only renders if `title` is also set (subtitle alone does not show header)
   * - Use for status, date, or contextual metadata
   * - Text is wrapped in Material card subtitle styles (lighter color, smaller font)
   *
   * @default '' (no subtitle rendered)
   *
   * @example
   * ```html
   * <nx-card title="Recent Orders" subtitle="Last 30 days">
   *   <!-- content -->
   * </nx-card>
   * ```
   */
  readonly subtitle = input<string>('');

  /**
   * Visual elevation/depth treatment controlling card prominence and shadow style.
   *
   * - `'raised'` — `--nx-shadow-md` applied; card lifts above background (default, recommended)
   *   Use for primary content, standalone cards, or cards that need visual prominence
   *
   * - `'flat'` — `--nx-shadow-none` applied; no drop shadow
   *   Use for list items, grid items, or tight/nested layouts where stacking is implicit
   *
   * - `'outlined'` — Hairline border on `--nx-color-outline`; no shadow
   *   Use for high-contrast contexts, users with contrast sensitivity, or dark backgrounds
   *
   * In dark mode, shadows are disabled; depth is achieved via surface color lift + hairline outline.
   *
   * @default 'raised'
   *
   * @example
   * ```html
   * <!-- Primary card (prominent) -->
   * <nx-card elevation="raised">...</nx-card>
   *
   * <!-- List item card (compact) -->
   * <nx-card elevation="flat">...</nx-card>
   *
   * <!-- High-contrast variant (accessibility) -->
   * <nx-card elevation="outlined">...</nx-card>
   * ```
   */
  readonly elevation = input<CardElevation>('raised');

  /**
   * ARIA label for the card container element.
   *
   * Use to provide semantic context when:
   * - The card's purpose is not obvious from its title/content alone
   * - The card is part of a grid/list of similar cards (helps differentiate them)
   * - The card contains interactive controls but no visible heading
   * - Screen reader users need additional context
   *
   * If omitted, the card title (if present) serves as the implicit label.
   *
   * @default '' (use implicit title or content labels)
   *
   * @example
   * ```html
   * <nx-card ariaLabel="User account settings and preferences">
   *   <!-- complex settings form -->
   * </nx-card>
   * ```
   */
  readonly ariaLabel = input<string>('');

  /**
   * Builds the CSS class string for the card host element.
   *
   * Combines the base class (`nx-card`) with the elevation modifier
   * (e.g. `nx-card--raised`, `nx-card--outlined`).
   *
   * @returns CSS class string applied to the `<mat-card>` host
   * @internal
   */
  protected cardClass(): string {
    return `nx-card nx-card--${this.elevation()}`;
  }
}
