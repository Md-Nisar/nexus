import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';

/**
 * Empty state presentation component for data-empty contexts.
 *
 * Displays a centered, visually prominent empty state with optional icon,
 * title, description, and action slot. Commonly used when a list, table,
 * or search result yields no data. Automatically marks itself as a status
 * region for assistive technologies.
 *
 * Use `NxEmptyState` when:
 * - A list/table has zero items after load (not while loading)
 * - A search yields no results
 * - A feature is not yet configured or enabled
 *
 * Use `NxErrorState` instead when:
 * - Load failed (network error, server 5xx, etc.)
 *
 * @example
 * // Basic empty list
 * @if (!items(); else showList) {
 *   <nx-empty-state
 *     icon="inbox"
 *     title="No messages"
 *     description="Your inbox is empty. Create a new message to get started."
 *   >
 *     <button nx-button variant="primary" (click)="openCompose()">
 *       Compose message
 *     </button>
 *   </nx-empty-state>
 * }
 * @template #showList { ... }
 *
 * @example
 * // Search-specific empty state
 * @if (searchResults().length === 0 && hasSearched()) {
 *   <nx-empty-state
 *     icon="search"
 *     title="No results for "{{ searchTerm() }}""
 *     description="Try different keywords or filters."
 *   />
 * }
 *
 * @example
 * // Feature not enabled
 * <nx-empty-state
 *   icon="settings"
 *   title="Feature not configured"
 *   description="Configure this feature in settings to get started."
 * >
 *   <a nx-button variant="secondary" routerLink="/settings">Go to settings</a>
 * </nx-empty-state>
 *
 * @accessibility
 * - Root element has `role="status"` to announce empty state to screen readers
 * - Icon marked as `aria-hidden="true"` (decorative; message conveyed by text)
 * - Title is visually largest; screen readers consume it as status message
 * - Description provides context; use it liberally for clarity
 * - Action slot (ng-content) should contain semantic `<button>` or `<a>` elements,
 *   never `<div>` with click handlers
 * - Status role automatically announces when inserted (no need for aria-live)
 *
 * @ux-notes
 * - Component is centered with generous vertical padding; works well in full-height
 *   containers (e.g., page-height lists, dashboard panels)
 * - Icon defaults to Material "inbox" for generic empty state; customize for context
 *   (e.g., "search" for search results, "settings" for unconfigured features)
 * - Description is optional but recommended; provides reasoning and next steps
 * - Action slot (ng-content) is typically a single button or link; keep CTAs obvious
 * - Avoid using empty state for loading states; use a spinner component instead
 * - If showing empty state conditionally, ensure surrounding context is clear
 *   (e.g., "No tasks" vs. "No tasks in the selected project")
 *
 * @see {@link NxErrorState} for error/failure states
 * @see Material 3 empty state patterns for design reference
 */
@Component({
  selector: 'nx-empty-state',
  standalone: true,
  imports: [MatIconModule],
  template: `
    <div class="nx-empty-state" role="status" data-testid="nx-empty-state">
      @if (icon()) {
        <mat-icon class="nx-empty-state__icon" aria-hidden="true">{{ icon() }}</mat-icon>
      }
      <p class="nx-empty-state__title">{{ title() }}</p>
      @if (description()) {
        <p class="nx-empty-state__description">{{ description() }}</p>
      }
      <div class="nx-empty-state__action">
        <ng-content />
      </div>
    </div>
  `,
  styleUrl: './empty-state.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxEmptyState {
  /**
   * Material icon name displayed above the title.
   * Use context-appropriate icons:
   * - `inbox` (default) — generic empty state
   * - `search` — search results empty
   * - `settings` — unconfigured feature
   * - `event` — calendar/timeline empty
   * - `person_add` — no connections/contacts
   * - `star` — no favorites/saved items
   * Icon is marked decorative; message is conveyed by title/description.
   * @default 'inbox'
   */
  readonly icon = input<string>('inbox');

  /**
   * Required title text displayed in large, bold typography.
   * Announces the empty state to screen readers via `role="status"`.
   * Keep concise (2–5 words); use description for details.
   * @example "No messages"
   * @example "No search results"
   * @example "Feature not configured"
   */
  readonly title = input.required<string>();

  /**
   * Optional description text providing context and next steps.
   * Displayed below title in secondary text color.
   * Use for reasoning ("Your inbox is empty") or guidance
   * ("Create a new message to get started").
   * When empty string, the description paragraph is not rendered.
   * @default ''
   * @example "Your inbox is empty. Create a new message to get started."
   */
  readonly description = input<string>('');

  /**
   * Optional action content slot (ng-content).
   * Typically contains a single button or link (e.g., "Create new item", "Go back").
   * Examples:
   * - `<button nx-button (click)="create()">Create new</button>`
   * - `<a nx-button routerLink="/settings">Configure</a>`
   * - `<ng-container><!-- Custom recovery UI --></ng-container>`
   *
   * Use semantic elements only; avoid generic divs with click handlers.
   * If no action is needed, omit ng-content entirely.
   */
  // ng-content is not a field but documented here for completeness
}
