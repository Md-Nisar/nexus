import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';
import { ThemeService } from './core/theme.service';

/**
 * Root component of the Nexus Frontend application.
 *
 * Responsibilities:
 * - Renders the main application layout (header/nav, router outlet, footer)
 * - Manages global theme toggle (dark/light mode) via ThemeService
 * - Provides router outlet for feature routes
 * - Enforces OnPush change detection for performance
 *
 * Architecture:
 * - Uses standalone component API (no NgModule required)
 * - Dependency injection: ThemeService for theme management
 * - Imports: RouterOutlet (for nested routes), RouterLink (for navigation)
 *
 * Signals and computed values:
 * - title: Static display name for the application
 * - themeService: Injected service managing theme state (dark/light)
 * - themeIcon: Computed Material icon name based on current theme
 * - themeLabel: Computed ARIA label for theme toggle button
 *
 * Template integration:
 * The template (app.html) uses:
 * - [title] for app name display
 * - [themeIcon] and [themeLabel] for the theme toggle button
 * - Router outlet directives for nested component rendering
 *
 * Performance note:
 * OnPush change detection ensures the component only checks for changes when:
 * - @Input properties change
 * - Event handlers fire (click, submit, etc.)
 * - Signals/observables emit new values
 * This improves performance on fast-changing UIs.
 *
 * @see {@link ThemeService} for theme management implementation
 * @see {@link app.config.ts} for application bootstrap configuration
 * @see app.html for the template layout
 * @see app.scss for styling (theming via CSS data-theme attribute)
 */
@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink],
  templateUrl: './app.html',
  styleUrl: './app.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class App {
  /**
   * Application display title (static constant).
   * Used in the app header and browser title context.
   *
   * @example
   * In template: {{ title() }}
   */
  protected readonly title = signal('nexus-frontend');

  /**
   * Injected theme service managing dark/light mode state and persistence.
   * Provides the readonly signal {@link ThemeService.theme} that subscribers
   * (computed, effect, etc.) track for reactive theme changes.
   *
   * Integration note:
   * ThemeService is instantiated once at app bootstrap and reused across
   * the entire application. Its signal-based API ensures theme changes
   * propagate to all subscribers without manual subscription management.
   *
   * @see {@link ThemeService} for implementation details
   */
  protected readonly themeService = inject(ThemeService);

  /**
   * Computed Material icon name for the theme toggle button.
   * Automatically updates when {@link ThemeService.theme} changes.
   *
   * Logic:
   * - Dark theme → show 'light_mode' icon (clicking switches to light)
   * - Light theme → show 'dark_mode' icon (clicking switches to dark)
   *
   * Complex logic note:
   * This computed signal depends on themeService.theme(), which is itself
   * a signal. Angular automatically tracks this dependency, so whenever
   * the theme changes, themeIcon is recomputed before the next render.
   * Change detection runs only because of the signal change, respecting OnPush.
   *
   * @example
   * In template: <mat-icon>{{ themeIcon() }}</mat-icon>
   */
  protected readonly themeIcon = computed(() =>
    this.themeService.theme() === 'dark' ? 'light_mode' : 'dark_mode',
  );

  /**
   * Computed ARIA label for the theme toggle button (accessibility).
   * Automatically updates when {@link ThemeService.theme} changes.
   *
   * Purpose:
   * Screen readers announce this label, providing context for users with
   * visual impairments. The label always describes the action that will
   * happen on click (e.g., "Switch to light mode" when in dark theme).
   *
   * Complex logic note:
   * Like {@link themeIcon}, this computed value tracks themeService.theme()
   * automatically, ensuring the label stays in sync with the current theme
   * and icon.
   *
   * @example
   * In template: <button [attr.aria-label]="themeLabel()">
   */
  protected readonly themeLabel = computed(() =>
    this.themeService.theme() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode',
  );
}
