import { Service, signal } from '@angular/core';

/**
 * Supported theme modes for the application.
 * - 'dark': Dark theme with high-contrast colors
 * - 'light': Light theme with low-contrast colors
 */
export type Theme = 'dark' | 'light';

/**
 * localStorage key for persisting theme selection across sessions.
 */
const STORAGE_KEY = 'nx-theme';

/**
 * Manages application theme state and persistence.
 *
 * This service:
 * - Maintains the current theme as a signal
 * - Persists theme selection to localStorage for session recovery
 * - Synchronizes the DOM data-theme attribute for CSS-based styling
 *
 * @example
 * constructor(private themeService: ThemeService) {
 *   effect(() => {
 *     console.log('Theme changed to:', this.themeService.theme());
 *   });
 * }
 *
 * toggleTheme() {
 *   this.themeService.toggle();
 * }
 *
 * @note
 * Signals used:
 * - _theme (private writable signal): holds the current theme state
 * - theme (public readonly signal): read-only view of the current theme
 *
 * Side effects:
 * - Constructor mutates DOM: sets data-theme attribute on <html> element
 * - toggle() mutates DOM and localStorage for persistence
 * - These side effects are necessary for CSS-in-JS theming systems to work
 */
@Service()
export class ThemeService {
  /**
   * Writable signal holding the current theme state.
   * Initialized from localStorage or defaults to 'dark'.
   *
   * @internal Use the readonly {@link theme} signal instead for read access.
   */
  private readonly _theme = signal<Theme>(this.initialTheme());

  /**
   * Public readonly signal for the current theme.
   * Subscribers (via effect() or computed()) automatically react to changes.
   *
   * @example
   * const isDark = computed(() => this.themeService.theme() === 'dark');
   * const currentTheme = this.themeService.theme(); // read current value
   */
  readonly theme = this._theme.asReadonly();

  /**
   * Initializes the theme service and sets up the initial theme in the DOM.
   *
   * Complex logic note:
   * - Reads localStorage immediately to recover user's previous selection
   * - Sets DOM attribute synchronously so CSS is applied before first render
   * - This prevents a visual "flash" of the wrong theme on page load
   */
  constructor() {
    document.documentElement.dataset['theme'] = this._theme();
  }

  /**
   * Toggles between dark and light themes, persisting the choice.
   *
   * Side effects:
   * - Updates the internal _theme signal (triggers effect/computed subscribers)
   * - Updates DOM data-theme attribute (CSS responds immediately)
   * - Saves new theme to localStorage (survives page reload)
   *
   * @example
   * this.themeService.toggle(); // dark → light, or light → dark
   */
  toggle(): void {
    const next: Theme = this._theme() === 'dark' ? 'light' : 'dark';
    this._theme.set(next);
    document.documentElement.dataset['theme'] = next;
    localStorage.setItem(STORAGE_KEY, next);
  }

  /**
   * Resolves the initial theme from localStorage, with fallback to dark.
   *
   * Complex logic note:
   * - Validates localStorage value strictly: only 'light' or 'dark' are accepted
   * - Rejects null, undefined, or invalid strings (e.g. from corrupted storage)
   * - Defaults to 'dark' for any invalid or missing value
   * - This guards against type errors and provides a sensible default UX
   *
   * @returns The initial theme: stored value (if valid) or 'dark' (fallback)
   */
  private initialTheme(): Theme {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') return stored;
    return 'dark';
  }
}
