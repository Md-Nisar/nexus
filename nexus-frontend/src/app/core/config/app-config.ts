import { InjectionToken } from '@angular/core';
import { environment } from '../../../environments/environment';

/**
 * Log level type for controlling verbosity of LoggerService output.
 *
 * Levels in order of increasing severity:
 * - 'debug' (0): Detailed diagnostic information for troubleshooting
 * - 'info' (1): General informational messages about application flow
 * - 'warn' (2): Warning messages for potentially problematic situations
 * - 'error' (3): Error messages for failures that need immediate attention
 *
 * @example
 * // Production typically uses 'warn', development uses 'debug'
 * logLevel: 'debug' // in development
 * logLevel: 'warn'  // in production
 *
 * @note The numeric ordering (0-3) is used in LoggerService for level comparison.
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Application configuration interface.
 *
 * This interface defines all environment-dependent settings that control
 * application behavior. All properties are readonly to prevent accidental mutation.
 *
 * @note
 * - Do not add mutable state here; use services for that (e.g., ThemeService for theme)
 * - All values are resolved at application startup from environment files
 * - Tests can provide custom AppConfig via the APP_CONFIG token factory
 */
export interface AppConfig {
  /**
   * Indicates if the application is running in production mode.
   * - true: Production (optimized, less logging, minified assets)
   * - false: Development (verbose logging, source maps, debugging tools)
   *
   * @example
   * if (config.production) {
   *   disableDebugPanel();
   * }
   */
  readonly production: boolean;

  /**
   * Base URL for all backend API requests.
   * Feature code should use HttpClient with this as the base, never hardcode URLs.
   *
   * @example
   * // Development: 'http://localhost:1000'
   * // Production: 'https://api.example.com'
   *
   * @note
   * Services should prefix this with relative paths:
   * this.http.post(`${this.config.apiBaseUrl}/api/auth/login`, payload)
   */
  readonly apiBaseUrl: string;

  /**
   * Minimum log level for LoggerService.
   * Messages below this level are suppressed; see {@link LogLevel} for level ordering.
   *
   * @example
   * // Development: 'debug' (all messages shown)
   * // Production: 'warn' (debug and info messages hidden)
   *
   * @see LoggerService for how this value is used
   */
  readonly logLevel: LogLevel;

  /**
   * Optional "contact your administrator" link shown on the Access Denied page.
   * `null` hides the link; no placeholder ships. Consumers must pass the value through
   * {@link parseSupportContact}, which accepts only `mailto:` and `https://` hrefs.
   * The real value is a product decision (US-019 Q-N5).
   */
  readonly supportContact: SupportContact | null;
}

/** A labelled contact link. */
export interface SupportContact {
  readonly label: string;
  readonly href: string;
}

// eslint-disable-next-line no-control-regex
const SAFE_HREF = /^(?:mailto:|https:\/\/)[^\s\u0000-\u0008\u000e-\u001f\u007f]+$/i;

/**
 * Validates a configured support contact.
 *
 * @returns the contact when its `href` is a `mailto:` or `https://` URL without whitespace or
 *   control characters and its label is non-empty; otherwise `null` (the link stays hidden).
 * @security Blocks `javascript:`, `data:`, `ftp:` and scheme-relative values from configuration.
 */
export function parseSupportContact(raw: SupportContact | null | undefined): SupportContact | null {
  if (!raw || typeof raw.label !== 'string' || typeof raw.href !== 'string') return null;
  if (raw.label.trim().length === 0) return null;
  return SAFE_HREF.test(raw.href) ? raw : null;
}

/**
 * Single injection point for application configuration.
 *
 * Architecture note:
 * Feature code injects this token instead of importing environment files directly.
 * This decouples the application from the environment module and enables:
 * - Dependency injection for testing (tests provide their own AppConfig)
 * - Configuration override in specs
 * - Loose coupling to the environments/ directory structure
 *
 * @example
 * // In a feature service:
 * export class AuthService {
 *   private readonly config = inject(APP_CONFIG);
 *
 *   login(credentials: Credentials): Observable<LoginResponse> {
 *     return this.http.post(`${this.config.apiBaseUrl}/auth/login`, credentials);
 *   }
 * }
 *
 * // In a test, override config:
 * TestBed.overrideProvider(APP_CONFIG, {
 *   useValue: { production: false, apiBaseUrl: 'http://localhost:4200', logLevel: 'debug' }
 * });
 *
 * @note
 * Signals/Computed:
 * - This is a static injection token, not a signal
 * - If you need reactive config changes, use a service with signals instead
 * - Current use case (static environment config) does not require reactivity
 */
export const APP_CONFIG = new InjectionToken<AppConfig>('APP_CONFIG', {
  providedIn: 'root',
  factory: (): AppConfig => environment,
});
