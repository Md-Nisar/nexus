/**
 * Production environment configuration.
 *
 * This file defines environment-specific settings for production deployments.
 * The development variant ({@link environment.development.ts}) replaces this file
 * via `fileReplacements` in angular.json during builds.
 *
 * **Important:** Access values through `APP_CONFIG` — never import this file directly
 * from feature code. This ensures proper environment switching and enables testing.
 *
 * @example
 * // ✅ Correct: inject APP_CONFIG
 * constructor(private config: AppConfig) {
 *   this.apiUrl = this.config.apiBaseUrl;
 * }
 *
 * @example
 * // ❌ Wrong: direct import
 * import { environment } from './environment';  // Don't do this
 *
 * @see {@link APP_CONFIG} Angular DI token in `core/config/app-config.ts`
 * @see angular.json `fileReplacements` configuration
 */
export const environment = {
  /**
   * Indicates this is a production build.
   *
   * @type {boolean}
   * @default true
   */
  production: true,

  /**
   * Base URL for backend API requests.
   *
   * In production, requests are served from the same origin (`/api` relative path),
   * leveraging same-origin policy for enhanced security.
   *
   * @type {string}
   * @default '/api'
   */
  apiBaseUrl: '/api',

  /**
   * Log level for runtime logging.
   *
   * Controls verbosity of application logs. In production, set to `'warn'`
   * to reduce log volume and avoid exposing sensitive debugging information.
   *
   * Supported levels: `'debug'` | `'info'` | `'warn'` | `'error'`
   *
   * @type {string}
   * @default 'warn'
   */
  logLevel: 'warn',
} as const;
