/**
 * Development environment configuration.
 *
 * This file defines environment-specific settings for local development.
 * It replaces {@link environment.ts} during builds via `fileReplacements`
 * in angular.json.
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
 * import { environment } from './environment.development';  // Don't do this
 *
 * @see {@link APP_CONFIG} Angular DI token in `core/config/app-config.ts`
 * @see angular.json `fileReplacements` configuration
 */
export const environment = {
  /**
   * Indicates this is a development build.
   *
   * @type {boolean}
   * @default false
   */
  production: false,

  /**
   * Base URL for backend API requests.
   *
   * In development, points to the local backend server running on port 1000.
   * Allows testing against a locally running Spring Boot instance.
   *
   * @type {string}
   * @default 'http://localhost:1000/api'
   */
  apiBaseUrl: 'http://localhost:1000/api',

  /**
   * Log level for runtime logging.
   *
   * Controls verbosity of application logs. In development, set to `'debug'`
   * to enable detailed logging for troubleshooting and development.
   *
   * Supported levels: `'debug'` | `'info'` | `'warn'` | `'error'`
   *
   * @type {string}
   * @default 'debug'
   */
  logLevel: 'debug',
} as const;
