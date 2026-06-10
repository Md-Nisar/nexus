/**
 * Production environment. The development variant replaces this file via
 * `fileReplacements` in angular.json. Access values through APP_CONFIG — never
 * import this file from feature code.
 */
export const environment = {
  production: true,
  apiBaseUrl: '/api',
  logLevel: 'warn',
} as const;
