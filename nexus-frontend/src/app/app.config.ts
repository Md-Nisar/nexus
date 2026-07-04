import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideHttpClient, withInterceptors, withXhr } from '@angular/common/http';
import { provideRouter, withComponentInputBinding } from '@angular/router';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';

import { routes } from './app.routes';
import { correlationIdInterceptor } from './core/http/correlation-id.interceptor';
import { apiErrorInterceptor } from './core/http/api-error.interceptor';
import { authInterceptor } from './core/http/auth.interceptor';

/**
 * Application-wide dependency injection and feature configuration.
 *
 * This configuration object is passed to {@link bootstrapApplication} in main.ts.
 * It registers all providers (services, interceptors, routes, features) needed for
 * the entire application lifecycle.
 *
 * Provider registration order matters:
 * 1. Error listeners (browser-level error handling)
 * 2. Router (establishes navigation)
 * 3. HTTP client with interceptors (request/response pipeline)
 * 4. Animations (async initialization for better performance)
 *
 * Integration notes:
 * - All providers are singletons scoped to the root injector
 * - Interceptors are executed in order: correlation-id → api-error → auth
 * - Routes are lazy-loaded per feature; see {@link routes} for route definitions
 * - Animations use async initialization to prevent blocking the main thread
 *
 * @see {@link routes} for the route configuration
 * @see {@link main.ts} where this config is passed to bootstrapApplication
 * @see {@link App} root component that uses these providers
 */
export const appConfig: ApplicationConfig = {
  providers: [
    /**
     * Global error listener (window.onerror handler).
     * Captures uncaught errors in the browser's global scope.
     * Useful for catching errors in event handlers, setTimeout, etc.
     *
     * Integration note:
     * Errors are logged to the browser console. In production, you may want
     * to send these to an error tracking service (Sentry, etc.).
     */
    provideBrowserGlobalErrorListeners(),

    /**
     * Router configuration and setup.
     *
     * withComponentInputBinding():
     * - Allows route params to be passed as @Input properties to components
     * - Example: route /user/:id automatically binds the 'id' param to
     *   a component's @Input() id property
     * - Simplifies component APIs by eliminating ActivatedRoute.params subscriptions
     *
     * Integration note:
     * Routes are defined separately in app.routes.ts for easier feature organization.
     * Feature routes are lazy-loaded to reduce initial bundle size.
     */
    provideRouter(routes, withComponentInputBinding()),

    /**
     * HTTP client configuration with interceptors.
     *
     * withXhr():
     * - Explicitly enables the XHR-based HTTP backend (XMLHttpRequest API)
     * - Required for projects not using fetch-based backends
     * - Ensures compatibility with older environments
     *
     * withInterceptors([...]):
     * Registers HTTP interceptors that transform requests and responses.
     * Interceptors are invoked in the order listed:
     *
     * 1. {@link correlationIdInterceptor}
     *    - Attaches a unique correlation-id header to each request
     *    - Enables end-to-end request tracing (frontend → backend → logs)
     *    - Used by the backend for log aggregation and debugging
     *
     * 2. {@link apiErrorInterceptor}
     *    - Transforms HTTP error responses into typed AppError objects
     *    - Components receive AppError (never raw HttpErrorResponse)
     *    - Handles common error scenarios: 4xx, 5xx, network timeouts
     *
     * 3. {@link authInterceptor}
     *    - Attaches access token to all Nexus API requests (Bearer token)
     *    - Implements proactive token refresh (2 min before expiry)
     *    - Handles reactive refresh on 401 responses
     *    - Prevents token leakage to third-party origins (only Nexus API)
     *
     * Execution order ensures correlation IDs are set first (tracing context),
     * followed by error transformation, then auth token attachment.
     *
     * Security note:
     * The auth interceptor validates request origin before attaching tokens,
     * preventing accidental token leakage to third-party CDNs or resources.
     *
     * Integration note:
     * See {@link auth.interceptor.ts} for token refresh deduplication logic
     * and cross-tab safety guarantees.
     */
    provideHttpClient(
      withXhr(),
      withInterceptors([correlationIdInterceptor, apiErrorInterceptor, authInterceptor]),
    ),

    /**
     * Angular animations module (async initialization).
     *
     * provideAnimationsAsync():
     * - Loads the BrowserAnimationsModule asynchronously
     * - Defers animation feature initialization until after first render
     * - Improves initial page load performance (critical for First Contentful Paint)
     * - Material components still work during async initialization
     *
     * Integration note:
     * If animations are needed immediately, use provideAnimations() instead.
     * For most modern SPAs, async initialization is preferred for better
     * Lighthouse scores and faster time-to-interactive.
     */
    provideAnimationsAsync(),
  ],
};
