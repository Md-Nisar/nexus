import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';

/**
 * Application route definitions.
 *
 * This module exports the root route configuration for the Nexus Frontend.
 * Routes are lazy-loaded by feature to minimize initial bundle size.
 *
 * Route architecture:
 * - Each feature (auth, dashboard) is loaded only when its route is activated
 * - Child routes within features are defined in feature-specific route modules
 *   (e.g., features/auth/auth.routes.ts)
 * - Guards (authGuard) protect routes that require authentication
 *
 * Lazy-loading benefits:
 * - Initial bundle includes only essential code (main app shell)
 * - Feature bundles are downloaded on-demand when the user navigates
 * - Reduces Time-to-Interactive (TTI) for initial page load
 *
 * Integration notes:
 * - Router is configured in {@link appConfig} with {@link withComponentInputBinding}
 * - All routes are standalone components (no ngModule required)
 * - Feature routes can be found in features/<feature-name>/
 *
 * @see {@link authGuard} for authentication protection logic
 * @see {@link app.config.ts} where these routes are registered
 */
export const routes: Routes = [
  /**
   * Authentication feature routes.
   *
   * Path: /auth
   * Access: Public (unauthenticated users)
   * Child routes: login, register, forgot-password, reset-password, verify-email, etc.
   *
   * Implementation:
   * - Lazy-loaded child routes from features/auth/auth.routes.ts
   * - Contains all authentication-related pages and flows
   * - No guard required (public feature)
   * - Child routes define their own paths and components
   *
   * Navigation examples:
   * - /auth/login → login form
   * - /auth/register → registration form
   * - /auth/forgot-password → forgot password request
   * - /auth/reset-password?token=xyz → password reset with token
   *
   * Integration note:
   * The auth feature must not import dashboard or other protected features
   * to avoid circular dependencies and ensure proper code splitting.
   */
  {
    path: 'auth',
    loadChildren: () => import('./features/auth/auth.routes').then((m) => m.AUTH_ROUTES),
  },

  /**
   * Design system preview and component showcase.
   *
   * Path: /design-system
   * Access: Public
   * Component: DesignSystemPreviewComponent
   *
   * Purpose:
   * - Displays all Material 3 components and Nexus design tokens in action
   * - Serves as a living documentation for frontend developers
   * - Useful for visual regression testing and design reviews
   * - Can be hidden behind a feature flag in production if needed
   *
   * Implementation:
   * - Lazy-loaded component (downloaded only if user navigates to it)
   * - Standalone component, no routes or children
   * - No guard protection (public, but internal tool)
   *
   * Integration note:
   * This route is typically used by developers during development.
   * In production, consider removing or gating behind an internal-only
   * feature flag to reduce bundle exposure.
   */
  {
    path: 'design-system',
    loadComponent: () =>
      import('./features/design-system/design-system-preview.component').then(
        (m) => m.DesignSystemPreviewComponent,
      ),
  },

  /**
   * Main dashboard (protected by authentication guard).
   *
   * Path: /dashboard
   * Access: Authenticated users only
   * Guard: {@link authGuard}
   * Component: DashboardComponent
   *
   * Purpose:
   * - Primary application interface for authenticated users
   * - Displays user's main workspace and key information
   * - Landing page after successful login
   *
   * Authentication flow:
   * - canActivate: [authGuard] checks if user has a valid session
   * - If authenticated: component is loaded and displayed
   * - If not authenticated: authGuard redirects to /auth/login
   *
   * Implementation:
   * - Lazy-loaded component (downloaded when user authenticates)
   * - Standalone component, no child routes in this definition
   * - Dashboard feature may define sub-routes for analytics, settings, etc.
   *
   * Integration note:
   * The authGuard checks the AuthStore for a valid session token.
   * If the token is expired, the HTTP interceptors handle refresh or
   * redirect to login. See {@link auth.interceptor.ts} for details.
   *
   * @see {@link authGuard} for the authentication check implementation
   * @see {@link auth.interceptor.ts} for token refresh and expiry handling
   */
  {
    path: 'dashboard',
    canActivate: [authGuard],
    loadComponent: () =>
      import('./features/dashboard/dashboard.component').then((m) => m.DashboardComponent),
  },

  /**
   * Access Denied page.
   *
   * Path: /access-denied
   * Access: Public — intentionally unguarded
   * Component: AccessDeniedComponent
   *
   * Purpose:
   * - Destination of {@link permissionGuard}'s denial redirect (US-013 AC-2), so an
   *   authenticated user who lacks a permission is not bounced to the login page.
   *
   * Implementation:
   * - Lazy-loaded, following the /design-system precedent (top-level path, no guard).
   * - Unguarded on purpose: the page makes no HTTP call and reveals nothing, so it must
   *   render for a direct visit or a cold-start redirect.
   *
   * Constraint:
   * - MUST remain a top-level, unguarded route and MUST NOT become a descendant of a
   *   route carrying `data.permission`. Angular merges a parent route's `data` into child
   *   snapshots, so nesting this page under a gated ancestor would make its own denial
   *   redirect target a route that itself denies — a navigation loop instead of the
   *   intended UX.
   *
   * @see {@link permissionGuard}
   */
  {
    path: 'access-denied',
    loadComponent: () =>
      import('./shared/pages/access-denied/access-denied.component').then(
        (m) => m.AccessDeniedComponent,
      ),
  },

  /**
   * Wildcard fallback route (not defined here).
   *
   * Best practice:
   * Consider adding a wildcard route at the end to catch unknown paths:
   *
   * {
   *   path: '**',
   *   redirectTo: '/dashboard'  // or point to a 404 component
   * }
   *
   * This prevents blank pages when users navigate to non-existent routes.
   * Recommended: add this in a future enhancement.
   */
];
