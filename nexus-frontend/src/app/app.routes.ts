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
 * - Public pages (auth, access-denied, design-system) render inside PublicLayout
 * - Signed-in pages render inside the lazy Shell, which carries authGuard
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
   * Home redirect. It must precede both empty-path parents: for an empty URL the router accepts
   * the public layout (no child needs to match nothing) and never backtracks to the shell, so
   * `/` would render an empty public page instead of reaching the dashboard.
   */
  { path: '', pathMatch: 'full', redirectTo: 'dashboard' },

  /**
   * Public pages, rendered inside {@link PublicLayout} (header with wordmark and theme toggle).
   *
   * Declared BEFORE the shell: both parents have an empty path, so the router tries this one
   * first and backtracks to the shell only when none of these children match. No guard and no
   * `data` here, on purpose (see the access-denied constraint below).
   */
  {
    path: '',
    loadComponent: () =>
      import('./core/layout/public-layout/public-layout').then((m) => m.PublicLayout),
    children: [
      /**
       * Authentication feature routes (login, register, forgot-password, reset-password,
       * verify-email). Public; the auth feature must not import protected features.
       */
      {
        path: 'auth',
        loadChildren: () => import('./features/auth/auth.routes').then((m) => m.AUTH_ROUTES),
      },

      /**
       * Design system preview and component showcase. Public, internal tool.
       */
      {
        path: 'design-system',
        title: 'Design system',
        loadComponent: () =>
          import('./features/design-system/design-system-preview.component').then(
            (m) => m.DesignSystemPreviewComponent,
          ),
      },

      /**
       * Access Denied page.
       *
       * Destination of {@link permissionGuard}'s denial redirect (US-013 AC-2), so an
       * authenticated user who lacks a permission is not bounced to the login page.
       *
       * Unguarded on purpose: the page makes no HTTP call and reveals nothing, so it must
       * render for a direct visit or a cold-start redirect.
       *
       * Constraint:
       * - MUST stay outside the shell and MUST NOT become a descendant of a route carrying
       *   `data.permission`. Angular merges a parent route's `data` into child snapshots, so
       *   nesting this page under a gated ancestor would make its own denial redirect target
       *   a route that itself denies: a navigation loop instead of the intended UX.
       *
       * @see {@link permissionGuard}
       */
      {
        path: 'access-denied',
        title: 'Access denied',
        // The component focuses its own h1; route-focus must not double-handle it.
        data: { selfManagedFocus: true },
        loadComponent: () =>
          import('./shared/pages/access-denied/access-denied.component').then(
            (m) => m.AccessDeniedComponent,
          ),
      },
    ],
  },

  /**
   * Signed-in shell (header, permission-filtered nav, user menu, skip link, `main`).
   *
   * Access: authenticated users only; {@link authGuard} sits on this ancestor so every child,
   * including future routes guarded by `permissionGuard`, runs after the session is restored.
   * Guards in one `canActivate` array run concurrently, so `authGuard` must never share an
   * array with `permissionGuard`.
   *
   * Unknown URLs fall through to this shell: a signed-out visitor is sent to /auth/login.
   */
  {
    path: '',
    canActivate: [authGuard],
    loadComponent: () => import('./core/layout/shell/shell').then((m) => m.Shell),
    children: [
      {
        path: 'dashboard',
        title: 'Dashboard',
        loadComponent: () =>
          import('./features/dashboard/dashboard.component').then((m) => m.DashboardComponent),
      },
      {
        path: '**',
        title: 'Page not found',
        loadComponent: () =>
          import('./shared/pages/not-found/not-found.component').then((m) => m.NotFoundComponent),
      },
    ],
  },
];
