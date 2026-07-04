import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, finalize, Observable, shareReplay, switchMap, throwError } from 'rxjs';
import { Router } from '@angular/router';
import { AuthStore } from '../auth/auth.store';
import { AuthService } from '../../features/auth/auth.service';
import { AuthSession } from '../../shared/types/auth';
import { APP_CONFIG } from '../config/app-config';

/**
 * Shared in-flight refresh observable — ensures concurrent requests share one POST /refresh call.
 * Multiple callers each subscribe to the same observable via shareReplay(1); the second
 * subscriber does NOT trigger a second HTTP request, preventing theft-detection family revocation.
 * See design §8 for cross-tab safety guarantees.
 */
let refreshInFlight: Observable<AuthSession> | null = null;

/**
 * HTTP paths that must not trigger proactive refresh to prevent infinite loops.
 * Includes auth endpoints (login, refresh, logout) that manage session state directly.
 */
const AUTH_PATHS = ['/api/v1/auth/login', '/api/v1/auth/refresh', '/api/v1/auth/logout'];

/**
 * Proactively refresh when access token has less than this many milliseconds remaining.
 * Prevents 401 responses on user actions by refreshing just before expiry.
 */
const PROACTIVE_REFRESH_THRESHOLD_MS = 120_000; // 2 min

/**
 * Determines whether a request targets the Nexus API (same origin + apiBaseUrl prefix).
 * Both `apiBaseUrl` and `req.url` are resolved against the page origin before comparing,
 * so this works whether apiBaseUrl is relative (prod: `/api`) or absolute
 * (dev: `http://localhost:1000/api`).
 *
 * @param url - The request URL to validate.
 * @param apiBaseUrl - The configured API base URL (relative or absolute).
 * @returns True if the request is for the Nexus API; false for external resources.
 * @security Prevents leaking access tokens to third-party origins (e.g., Google Fonts).
 */
function isApiRequest(url: string, apiBaseUrl: string): boolean {
  const target = new URL(url, window.location.origin);
  const base = new URL(apiBaseUrl, window.location.origin);
  return target.origin === base.origin && target.pathname.startsWith(base.pathname);
}

/**
 * HTTP interceptor for automatic token management and session maintenance.
 *
 * Responsibilities:
 * - **Token attachment**: Attaches the current access token to all Nexus API requests.
 * - **Proactive refresh** (AC-4): Refreshes access token before expiry (≤ 2 min remaining)
 *   to prevent user-visible 401 responses.
 * - **Reactive refresh**: Handles 401 responses from expired tokens by triggering a refresh
 *   and replaying the original request.
 * - **Request deduplication**: Uses shareReplay(1) to ensure concurrent requests share
 *   exactly one POST /refresh call, preventing theft-detection family revocation (design §8).
 * - **Cross-origin safety**: Never attaches tokens or initiates refresh flows for
 *   third-party origins; only targets the configured Nexus API.
 *
 * Auth endpoints (login, refresh, logout) are excluded from proactive refresh to prevent
 * infinite loops. Both proactive and reactive refresh paths use the same `refreshInFlight`
 * observable to deduplicate concurrent POST /refresh calls.
 *
 * Cross-tab safety: The HttpOnly+SameSite=Strict refresh cookie ensures that a second tab
 * always presents the rotated cookie from the auth server, not a stale one, preventing
 * false theft-detection triggers (see design §8).
 *
 * @security Validates request origin and endpoint before attaching tokens.
 *           Always fails closed on refresh errors (logs out and redirects to login).
 *           Never leaks tokens to third-party origins.
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authStore = inject(AuthStore);
  const authService = inject(AuthService);
  const router = inject(Router);
  const config = inject(APP_CONFIG);

  // Security: Never attach the bearer token or trigger refresh/theft-detection flows for
  // requests outside the Nexus API (e.g., Google Fonts). Doing so would leak the access
  // token to a third party.
  if (!isApiRequest(req.url, config.apiBaseUrl)) {
    return next(req);
  }

  // Extract the endpoint path using exact pathname comparison to avoid false matches on
  // future paths (e.g., /admin/auth/login-audit would incorrectly match an includes() check).
  const path = new URL(req.url, window.location.origin).pathname;
  const isAuthEndpoint = AUTH_PATHS.includes(path);

  // ───────────────────────────────────────────────────────────────────────────────────
  // Proactive refresh (AC-4): Refresh before forwarding if the access token will expire
  // within 2 minutes. This prevents 401 responses on user actions.
  //
  // Auth endpoints are excluded to prevent infinite refresh loops.
  // Both this path and the reactive-401 path below share `refreshInFlight` (shareReplay(1))
  // so a burst of concurrent requests issues exactly one POST /refresh call. This is
  // critical to prevent theft-detection family revocation (design §8).
  // ───────────────────────────────────────────────────────────────────────────────────
  const session = authStore.session();
  const proactive =
    session !== null && session.expiresAt - Date.now() < PROACTIVE_REFRESH_THRESHOLD_MS;

  if (proactive && !isAuthEndpoint) {
    if (!refreshInFlight) {
      refreshInFlight = authService.refresh().pipe(
        finalize(() => {
          refreshInFlight = null;
        }),
        shareReplay(1),
      );
    }
    return refreshInFlight.pipe(
      catchError((err) => {
        authStore.clearSession();
        router.navigate(['/auth/login']);
        return throwError(() => err);
      }),
      switchMap((session) =>
        next(req.clone({ setHeaders: { Authorization: `Bearer ${session.accessToken}` } })),
      ),
    );
  }

  // Standard flow: Attach the current access token to the request.
  // Skip if Authorization header is already set (respects caller-provided credentials).
  const token = authStore.accessToken();
  const authReq =
    token && !req.headers.has('Authorization')
      ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
      : req;

  return next(authReq).pipe(
    catchError((error: unknown) => {
      // ───────────────────────────────────────────────────────────────────────────────
      // Reactive refresh: Handle 401 responses (expired token) by triggering a refresh
      // and replaying the original request. Auth endpoints are excluded because they
      // manage their own session state.
      // ───────────────────────────────────────────────────────────────────────────────
      if (error instanceof HttpErrorResponse && error.status === 401 && !isAuthEndpoint) {
        if (!refreshInFlight) {
          refreshInFlight = authService.refresh().pipe(
            finalize(() => {
              refreshInFlight = null;
            }),
            shareReplay(1),
          );
        }

        return refreshInFlight.pipe(
          switchMap((session) =>
            next(req.clone({ setHeaders: { Authorization: `Bearer ${session.accessToken}` } })),
          ),
          catchError(() => {
            authStore.clearSession();
            router.navigate(['/auth/login']);
            return throwError(() => error);
          }),
        );
      }

      return throwError(() => error);
    }),
  );
};
