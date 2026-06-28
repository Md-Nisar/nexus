import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, finalize, Observable, shareReplay, switchMap, throwError } from 'rxjs';
import { Router } from '@angular/router';
import { AuthStore } from '../auth/auth.store';
import { AuthService } from '../../features/auth/auth.service';
import { AuthSession } from '../../shared/types/auth';

// Shared in-flight refresh observable — ensures concurrent requests share one POST /refresh call.
// Multiple callers each subscribe to the same observable via shareReplay(1); the second
// subscriber does NOT trigger a second HTTP request, preventing theft-detection family revocation.
let refreshInFlight: Observable<AuthSession> | null = null;

const AUTH_PATHS = ['/api/v1/auth/login', '/api/v1/auth/refresh', '/api/v1/auth/logout'];

/** Proactively refresh when access token has less than this many ms remaining. */
const PROACTIVE_REFRESH_THRESHOLD_MS = 120_000; // 2 min

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authStore = inject(AuthStore);
  const authService = inject(AuthService);
  const router = inject(Router);

  // Use exact pathname comparison to avoid false matches on future paths
  // (e.g. /admin/auth/login-audit would incorrectly match an includes() check).
  const path = new URL(req.url, window.location.origin).pathname;
  const isAuthEndpoint = AUTH_PATHS.includes(path);

  // ── Proactive refresh (AC-4) ────────────────────────────────────────────────
  // Refresh before forwarding if the access token will expire within 2 min.
  // Auth endpoints are excluded to prevent an infinite refresh loop.
  // Both this path and the reactive-401 path below share `refreshInFlight`
  // (shareReplay(1)) so a burst of concurrent requests issues exactly one POST /refresh.
  // Cross-tab safety: the cookie is HttpOnly+SameSite=Strict so a second tab presents
  // the rotated cookie, not a stale one — no false theft-detection (design §8).
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
  // ── End proactive refresh ───────────────────────────────────────────────────

  const token = authStore.accessToken();
  const authReq =
    token && !req.headers.has('Authorization')
      ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
      : req;

  return next(authReq).pipe(
    catchError((error: unknown) => {
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
