import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, finalize, Observable, shareReplay, switchMap, throwError } from 'rxjs';
import { Router } from '@angular/router';
import { AuthStore } from '../auth/auth.store';
import { AuthService } from '../../features/auth/auth.service';
import { AuthSession } from '../../shared/types/auth';

// Shared in-flight refresh observable — ensures concurrent 401s share one POST /refresh call.
// Multiple callers each subscribe to the same observable via shareReplay(1); the second
// subscriber does NOT trigger a second HTTP request, preventing theft-detection family revocation.
let refreshInFlight: Observable<AuthSession> | null = null;

const AUTH_PATHS = ['/api/v1/auth/login', '/api/v1/auth/refresh'];

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authStore = inject(AuthStore);
  const authService = inject(AuthService);
  const router = inject(Router);

  const token = authStore.accessToken();
  const authReq =
    token && !req.headers.has('Authorization')
      ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
      : req;

  return next(authReq).pipe(
    catchError((error: unknown) => {
      // Use exact pathname comparison to avoid false matches on future paths
      // (e.g. /admin/auth/login-audit would incorrectly match an includes() check).
      const path = new URL(req.url, window.location.origin).pathname;
      const isAuthEndpoint = AUTH_PATHS.includes(path);

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
