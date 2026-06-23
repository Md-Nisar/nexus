import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';
import { Router } from '@angular/router';
import { AuthStore } from '../auth/auth.store';
import { AuthService } from '../../features/auth/auth.service';

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
      const isAuthEndpoint = req.url.includes('/auth/login') || req.url.includes('/auth/refresh');

      if (error instanceof HttpErrorResponse && error.status === 401 && !isAuthEndpoint) {
        return authService.refresh().pipe(
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
