import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';
import { AuthStore } from '../auth/auth.store';
import { AuthService } from '../../features/auth/auth.service';

/**
 * Route guard that requires the user to be authenticated.
 *
 * If the session exists and is valid, grants immediate access. Otherwise,
 * attempts a silent refresh using the HttpOnly refresh cookie. If the cookie
 * is still valid, the session is restored and access is granted; if not,
 * the user is redirected to the login page.
 *
 * This handles cold-start scenarios (page reload) where the in-memory session
 * is null but the secure refresh cookie may still be valid.
 *
 * @returns true to allow navigation, or a UrlTree to redirect to /auth/login.
 */
export const authGuard: CanActivateFn = () => {
  const authStore = inject(AuthStore);
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authStore.isAuthenticated()) return true;

  return authService.refresh().pipe(
    map(() => true as const),
    catchError(() => of(router.createUrlTree(['/auth/login']))),
  );
};
