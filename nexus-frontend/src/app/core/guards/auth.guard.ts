import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';
import { AuthStore } from '../auth/auth.store';
import { AuthService } from '../../features/auth/auth.service';

function isServiceUnavailable(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return code === 'AUTH_005' || code === 'NETWORK_ERROR';
}

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
 * A refresh that fails because the service is unavailable (503 `AUTH_005`, network error) is not
 * proof the session is gone, so the guard cancels the navigation (`false`) instead of redirecting.
 *
 * @returns true to allow navigation, or a UrlTree to redirect to /auth/login with the attempted
 * URL as `returnUrl`. The login form validates it with `safeReturnUrl` before navigating.
 */
export const authGuard: CanActivateFn = (_route, state) => {
  const authStore = inject(AuthStore);
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authStore.isAuthenticated()) return true;

  return authService.refresh().pipe(
    map(() => true as const),
    catchError((error: unknown) => {
      // The session may still be valid: 503 AUTH_005 and network errors never navigate (design
      // 12.10). The interceptor already toasted; the user stays put and can retry or reload.
      if (isServiceUnavailable(error)) return of(false as const);
      return of(router.createUrlTree(['/auth/login'], { queryParams: { returnUrl: state.url } }));
    }),
  );
};
