import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';
import { AuthStore } from '../auth/auth.store';
import { LoggerService } from '../logging/logger.service';
import { UnavailableState } from '../routing/unavailable-state';
import { AuthService } from '../../features/auth/auth.service';
import { AppError, isAppError } from '../../shared/types/app-error';

/**
 * Failures where nobody authoritative answered the refresh (US-020 design §4.5):
 * - `NETWORK_ERROR`: no response at all (connection refused or reset).
 * - `HTTP_ERROR`: a response that is not a problem document, so a gateway, nginx or another
 *   intermediary answered (502, 503, 504, nginx's HTML 429). The backend always sends one.
 * - `AUTH_005`: the backend's own "temporarily unavailable".
 *
 * Every other backend problem document (`AUTH_004`, `RATE_001`, `INTERNAL_ERROR`, …) is an
 * authoritative answer and goes to login.
 */
const UNAVAILABLE_CODES: ReadonlySet<string> = new Set(['NETWORK_ERROR', 'HTTP_ERROR', 'AUTH_005']);

function isServiceUnavailable(error: unknown): error is AppError {
  return isAppError(error) && UNAVAILABLE_CODES.has(error.code);
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
 * A refresh that nobody authoritative answered (see {@link UNAVAILABLE_CODES}) is not proof the
 * session is gone, so the guard records the failure in {@link UnavailableState} and redirects to
 * the static `/unavailable` view, whose user-initiated Retry re-enters through this guard.
 *
 * ## Refresh contract (RC-65)
 * `refresh()` is called **exactly once per activation**, and this guard sits only on the shell's
 * `canActivate` (never `canActivateChild`). The unavailable view issues no request of its own, so
 * every refresh comes from here. A lost refresh response followed by Retry presents a rotated-away
 * cookie: the backend answers 401 `AUTH_004` (reuse), which goes to login, never back to
 * `/unavailable`, so there is no loop (RC-71, accepted as fail-closed).
 *
 * @returns true only after a successful refresh (or with a session already in memory); otherwise
 * a UrlTree to `/unavailable` or `/auth/login`, each with the attempted URL as `returnUrl`. Both
 * targets validate it with `safeReturnUrl` before navigating.
 */
export const authGuard: CanActivateFn = (_route, state) => {
  const authStore = inject(AuthStore);
  const authService = inject(AuthService);
  const router = inject(Router);
  const unavailableState = inject(UnavailableState);
  const logger = inject(LoggerService);

  if (authStore.isAuthenticated()) return true;

  return authService.refresh().pipe(
    map(() => {
      // The sign-in is confirmed: an earlier failure's reference and cool-down no longer apply.
      unavailableState.clear();
      return true as const;
    }),
    catchError((error: unknown) => {
      if (isServiceUnavailable(error)) {
        unavailableState.record(error);
        // Code and correlation id only: no URL, server text or trace id in the log.
        logger.warn('Session restore could not reach Nexus; showing the unavailable view', {
          event: 'auth_guard_unavailable',
          errorCode: error.code,
          correlationId: error.correlationId,
        });
        return of(
          router.createUrlTree(['/unavailable'], { queryParams: { returnUrl: state.url } }),
        );
      }
      return of(router.createUrlTree(['/auth/login'], { queryParams: { returnUrl: state.url } }));
    }),
  );
};
