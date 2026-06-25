import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';
import { AuthStore } from '../auth/auth.store';
import { AuthService } from '../../features/auth/auth.service';

export const authGuard: CanActivateFn = () => {
  const authStore = inject(AuthStore);
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authStore.isAuthenticated()) return true;

  // Session is null (page reload / cold start). The HttpOnly refresh cookie may
  // still be valid — attempt a silent restore before giving up and sending to login.
  return authService.refresh().pipe(
    map(() => true as const),
    catchError(() => of(router.createUrlTree(['/auth/login']))),
  );
};
