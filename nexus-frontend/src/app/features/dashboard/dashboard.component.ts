import { httpResource } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { finalize } from 'rxjs';
import { APP_CONFIG } from '../../core/config/app-config';
import { AuthService } from '../auth/auth.service';
import { NxButton, NxToast } from '../../shared/ui';

/**
 * Main authenticated dashboard page (US-005).
 *
 * Provides the landing page for logged-in users with a logout button that revokes
 * all server-side refresh tokens (revoke-by-userId, not per-session). Dashboard is
 * intentionally minimal; user profile and settings are future work.
 *
 * Lifecycle:
 * - On init: fetches `/v1/users/me` to prime the interceptor's proactive-refresh logic.
 *   This ensures the token refresh mechanism is active if the access token is near expiry.
 * - On logout: POST to `/api/v1/auth/logout` (Bearer-authenticated), revokes all refresh
 *   token families, clears the session, shows toast, and redirects to login.
 * - Error handling: logout errors still redirect to login (session is cleared client-side).
 *
 * Security notes:
 * - Refresh token revocation strategy: TTL-only for GA. Access token remains valid for
 *   its residual window (≤15 min). Instant revocation via `jti` denylist is a planned
 *   fast-follow (ADR-0008).
 * - CSRF protection: SameSite=Strict on the refresh cookie. No CSRF token needed since
 *   logout has no side effects other than the caller's session.
 * - Interceptor integration: auth.interceptor.ts must exclude /logout from the 401-retry
 *   logic (AUTH_PATHS list) to prevent token refresh resurrection.
 *
 * Ref: docs/features/US-005/03-design.md
 */
@Component({
  selector: 'nx-dashboard',
  standalone: true,
  imports: [NxButton],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <main class="dashboard" data-testid="dashboard-root">
      <h1>Dashboard</h1>
      <nx-button
        variant="secondary"
        [loading]="loggingOut()"
        [disabled]="loggingOut()"
        data-testid="logout-button"
        (clicked)="onLogout()"
      >
        Log out
      </nx-button>
    </main>
  `,
})
export class DashboardComponent {
  private readonly config = inject(APP_CONFIG);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly toast = inject(NxToast);

  /** True while logout request is in flight; used to disable the button and show loading state. */
  readonly loggingOut = signal(false);

  /**
   * Fetches user profile on init to prime the auth interceptor's proactive-refresh branch.
   * The interceptor watches all HTTP responses; if expiresAt - now < 120 s, it proactively
   * calls POST /refresh to get a new access token before the current one expires.
   *
   * This fetch ensures the interceptor runs at least once per dashboard session,
   * preventing a scenario where the access token silently expires without refresh.
   *
   * Note: Result is not rendered in the template; this exists for its side effect only.
   */
  readonly userProfile = httpResource(() => `${this.config.apiBaseUrl}/v1/users/me`);

  /**
   * Initiates logout flow:
   * 1. Set loggingOut = true (disable button, show spinner)
   * 2. POST to /api/v1/auth/logout (Bearer-authenticated with access token)
   *    - Backend: revokes all refresh tokens for the user via LogoutUseCase.revokeByUserId
   *    - Clears the httpOnly, SameSite=Strict refresh cookie
   *    - Returns 204 No Content
   * 3. AuthService.logout() also calls clearSession() to clear local tokens
   * 4. Show success/error toast and redirect to /auth/login
   * 5. finalize(() => loggingOut.set(false)) — reset button state regardless of outcome
   *
   * Error handling: Even if logout HTTP fails, we still redirect to login because:
   * - Client has already cleared the session via clearSession()
   * - Access token will expire soon (typical TTL: 15 min)
   * - Network errors during logout are rare
   * - User experience is uniform: logout always → login
   */
  onLogout(): void {
    this.loggingOut.set(true);
    this.authService
      .logout()
      .pipe(finalize(() => this.loggingOut.set(false)))
      .subscribe({
        next: () => {
          this.toast.success('You have been logged out.');
          this.router.navigate(['/auth/login']);
        },
        error: () => {
          this.toast.error('Logout could not be confirmed, but your session was ended.');
          this.router.navigate(['/auth/login']);
        },
      });
  }
}
