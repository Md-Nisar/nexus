import { computed, inject, Service, signal } from '@angular/core';
import { LoggerService } from '../logging/logger.service';
import { AuthSession } from '../../shared/types/auth';

/**
 * Stable, frozen empty permission list returned when no session exists.
 *
 * A module-level frozen constant (rather than an inline `?? []`) keeps the computed's
 * reference identity stable across recomputations, so downstream `computed`/`effect`
 * consumers — notably HasPermissionDirective — never see spurious identity churn.
 */
const NO_PERMISSIONS: readonly string[] = Object.freeze([]);

/**
 * Manages the current authentication session state via signals.
 *
 * Provides reactive access to the authenticated user, access token, and authentication
 * status throughout the application. The store maintains session validity by checking
 * both session existence and token expiration time.
 */
@Service()
export class AuthStore {
  private readonly logger = inject(LoggerService);
  private readonly _session = signal<AuthSession | null>(null);

  /** Read-only signal containing the full session or null. */
  readonly session = this._session.asReadonly();

  /**
   * Computed signal indicating whether the user is currently authenticated.
   *
   * True only if a session exists and the access token has not expired.
   */
  readonly isAuthenticated = computed(() => {
    const s = this._session();
    return s !== null && Date.now() < s.expiresAt;
  });

  /**
   * Computed signal containing the current user or null if not authenticated.
   */
  readonly currentUser = computed(() => this._session()?.user ?? null);

  /**
   * Computed signal containing the current access token or null if not authenticated.
   */
  readonly accessToken = computed(() => this._session()?.accessToken ?? null);

  /**
   * Computed signal containing the current user's RBAC permissions.
   *
   * Returns a stable empty array when there is no session, so consumers never need a
   * null check and `.includes()` can never throw (US-013 AC-4).
   *
   * @security UX only — see {@link AuthUser.permissions}. Never an authorization decision.
   */
  readonly permissions = computed<readonly string[]>(
    () => this._session()?.user.permissions ?? NO_PERMISSIONS,
  );

  /**
   * Establishes a new authentication session.
   *
   * @param session The session containing user info and tokens.
   */
  setSession(session: AuthSession): void {
    this._session.set(session);
    this.logger.debug('Auth session established', { context: { userId: session.user.userId } });
  }

  /**
   * Clears the current authentication session.
   */
  clearSession(): void {
    this._session.set(null);
    this.logger.debug('Auth session cleared');
  }
}
