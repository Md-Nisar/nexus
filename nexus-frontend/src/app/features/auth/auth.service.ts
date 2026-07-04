import { inject, Service } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { finalize, map, Observable, switchMap, tap } from 'rxjs';
import { APP_CONFIG } from '../../core/config/app-config';
import { AuthStore } from '../../core/auth/auth.store';
import { AuthSession } from '../../shared/types/auth';

/**
 * Response payload from the login endpoint.
 */
interface LoginApiResponse {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  userId: string;
}

/**
 * Response payload from the /users/me endpoint after successful authentication.
 */
interface MeApiResponse {
  userId: string;
  emailVerified: boolean;
  tenantId: string;
  roles: string[];
  tokenVersion: number;
}

/**
 * Manages authentication operations and session lifecycle.
 *
 * Handles user registration, login, logout, email verification, password reset,
 * and token refresh. All authentication state is persisted to AuthStore.
 *
 * Security notes:
 * - Login and refresh use `withCredentials: true` for secure HTTP-only cookie handling.
 * - Tokens are extracted and stored in AuthStore after successful authentication.
 * - Session expiration is calculated and stored for client-side expiry tracking.
 */
@Service()
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly config = inject(APP_CONFIG);
  private readonly authStore = inject(AuthStore);

  /**
   * Constructs the base URL for authentication endpoints.
   *
   * @returns The v1 auth API base URL.
   */
  private get base(): string {
    return `${this.config.apiBaseUrl}/v1/auth`;
  }

  /**
   * Registers a new user account.
   *
   * @param email The user's email address.
   * @param password The user's password (must meet policy requirements).
   * @param consentAccepted Whether the user has accepted terms and conditions.
   * @returns Observable that completes on success or errors with AppError on validation failure.
   */
  register(email: string, password: string, consentAccepted: boolean): Observable<void> {
    return this.http
      .post(`${this.base}/register`, { email, password, consentAccepted })
      .pipe(map(() => undefined));
  }

  /**
   * Verifies a user's email address using a verification token.
   *
   * @param token The email verification token sent to the user's inbox.
   * @returns Observable that completes on success or errors with AppError if token is invalid/expired.
   */
  verifyEmail(token: string): Observable<void> {
    return this.http.post(`${this.base}/verify-email`, { token }).pipe(map(() => undefined));
  }

  /**
   * Requests a new email verification link to be sent.
   *
   * @param email The user's email address.
   * @returns Observable that completes when the request is processed (always succeeds for security).
   */
  resendVerification(email: string): Observable<void> {
    return this.http.post(`${this.base}/resend-verification`, { email }).pipe(map(() => undefined));
  }

  /**
   * Authenticates a user and establishes a session.
   *
   * Fetches credentials, obtains user metadata, and stores the session in AuthStore.
   * The session includes access token, user roles, and expiration details.
   *
   * Security notes:
   * - Uses `withCredentials: true` to persist refresh token in HTTP-only cookie.
   * - Access token is stored in memory (not localStorage) for XSS protection.
   *
   * @param email The user's email address.
   * @param password The user's password.
   * @returns Observable emitting the authenticated session or AppError on failure.
   */
  login(email: string, password: string): Observable<AuthSession> {
    return this.http
      .post<LoginApiResponse>(`${this.base}/login`, { email, password }, { withCredentials: true })
      .pipe(
        switchMap((loginResp) =>
          this.fetchMe(loginResp.accessToken, loginResp.tokenType).pipe(
            map((me) => this.buildSession(loginResp, me)),
          ),
        ),
        tap((session) => this.authStore.setSession(session)),
      );
  }

  /**
   * Initiates a password reset flow.
   *
   * Sends a reset link to the user's email. Always succeeds (even for non-existent accounts)
   * to prevent account enumeration.
   *
   * @param email The user's email address.
   * @returns Observable that completes when the request is processed.
   */
  forgotPassword(email: string): Observable<void> {
    return this.http.post(`${this.base}/password/forgot`, { email }).pipe(map(() => undefined));
  }

  /**
   * Resets a user's password using a reset token.
   *
   * @param token The password reset token from the email link.
   * @param newPassword The user's new password (must meet policy requirements).
   * @returns Observable emitting a success message or AppError if token is invalid/expired.
   */
  resetPassword(token: string, newPassword: string): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.base}/password/reset`, {
      token,
      newPassword,
    });
  }

  /**
   * Logs out the current user and clears the session.
   *
   * Clears the session from AuthStore even if the HTTP request fails, ensuring
   * the local session is always cleared.
   *
   * Security notes:
   * - Uses `withCredentials: true` to send refresh token for server-side revocation.
   * - Relies on finalize() to guarantee AuthStore cleanup.
   *
   * @returns Observable that completes on success or error (session is cleared either way).
   */
  logout(): Observable<void> {
    return this.http
      .post<void>(`${this.base}/logout`, null, { withCredentials: true })
      .pipe(finalize(() => this.authStore.clearSession()));
  }

  /**
   * Refreshes the authentication session using the stored refresh token.
   *
   * Obtains a new access token and updates the session in AuthStore.
   *
   * Security notes:
   * - Uses `withCredentials: true` to send the HTTP-only refresh token cookie.
   *
   * @returns Observable emitting the refreshed session or AppError on failure.
   */
  refresh(): Observable<AuthSession> {
    return this.http
      .post<LoginApiResponse>(`${this.base}/refresh`, null, { withCredentials: true })
      .pipe(
        switchMap((loginResp) =>
          this.fetchMe(loginResp.accessToken, loginResp.tokenType).pipe(
            map((me) => this.buildSession(loginResp, me)),
          ),
        ),
        tap((session) => this.authStore.setSession(session)),
      );
  }

  /**
   * Fetches the current user's profile and metadata.
   *
   * @param token The access token.
   * @param tokenType The token type (usually "Bearer").
   * @returns Observable emitting the user profile or AppError on failure.
   */
  private fetchMe(token: string, tokenType: string): Observable<MeApiResponse> {
    return this.http.get<MeApiResponse>(`${this.config.apiBaseUrl}/v1/users/me`, {
      headers: { Authorization: `${tokenType} ${token}` },
    });
  }

  /**
   * Constructs a session object from login and user profile responses.
   *
   * Calculates `expiresAt` as a Unix timestamp for client-side expiry tracking.
   *
   * @param login The login response containing token and expiration.
   * @param me The user profile response from /users/me.
   * @returns The constructed AuthSession object.
   */
  private buildSession(login: LoginApiResponse, me: MeApiResponse): AuthSession {
    return {
      accessToken: login.accessToken,
      tokenType: login.tokenType,
      expiresIn: login.expiresIn,
      expiresAt: Date.now() + login.expiresIn * 1000,
      user: {
        userId: me.userId,
        tenantId: me.tenantId,
        emailVerified: me.emailVerified,
        roles: me.roles,
        tokenVersion: me.tokenVersion,
      },
    };
  }
}
