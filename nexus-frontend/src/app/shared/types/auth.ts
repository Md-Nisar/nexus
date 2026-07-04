/**
 * Authenticated user identity and authorization context.
 *
 * Extracted from the JWT access token and used throughout the application
 * to control feature availability, audit logging, and multi-tenant routing.
 * Never modify these properties — they are refreshed on token refresh.
 */
export interface AuthUser {
  /**
   * Unique user identifier (UUID).
   * Stable across password resets and email changes; used as the audit principal.
   */
  readonly userId: string;

  /**
   * Tenant identifier (UUID) for multi-tenant isolation.
   * All user queries and writes must be scoped by this tenant ID; failure to do so
   * is a critical data leak. See the multi-tenant interceptor for scoping enforcement.
   *
   * @security Critical isolation boundary — never trust user input for scoping.
   */
  readonly tenantId: string;

  /**
   * Email verification status at token issue time.
   * Used to gate email-dependent features (e.g. password reset). Do not cache this
   * beyond the token lifetime; refresh on next token refresh to detect verification
   * status changes.
   */
  readonly emailVerified: boolean;

  /**
   * Comma-delimited RBAC roles (e.g. "ADMIN", "USER"). Normalized to uppercase
   * at token issue. Used to gate operations via directive/guard chain; never rely
   * on roles for data access control — use tenant ID instead.
   */
  readonly roles: readonly string[];

  /**
   * Token version counter, incremented on each logout/token revocation.
   * Used to invalidate cached tokens if the user force-logs-out on another device.
   * If stale (server version > client version), trigger re-login flow.
   *
   * @security Used to detect token revocation; always check on refresh.
   */
  readonly tokenVersion: number;
}

/**
 * Active authentication session with access credentials and user identity.
 *
 * Holds the JWT access token and computed expiry time. Stored in sessionStorage
 * (not localStorage) to limit exposure to XSS. Cleared on logout, page close, or
 * on 401 response from the API.
 *
 * @security Never log, transmit to analytics, or expose in error messages.
 */
export interface AuthSession {
  /**
   * JWT access token (RS256-signed).
   * Contains user identity, tenant ID, roles, and token version in the claims.
   * Sent as "Authorization: Bearer <token>" on every API request via the
   * HTTP interceptor. Lifetime is typically 15 minutes.
   *
   * @security Never log, store in localStorage, or expose in the DOM.
   */
  readonly accessToken: string;

  /**
   * Bearer token type. Always "Bearer" in standard OAuth 2.0 / OpenID Connect flows.
   * Included in the Authorization header as "Bearer <token>".
   */
  readonly tokenType: string;

  /**
   * Token lifetime in seconds (e.g. 900 for 15 minutes).
   * Used to compute {@link expiresAt}. Typically matches the backend JWT config.
   */
  readonly expiresIn: number;

  /**
   * Computed absolute expiry time, in epoch milliseconds.
   * Calculated as Date.now() + (expiresIn * 1000) at login/refresh.
   * Used to proactively refresh the token before it expires (e.g. 60 seconds before).
   * If expired, the next API call will receive 401 and trigger re-login.
   *
   * Example: expiresIn = 900 (15 min), expiresAt = now + 15 * 60 * 1000
   */
  readonly expiresAt: number;

  /**
   * Authenticated user identity and roles.
   * Extracted from the JWT claims; immutable during the session.
   */
  readonly user: AuthUser;
}
