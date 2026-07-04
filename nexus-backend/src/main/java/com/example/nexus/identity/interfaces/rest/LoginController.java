package com.example.nexus.identity.interfaces.rest;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.web.CorrelationIdFilter;
import com.example.nexus.identity.application.service.LoginUseCase;
import com.example.nexus.identity.application.service.LogoutUseCase;
import com.example.nexus.identity.application.service.RefreshTokenUseCase;
import com.example.nexus.identity.domain.AuthConstants;
import com.example.nexus.identity.domain.LoginResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.nexus.identity.interfaces.rest.dto.LoginRequest;
import com.example.nexus.identity.interfaces.rest.dto.LoginResponse;

/**
 * Handles login, token refresh, and logout for the identity bounded context (US-003).
 *
 * <p>Active only when {@code feature.nexus-us003-auth-login.enabled=true}.
 *
 * <p><strong>Security notes:</strong>
 * <ul>
 *   <li>The raw refresh token is placed exclusively in the {@code Set-Cookie} header —
 *       never in the response body.
 *   <li>Client IP is read from {@code request.getRemoteAddr()} only (T-1.3 — never
 *       {@code X-Forwarded-For}).
 *   <li>The refresh cookie is {@code HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth}
 *       to prevent XSS theft and limit delivery scope.
 *   <li>Logout revokes all server-side refresh tokens via {@link LogoutUseCase} — clearing
 *       the cookie alone is insufficient because the raw token could have been captured.
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/auth")
@ConditionalOnProperty(name = "feature.nexus-us003-auth-login.enabled", havingValue = "true")
public class LoginController {

  // Derived from AuthConstants so cookie TTL and DB token TTL stay in sync.
  private static final long REFRESH_COOKIE_MAX_AGE =
      AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS * 24L * 3600L;

  private final LoginUseCase loginUseCase;
  private final RefreshTokenUseCase refreshTokenUseCase;
  private final LogoutUseCase logoutUseCase;
  private final UUID defaultTenantId;

  public LoginController(
      LoginUseCase loginUseCase,
      RefreshTokenUseCase refreshTokenUseCase,
      LogoutUseCase logoutUseCase,
      @Value("${nexus.identity.default-tenant-id}") UUID defaultTenantId) {
    this.loginUseCase = loginUseCase;
    this.refreshTokenUseCase = refreshTokenUseCase;
    this.logoutUseCase = logoutUseCase;
    this.defaultTenantId = defaultTenantId;
  }

  /**
   * Authenticates a user with email and password, issuing an access JWT and a refresh token.
   * The refresh token is set in an {@code HttpOnly; Secure; SameSite=Strict} cookie.
   *
   * @param req     login credentials (email, password)
   * @param request the HTTP request (used to extract client IP)
   * @return 200 OK with {@link LoginResponse} containing access token, token type, and TTL.
   *         The refresh token is set in a secure cookie (see security notes in class JavaDoc).
   * @throws AuthenticationException if credentials are invalid or account is not active
   * @throws AccountLockedException  if the account is locked (includes {@code Retry-After} header)
   * @throws AccountNotVerifiedException if the account is pending email verification
   */
  @PostMapping("/login")
  ResponseEntity<LoginResponse> login(
      @Valid @RequestBody LoginRequest req, HttpServletRequest request) {
    LoginResult result = loginUseCase.execute(
        defaultTenantId, req.email(), req.password(), requestContext(request));
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(result.rawRefreshToken(),
            REFRESH_COOKIE_MAX_AGE).toString())
        .body(new LoginResponse(result.accessToken(), "Bearer", result.expiresInSeconds(),
            result.userId()));
  }

  /**
   * Rotates the refresh token and issues a new access JWT.
   * The old refresh token is revoked; a new one is issued in the same family chain.
   *
   * @param cookieValue the raw refresh token from the {@code refresh_token} cookie (if present)
   * @param request     the HTTP request (used to extract client IP)
   * @return 200 OK with {@link LoginResponse} and a fresh refresh token in a secure cookie
   * @throws AuthenticationException if the token is invalid, revoked, or expired (AUTH_004)
   */
  @PostMapping("/refresh")
  ResponseEntity<LoginResponse> refresh(
      @CookieValue(value = "refresh_token", required = false) String cookieValue,
      HttpServletRequest request) {
    if (cookieValue == null) {
      throw new AuthenticationException("AUTH_004", "Refresh token invalid");
    }
    LoginResult result = refreshTokenUseCase.execute(cookieValue, request.getRemoteAddr());
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(result.rawRefreshToken(),
            REFRESH_COOKIE_MAX_AGE).toString())
        .body(new LoginResponse(result.accessToken(), "Bearer", result.expiresInSeconds(),
            result.userId()));
  }

  /**
   * Revokes all active refresh tokens for the authenticated user and clears the refresh cookie.
   * Logout is idempotent: an unauthenticated request or missing token is accepted normally.
   *
   * @param cookieValue the raw refresh token from the {@code refresh_token} cookie (if present)
   * @param request     the HTTP request (used to extract client IP and authenticated user)
   * @return 204 No Content with refresh cookie cleared (max-age=0)
   */
  @PostMapping("/logout")
  ResponseEntity<Void> logout(
      @CookieValue(value = "refresh_token", required = false) String cookieValue,
      HttpServletRequest request) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    UUID userId = (auth != null && auth.isAuthenticated()
        && !(auth instanceof AnonymousAuthenticationToken)
        && auth.getPrincipal() instanceof String s) ? UUID.fromString(s) : null;
    logoutUseCase.execute(userId, cookieValue, requestContext(request));
    ResponseCookie clear = buildRefreshCookie("", 0);
    return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, clear.toString()).build();
  }

  /**
   * Constructs a {@link RequestContext} from the HTTP request, extracting client IP, correlation ID,
   * and user-agent header for audit events and request tracing.
   *
   * @param req the HTTP servlet request
   * @return request context with client IP, trace ID, and user-agent
   */
  private RequestContext requestContext(HttpServletRequest req) {
    // user_agent is advisory forensic context only, never an authorization input -- captured
    // verbatim; RequestContext.of(...) caps and escapes it before it reaches storage.
    return RequestContext.of(
        req.getRemoteAddr(), MDC.get(CorrelationIdFilter.MDC_KEY), req.getHeader("User-Agent"));
  }

  /**
   * Builds an {@code HttpOnly; Secure; SameSite=Strict} cookie for the refresh token.
   * Set to {@code max-age=0} to clear an existing cookie.
   *
   * @param raw    the raw refresh token value (or empty string to clear)
   * @param maxAge the cookie max-age in seconds (use {@link #REFRESH_COOKIE_MAX_AGE} for new tokens, 0 to clear)
   * @return a {@link ResponseCookie} configured with security headers per OWASP guidelines
   */
  private ResponseCookie buildRefreshCookie(String raw, long maxAge) {
    return ResponseCookie.from("refresh_token")
        .value(raw)
        .httpOnly(true).secure(true).sameSite("Strict").path("/api/v1/auth").maxAge(maxAge)
        .build();
  }
}
