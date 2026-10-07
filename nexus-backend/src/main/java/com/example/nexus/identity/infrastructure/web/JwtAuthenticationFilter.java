package com.example.nexus.identity.infrastructure.web;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.common.security.AuthenticationDetailKeys;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.rbac.application.FreshnessVerdict;
import com.example.nexus.rbac.application.PermissionFreshnessService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Validates the {@code Authorization: Bearer <jwt>} header on every request.
 *
 * <p>If no header is present the filter is a no-op — unauthenticated requests fall through to
 * Spring Security's default-deny for protected endpoints.
 *
 * <p><b>Non-public requests</b> (US-018 A9): the token is verified, then its permission epoch is
 * checked once. An invalid or stale token clears the security context and goes to the
 * {@link AuthenticationEntryPoint} (401 {@code AUTH_003}); the filter chain is NOT continued. A
 * check the epoch store could not answer lets this one request proceed (counted by the freshness
 * service).
 *
 * <p><b>Public requests</b> ({@link PublicEndpointRequestMatcher} matches; RC-24, RC-44.2) are
 * never rejected here: there is no epoch check, and a bearer that fails verification is ignored
 * (the request proceeds anonymously; the rejection is counted by the verifier). A bearer that
 * verifies sets the principal with an <b>empty</b> {@code PERMISSIONS} detail and <b>no</b>
 * authorities, so an epoch-unchecked token can never satisfy {@code @RequiresPermission}, even if
 * the matcher misclassified the request. Logout needs only the principal's user id.
 *
 * <p>On a principal, puts {@code userId} / {@code tenantId} into MDC so they propagate to all
 * downstream log entries (T-3.7).
 *
 * <p>Client IP reading policy: this filter reads no IP; IP is read by the controller via
 * {@code request.getRemoteAddr()} only (T-1.3).
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private static final String AUTH_003 = "AUTH_003";

  private final JwtPort jwtPort;
  private final AuthenticationEntryPoint authenticationEntryPoint;
  private final PublicEndpointRequestMatcher publicEndpoints;
  private final PermissionFreshnessService permissionFreshness;

  public JwtAuthenticationFilter(
      JwtPort jwtPort,
      AuthenticationEntryPoint authenticationEntryPoint,
      PublicEndpointRequestMatcher publicEndpoints,
      PermissionFreshnessService permissionFreshness) {
    this.jwtPort = jwtPort;
    this.authenticationEntryPoint = authenticationEntryPoint;
    this.publicEndpoints = publicEndpoints;
    this.permissionFreshness = permissionFreshness;
  }

  /**
   * Validates the {@code Authorization: Bearer <jwt>} header and populates {@link SecurityContextHolder}
   * with the authenticated principal. See the class description for the public and non-public rules.
   *
   * @param req   the HTTP request (Bearer token in {@code Authorization} header)
   * @param res   the HTTP response (401 problem document on an invalid or stale token)
   * @param chain the filter chain
   * @throws ServletException if an error occurs during filtering
   * @throws IOException      if an I/O error occurs during filtering
   */
  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    String header = req.getHeader("Authorization");
    if (header == null || !header.startsWith("Bearer ")) {
      chain.doFilter(req, res);
      return;
    }
    String rawJwt = header.substring(7);
    if (publicEndpoints.matches(req)) {
      filterPublic(rawJwt, req, res, chain);
      return;
    }
    JwtClaims claims;
    try {
      claims = jwtPort.verify(rawJwt);
    } catch (AuthenticationException e) {
      reject(req, res, e);
      return;
    }
    UUID tenantId;
    UUID userId;
    try {
      tenantId = UUID.fromString(claims.tenantId());
      userId = UUID.fromString(claims.sub());
    } catch (IllegalArgumentException e) {
      // verify() already guarantees canonical UUIDs (RC-40.1); another JwtPort might not.
      reject(req, res, new AuthenticationException(AUTH_003, "Token identifiers are malformed"));
      return;
    }
    FreshnessVerdict verdict = permissionFreshness.check(tenantId, userId, claims.permEpoch());
    boolean stale = switch (verdict) {
      case STALE -> true;
      case FRESH, SKIPPED_ERROR -> false;
    };
    if (stale) {
      reject(req, res, new AuthenticationException(AUTH_003, "Token permissions are stale"));
      return;
    }
    List<SimpleGrantedAuthority> authorities = claims.roles().stream()
        .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
        .toList();
    authenticateAndContinue(claims, authorities, claims.permissions(), req, res, chain);
  }

  /** A {@code @PublicEndpoint} request: never rejected, never epoch-checked, permission-free. */
  private void filterPublic(
      String rawJwt, HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    JwtClaims claims;
    try {
      claims = jwtPort.verify(rawJwt);
    } catch (AuthenticationException e) {
      chain.doFilter(req, res);
      return;
    }
    authenticateAndContinue(claims, List.of(), List.of(), req, res, chain);
  }

  private void authenticateAndContinue(
      JwtClaims claims,
      List<SimpleGrantedAuthority> authorities,
      List<String> permissions,
      HttpServletRequest req,
      HttpServletResponse res,
      FilterChain chain)
      throws ServletException, IOException {
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(claims.sub(), null, authorities);
    // stash all extra claims as details (T-3.7 — downstream reads from SecurityContext)
    auth.setDetails(Map.of(
        AuthenticationDetailKeys.TENANT_ID, claims.tenantId(),
        AuthenticationDetailKeys.EMAIL_VERIFIED, claims.emailVerified(),
        AuthenticationDetailKeys.TOKEN_VERSION, claims.tokenVersion(),
        AuthenticationDetailKeys.PERMISSIONS, permissions));
    SecurityContextHolder.getContext().setAuthentication(auth);
    MDC.put(AuthenticationDetailKeys.MDC_USER_ID, claims.sub());
    MDC.put(AuthenticationDetailKeys.MDC_TENANT_ID, claims.tenantId());
    try {
      chain.doFilter(req, res);
    } finally {
      MDC.remove(AuthenticationDetailKeys.MDC_USER_ID);
      MDC.remove(AuthenticationDetailKeys.MDC_TENANT_ID);
    }
  }

  private void reject(HttpServletRequest req, HttpServletResponse res, AuthenticationException e)
      throws ServletException, IOException {
    SecurityContextHolder.clearContext();
    authenticationEntryPoint.commence(req, res,
        new org.springframework.security.core.AuthenticationException(e.getMessage(), e) {});
  }
}
