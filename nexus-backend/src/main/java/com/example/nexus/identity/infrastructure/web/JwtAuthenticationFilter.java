package com.example.nexus.identity.infrastructure.web;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.JwtClaims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
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
 * <p>On a valid token, sets {@link SecurityContextHolder} authentication and puts {@code userId}
 * / {@code tenantId} into MDC so they propagate to all downstream log entries (T-3.7).
 *
 * <p>On an invalid token, clears the security context and delegates directly to the
 * {@link AuthenticationEntryPoint} — the response is a 401 RFC 7807 problem document, and the
 * filter chain is NOT continued.
 *
 * <p>Client IP reading policy: this filter reads no IP; IP is read by the controller via
 * {@code request.getRemoteAddr()} only (T-1.3).
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtPort jwtPort;
  private final AuthenticationEntryPoint authenticationEntryPoint;

  public JwtAuthenticationFilter(JwtPort jwtPort, AuthenticationEntryPoint authenticationEntryPoint) {
    this.jwtPort = jwtPort;
    this.authenticationEntryPoint = authenticationEntryPoint;
  }

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
    try {
      JwtClaims claims = jwtPort.verify(rawJwt);
      List<SimpleGrantedAuthority> authorities = claims.roles().stream()
          .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
          .toList();
      UsernamePasswordAuthenticationToken auth =
          new UsernamePasswordAuthenticationToken(claims.sub(), null, authorities);
      // stash all extra claims as details (T-3.7 — downstream reads from SecurityContext)
      auth.setDetails(Map.of(
          "tenantId", claims.tenantId(),
          "emailVerified", claims.emailVerified(),
          "tokenVersion", claims.tokenVersion()));
      SecurityContextHolder.getContext().setAuthentication(auth);
      MDC.put("userId", claims.sub());
      MDC.put("tenantId", claims.tenantId());
    } catch (AuthenticationException e) {
      SecurityContextHolder.clearContext();
      authenticationEntryPoint.commence(req, res,
          new org.springframework.security.core.AuthenticationException(e.getMessage(), e) {});
      return;
    }
    try {
      chain.doFilter(req, res);
    } finally {
      MDC.remove("userId");
      MDC.remove("tenantId");
    }
  }
}
