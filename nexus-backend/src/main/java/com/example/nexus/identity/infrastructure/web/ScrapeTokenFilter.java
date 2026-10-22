package com.example.nexus.identity.infrastructure.web;

import com.example.nexus.common.web.CorrelationIdFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates the platform metrics scrape (pre-PR security re-review RR-M2). The metrics and
 * Prometheus endpoints describe the whole platform, so no tenant credential may read them: they
 * accept only the operator-held {@code nexus.management.scrape-token}, as a bearer token, and
 * nothing else. A tenant administrator's JWT is a 401 here.
 *
 * <ul>
 *   <li>Only requests the {@code scrapeEndpoints} matcher selects are handled; every other request
 *       passes through untouched.
 *   <li>With no token configured, the endpoints are closed: 403 for everyone (fail closed).
 *   <li>A valid token authenticates the request with {@link #AUTHORITY} and tells {@link
 *       JwtAuthenticationFilter} to skip it, because a scrape token is not a JWT.
 *   <li>The comparison is between SHA-256 digests with {@link MessageDigest#isEqual}, which is
 *       constant-time. The token is never logged.
 * </ul>
 */
public final class ScrapeTokenFilter extends OncePerRequestFilter {

  /** The only authority the scrape endpoints accept. */
  public static final String AUTHORITY = "METRICS_SCRAPER";

  /** Request attribute telling {@link JwtAuthenticationFilter} that this request is handled. */
  public static final String AUTHENTICATED_ATTRIBUTE =
      ScrapeTokenFilter.class.getName() + ".authenticated";

  /** Shortest token accepted at startup: 32 characters. */
  public static final int MIN_TOKEN_LENGTH = 32;

  private static final String BEARER_PREFIX = "Bearer ";

  private final RequestMatcher scrapeEndpoints;
  private final byte[] expectedDigest;

  /**
   * Creates the filter.
   *
   * @param scrapeEndpoints selects the requests this filter guards
   * @param scrapeToken the operator's scrape token; blank closes the endpoints
   * @throws IllegalArgumentException if a non-blank token is shorter than {@value
   *     #MIN_TOKEN_LENGTH} characters
   */
  public ScrapeTokenFilter(RequestMatcher scrapeEndpoints, String scrapeToken) {
    this.scrapeEndpoints = scrapeEndpoints;
    if (scrapeToken == null || scrapeToken.isBlank()) {
      this.expectedDigest = null;
      return;
    }
    if (scrapeToken.length() < MIN_TOKEN_LENGTH) {
      throw new IllegalArgumentException(
          "nexus.management.scrape-token must be at least " + MIN_TOKEN_LENGTH + " characters");
    }
    this.expectedDigest = sha256(scrapeToken);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !scrapeEndpoints.matches(request);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    if (expectedDigest == null) {
      write(res, HttpStatus.FORBIDDEN, "Forbidden", "ACCESS_DENIED");
      return;
    }
    String header = req.getHeader(HttpHeaders.AUTHORIZATION);
    if (header == null
        || !header.startsWith(BEARER_PREFIX)
        || !MessageDigest.isEqual(expectedDigest, sha256(header.substring(BEARER_PREFIX.length())))) {
      write(res, HttpStatus.UNAUTHORIZED, "Unauthorized", "AUTH_003");
      return;
    }
    req.setAttribute(AUTHENTICATED_ATTRIBUTE, Boolean.TRUE);
    SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(
            "metrics-scraper", null, List.of(new SimpleGrantedAuthority(AUTHORITY))));
    chain.doFilter(req, res);
  }

  private static byte[] sha256(String value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required by the Java platform", e);
    }
  }

  private static void write(HttpServletResponse res, HttpStatus status, String title, String code)
      throws IOException {
    String traceId = MDC.get(CorrelationIdFilter.MDC_KEY);
    res.setStatus(status.value());
    res.setContentType("application/problem+json");
    res.getWriter().write("{\"status\":" + status.value() + ",\"title\":\"" + title
        + "\",\"code\":\"" + code + "\",\"traceId\":\"" + (traceId != null ? traceId : "") + "\"}");
  }
}
