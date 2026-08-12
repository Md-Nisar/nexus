package com.example.nexus.identity.infrastructure.web;

import com.example.nexus.common.web.CorrelationIdFilter;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Servlet filter that enforces sliding-window rate limits on the auth endpoints before any
 * Spring MVC processing occurs.
 *
 * <ul>
 *   <li>{@code POST /api/v1/auth/login} — IP bucket: {@code ip-max-attempts} per
 *       {@code ip-window-seconds}; user bucket: {@code user-max-attempts} per
 *       {@code user-window-seconds} keyed by email HMAC. Body is read, parsed for email,
 *       then replayed to the downstream handler.
 *   <li>{@code POST /api/v1/auth/refresh} — {@code refresh-max-attempts} per
 *       {@code ip-window-seconds} per IP only (no body).
 * </ul>
 *
 * <p>On a rate-limit breach, writes a 429 RFC 7807 problem document directly to the response
 * (before {@code @ControllerAdvice}) and sets the {@code Retry-After} header.
 *
 * <p><strong>T-1.3:</strong> Client IP is obtained exclusively from
 * {@code request.getRemoteAddr()}. Never {@code X-Forwarded-For}.
 *
 * <p><strong>Deployment precondition (DF-1):</strong> The IP bucket key is derived exclusively
 * from {@code request.getRemoteAddr()} — never {@code X-Forwarded-For}. This control is only
 * effective when Nexus runs as a single instance with direct client TCP connections (no reverse
 * proxy or load balancer). Behind a proxy, {@code getRemoteAddr()} returns the proxy IP and all
 * users collapse into one bucket. DB-level account lockout ({@link
 * com.example.nexus.identity.application.service.LoginUseCase}) remains globally authoritative
 * regardless of deployment topology.
 */
@Component
@SuppressWarnings("java:S1075")
public class LoginRateLimitFilter extends OncePerRequestFilter {

  private static final String LOGIN_PATH = "/api/v1/auth/login";
  private static final String REFRESH_PATH = "/api/v1/auth/refresh";
  private static final String FORGOT_PATH = "/api/v1/auth/password/forgot";
  private static final String RESET_PATH = "/api/v1/auth/password/reset";

  // Vanilla mapper — only reads top-level "email" string; no app-level customisations needed
  private static final ObjectMapper BODY_PARSER = new ObjectMapper();

  private final RateLimitStore rateLimitStore;
  private final EmailBlindIndexService emailBlindIndexService;
  private final int ipMaxAttempts;
  private final int ipWindowSeconds;
  private final int userMaxAttempts;
  private final int userWindowSeconds;
  private final int refreshMaxAttempts;
  private final int forgotIpMaxAttempts;
  private final int resetIpMaxAttempts;

  public LoginRateLimitFilter(
      RateLimitStore rateLimitStore,
      EmailBlindIndexService emailBlindIndexService,
      @Value("${nexus.security.rate-limit.ip-max-attempts}") int ipMaxAttempts,
      @Value("${nexus.security.rate-limit.ip-window-seconds}") int ipWindowSeconds,
      @Value("${nexus.security.rate-limit.user-max-attempts}") int userMaxAttempts,
      @Value("${nexus.security.rate-limit.user-window-seconds}") int userWindowSeconds,
      @Value("${nexus.security.rate-limit.refresh-max-attempts}") int refreshMaxAttempts,
      @Value("${nexus.security.rate-limit.forgot-ip-max-attempts}") int forgotIpMaxAttempts,
      @Value("${nexus.security.rate-limit.reset-ip-max-attempts}") int resetIpMaxAttempts) {
    this.rateLimitStore = rateLimitStore;
    this.emailBlindIndexService = emailBlindIndexService;
    this.ipMaxAttempts = ipMaxAttempts;
    this.ipWindowSeconds = ipWindowSeconds;
    this.userMaxAttempts = userMaxAttempts;
    this.userWindowSeconds = userWindowSeconds;
    this.refreshMaxAttempts = refreshMaxAttempts;
    this.forgotIpMaxAttempts = forgotIpMaxAttempts;
    this.resetIpMaxAttempts = resetIpMaxAttempts;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    if (!HttpMethod.POST.name().equalsIgnoreCase(request.getMethod())) {
      return true;
    }
    String path = request.getRequestURI();
    return !LOGIN_PATH.equals(path) && !REFRESH_PATH.equals(path)
        && !FORGOT_PATH.equals(path) && !RESET_PATH.equals(path);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    // T-1.3: getRemoteAddr() only — never X-Forwarded-For
    String clientIp = request.getRemoteAddr();
    String path = request.getRequestURI();

    if (LOGIN_PATH.equals(path)) {
      handleLogin(request, response, chain, clientIp);
    } else if (FORGOT_PATH.equals(path)) {
      handleForgot(request, response, chain, clientIp);
    } else if (RESET_PATH.equals(path)) {
      handleReset(request, response, chain, clientIp);
    } else {
      handleRefresh(request, response, chain, clientIp);
    }
  }

  // A valid login JSON body is well under 1 KB; 8 KB guards against heap-exhaustion DoS
  // without blocking any realistic client.
  private static final int MAX_LOGIN_BODY_BYTES = 8_192;

  private void handleLogin(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain, String clientIp)
      throws ServletException, IOException {
    long declared = request.getContentLengthLong();
    if (declared > MAX_LOGIN_BODY_BYTES) {
      response.setStatus(413);
      return;
    }
    byte[] body = request.getInputStream().readNBytes(MAX_LOGIN_BODY_BYTES + 1);
    if (body.length > MAX_LOGIN_BODY_BYTES) {
      response.setStatus(413);
      return;
    }
    String emailHmac = extractEmailHmac(body);

    RateLimitResult ipResult = rateLimitStore.tryConsume("IP:" + clientIp, ipWindowSeconds, ipMaxAttempts);
    RateLimitResult userResult = emailHmac != null
        ? rateLimitStore.tryConsume("USER:" + emailHmac, userWindowSeconds, userMaxAttempts)
        : RateLimitResult.permit();

    if (!ipResult.allowed() || !userResult.allowed()) {
      long retryAfter = Math.max(ipResult.retryAfterSeconds(), userResult.retryAfterSeconds());
      writeTooManyRequests(response, retryAfter);
      return;
    }
    // Replay body so the controller's @RequestBody can still read it
    chain.doFilter(new ReplayableBodyRequest(request, body), response);
  }

  private void handleForgot(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain, String clientIp)
      throws ServletException, IOException {
    long declared = request.getContentLengthLong();
    if (declared > MAX_LOGIN_BODY_BYTES) {
      response.setStatus(413);
      return;
    }
    byte[] body = request.getInputStream().readNBytes(MAX_LOGIN_BODY_BYTES + 1);
    if (body.length > MAX_LOGIN_BODY_BYTES) {
      response.setStatus(413);
      return;
    }
    String emailHmac = extractEmailHmac(body);

    RateLimitResult ipResult = rateLimitStore.tryConsume(
        "FORGOT_IP:" + clientIp, ipWindowSeconds, forgotIpMaxAttempts);
    RateLimitResult userResult = emailHmac != null
        ? rateLimitStore.tryConsume("FORGOT_USER:" + emailHmac, userWindowSeconds, userMaxAttempts)
        : RateLimitResult.permit();

    if (!ipResult.allowed() || !userResult.allowed()) {
      long retryAfter = Math.max(ipResult.retryAfterSeconds(), userResult.retryAfterSeconds());
      writeTooManyRequests(response, retryAfter);
      return;
    }
    chain.doFilter(new ReplayableBodyRequest(request, body), response);
  }

  private void handleReset(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain, String clientIp)
      throws ServletException, IOException {
    RateLimitResult ipResult = rateLimitStore.tryConsume(
        "RESET_IP:" + clientIp, ipWindowSeconds, resetIpMaxAttempts);
    if (!ipResult.allowed()) {
      writeTooManyRequests(response, ipResult.retryAfterSeconds());
      return;
    }
    chain.doFilter(request, response);
  }

  private void handleRefresh(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain, String clientIp)
      throws ServletException, IOException {
    RateLimitResult ipResult = rateLimitStore.tryConsume(
        "REFRESH_IP:" + clientIp, ipWindowSeconds, refreshMaxAttempts);
    if (!ipResult.allowed()) {
      writeTooManyRequests(response, ipResult.retryAfterSeconds());
      return;
    }
    chain.doFilter(request, response);
  }

  private String extractEmailHmac(byte[] body) {
    try {
      JsonNode node = BODY_PARSER.readTree(body);
      JsonNode emailNode = node.get("email");
      if (emailNode != null && !emailNode.isNull()) {
        return emailBlindIndexService.blindIndex(emailNode.asText());
      }
    } catch (Exception ignored) {
      // Malformed body — skip USER key; the controller will return 400
    }
    return null;
  }

  private void writeTooManyRequests(HttpServletResponse response, long retryAfter)
      throws IOException {
    response.setStatus(429);
    response.setContentType("application/problem+json");
    response.setHeader("Retry-After", String.valueOf(retryAfter));
    String traceId = MDC.get(CorrelationIdFilter.MDC_KEY);
    String json = "{\"status\":429,\"title\":\"Too Many Requests\",\"code\":\"RATE_001\""
        + ",\"retryAfterSeconds\":" + retryAfter
        + ",\"traceId\":\"" + (traceId != null ? traceId : "") + "\"}";
    response.getWriter().write(json);
  }

  /** Replays a pre-read request body so downstream handlers can read it a second time. */
  private static final class ReplayableBodyRequest extends HttpServletRequestWrapper {

    private final byte[] body;

    ReplayableBodyRequest(HttpServletRequest request, byte[] body) {
      super(request);
      this.body = body;
    }

    @Override
    public ServletInputStream getInputStream() {
      ByteArrayInputStream bais = new ByteArrayInputStream(body);
      return new ServletInputStream() {
        @Override public boolean isFinished() { return bais.available() == 0; }
        @Override public boolean isReady() { return true; }
        @Override public void setReadListener(ReadListener listener) { /* Non-blocking IO not supported here */ }
        @Override public int read() throws IOException { return bais.read(); }
        @Override public int read(byte[] b, int off, int len) throws IOException {
          return bais.read(b, off, len);
        }
      };
    }

    @Override
    public BufferedReader getReader() {
      return new BufferedReader(new InputStreamReader(
          new ByteArrayInputStream(body), StandardCharsets.UTF_8));
    }
  }
}
