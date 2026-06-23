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
 *   <li>{@code POST /api/v1/auth/login} — 5 attempts per window per IP and per email HMAC.
 *       Body is read, parsed for email, then replayed to the downstream handler.
 *   <li>{@code POST /api/v1/auth/refresh} — 30 attempts per window per IP only (no body).
 * </ul>
 *
 * <p>On a rate-limit breach, writes a 429 RFC 7807 problem document directly to the response
 * (before {@code @ControllerAdvice}) and sets the {@code Retry-After} header.
 *
 * <p><strong>T-1.3:</strong> Client IP is obtained exclusively from
 * {@code request.getRemoteAddr()}. Never {@code X-Forwarded-For}.
 */
@Component
public class LoginRateLimitFilter extends OncePerRequestFilter {

  private static final String LOGIN_PATH = "/api/v1/auth/login";
  private static final String REFRESH_PATH = "/api/v1/auth/refresh";

  // Vanilla mapper — only reads top-level "email" string; no app-level customisations needed
  private static final ObjectMapper BODY_PARSER = new ObjectMapper();

  private final RateLimitStore rateLimitStore;
  private final EmailBlindIndexService emailBlindIndexService;
  private final int maxAttempts;
  private final int windowSeconds;
  private final int refreshMaxAttempts;

  public LoginRateLimitFilter(
      RateLimitStore rateLimitStore,
      EmailBlindIndexService emailBlindIndexService,
      @Value("${nexus.security.rate-limit.max-attempts}") int maxAttempts,
      @Value("${nexus.security.rate-limit.window-seconds}") int windowSeconds) {
    this.rateLimitStore = rateLimitStore;
    this.emailBlindIndexService = emailBlindIndexService;
    this.maxAttempts = maxAttempts;
    this.windowSeconds = windowSeconds;
    this.refreshMaxAttempts = 30;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    if (!HttpMethod.POST.name().equalsIgnoreCase(request.getMethod())) {
      return true;
    }
    String path = request.getRequestURI();
    return !LOGIN_PATH.equals(path) && !REFRESH_PATH.equals(path);
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

    RateLimitResult ipResult = rateLimitStore.tryConsume("IP:" + clientIp, windowSeconds, maxAttempts);
    RateLimitResult userResult = emailHmac != null
        ? rateLimitStore.tryConsume("USER:" + emailHmac, windowSeconds, maxAttempts)
        : RateLimitResult.permit();

    if (!ipResult.allowed() || !userResult.allowed()) {
      long retryAfter = Math.max(ipResult.retryAfterSeconds(), userResult.retryAfterSeconds());
      writeTooManyRequests(response, retryAfter);
      return;
    }
    // Replay body so the controller's @RequestBody can still read it
    chain.doFilter(new ReplayableBodyRequest(request, body), response);
  }

  private void handleRefresh(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain, String clientIp)
      throws ServletException, IOException {
    RateLimitResult ipResult = rateLimitStore.tryConsume(
        "REFRESH_IP:" + clientIp, windowSeconds, refreshMaxAttempts);
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
        @Override public void setReadListener(ReadListener listener) { }
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
