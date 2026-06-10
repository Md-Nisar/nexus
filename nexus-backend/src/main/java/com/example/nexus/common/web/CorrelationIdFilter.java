package com.example.nexus.common.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Establishes a correlation id for every request: accepted from the {@code X-Correlation-Id}
 * header when a caller propagates one, generated otherwise. The id is stored in the MDC as
 * {@code traceId} (referenced by log patterns and {@code GlobalExceptionHandler}) and echoed back
 * on the response so clients can quote it in support requests.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

  public static final String CORRELATION_HEADER = "X-Correlation-Id";
  public static final String MDC_KEY = "traceId";

  // Incoming header values are untrusted — restrict to a safe charset to prevent log injection
  private static final Pattern SAFE_ID = Pattern.compile("^[A-Za-z0-9._-]{1,64}$");

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String incoming = request.getHeader(CORRELATION_HEADER);
    String traceId = (incoming != null && SAFE_ID.matcher(incoming).matches())
        ? incoming
        : UUID.randomUUID().toString();

    MDC.put(MDC_KEY, traceId);
    response.setHeader(CORRELATION_HEADER, traceId);
    try {
      filterChain.doFilter(request, response);
    } finally {
      MDC.remove(MDC_KEY);
    }
  }
}
