package com.example.nexus.common.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter that logs the completion of HTTP requests, recording HTTP method, path, response status,
 * duration, and outcome. Emits exactly one log statement per request and never logs stack traces.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class ApiRequestLoggingFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(ApiRequestLoggingFilter.class);
  private static final String LOGGED_ATTR = "api.request.logged";

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String path = request.getRequestURI();

    // Exclude health checks, actuators, api-docs, and swagger noise to prevent log pollution
    if (path.startsWith("/actuator")
        || path.startsWith("/swagger-ui")
        || path.startsWith("/v3/api-docs")
        || path.equals("/favicon.ico")) {
      filterChain.doFilter(request, response);
      return;
    }

    // Skip if we've already logged this request (OncePerRequestFilter safeguard)
    if (Boolean.TRUE.equals(request.getAttribute(LOGGED_ATTR))) {
      filterChain.doFilter(request, response);
      return;
    }

    long startTime = System.nanoTime();

    try {
      filterChain.doFilter(request, response);
      // Completed successfully (or exception was caught and handled by GlobalExceptionHandler)
      logRequest(request, response, startTime, null);
      request.setAttribute(LOGGED_ATTR, true);
    } catch (Throwable ex) {
      // Unhandled exceptions (e.g. from filters before DispatcherServlet)
      logRequest(request, response, startTime, ex);
      request.setAttribute(LOGGED_ATTR, true);
      throw ex;
    }
  }

  private void logRequest(
      HttpServletRequest request, HttpServletResponse response, long startTime, Throwable throwable) {
    long durationMs = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(
        System.nanoTime() - startTime);

    int statusCode = response.getStatus();
    if (throwable != null) {
      statusCode = isClientDisconnect(throwable) ? 499 : 500;
    }

    String outcome = (statusCode < 400) ? "SUCCESS" : "FAILURE";
    String correlationId = MDC.get(CorrelationIdFilter.MDC_CORRELATION_ID_KEY);

    var logBuilder = log.atInfo()
        .addKeyValue("event", "api_request")
        .addKeyValue("executionType", "http")
        .addKeyValue("operation", request.getMethod() + " " + request.getRequestURI())
        .addKeyValue("correlationId", correlationId)
        .addKeyValue("durationMs", durationMs)
        .addKeyValue("statusCode", statusCode)
        .addKeyValue("outcome", outcome);

    if (throwable != null) {
      logBuilder = logBuilder.addKeyValue("errorCode", "INTERNAL_ERROR");
    }

    logBuilder.log("API Request Completed: method={} path={} status={} durationMs={} outcome={} correlationId={}",
        request.getMethod(), request.getRequestURI(), statusCode, durationMs, outcome, correlationId);
  }

  private boolean isClientDisconnect(Throwable ex) {
    if (ex instanceof IOException) {
      String msg = ex.getMessage();
      if (msg != null) {
        String lower = msg.toLowerCase();
        return lower.contains("broken pipe")
            || lower.contains("connection reset")
            || lower.contains("clientabort");
      }
    }
    return false;
  }
}
