package com.example.nexus.common.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

@Tag("UnitTest")
class ApiRequestLoggingFilterTest {

  private ApiRequestLoggingFilter filter;
  private HttpServletRequest request;
  private HttpServletResponse response;
  private FilterChain filterChain;

  @BeforeEach
  void setUp() {
    filter = new ApiRequestLoggingFilter();
    request = mock(HttpServletRequest.class);
    response = mock(HttpServletResponse.class);
    filterChain = mock(FilterChain.class);
    MDC.clear();
  }

  @Test
  void shouldSkipExcludes() throws ServletException, IOException {
    when(request.getRequestURI()).thenReturn("/actuator/health");

    filter.doFilter(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
  }

  @Test
  void shouldLogNormalRequestCompletion() throws ServletException, IOException {
    when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
    when(request.getMethod()).thenReturn("POST");
    when(response.getStatus()).thenReturn(200);
    MDC.put(CorrelationIdFilter.MDC_CORRELATION_ID_KEY, "test-corr-id");

    filter.doFilter(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
    assertEquals("test-corr-id", MDC.get(CorrelationIdFilter.MDC_CORRELATION_ID_KEY));
  }

  @Test
  void shouldLogClientDisconnectAs499() throws ServletException, IOException {
    when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
    when(request.getMethod()).thenReturn("POST");
    doThrow(new IOException("Connection reset by peer")).when(filterChain).doFilter(request, response);

    assertThrows(IOException.class, () -> filter.doFilter(request, response, filterChain));
  }

  @Test
  void shouldLogGenericFailureAs500() throws ServletException, IOException {
    when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
    when(request.getMethod()).thenReturn("POST");
    doThrow(new RuntimeException("Database error")).when(filterChain).doFilter(request, response);

    assertThrows(RuntimeException.class, () -> filter.doFilter(request, response, filterChain));
  }
}
