package com.example.nexus.identity.infrastructure.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import jakarta.servlet.FilterChain;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class LoginRateLimitFilterTest {

  private RateLimitStore rateLimitStore;
  private EmailBlindIndexService emailBlindIndexService;
  private LoginRateLimitFilter filter;

  @BeforeEach
  void setUp() {
    rateLimitStore = mock(RateLimitStore.class);
    emailBlindIndexService = mock(EmailBlindIndexService.class);
    filter = new LoginRateLimitFilter(rateLimitStore, emailBlindIndexService, 5, 300);
  }

  @Test
  void shouldNotFilter_returnsTrue_forGetOnLoginPath() {
    MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/auth/login");
    assertThat(filter.shouldNotFilter(req)).isTrue();
  }

  @Test
  void shouldNotFilter_returnsTrue_forPostOnNonAuthPath() {
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/users");
    assertThat(filter.shouldNotFilter(req)).isTrue();
  }

  @Test
  void shouldNotFilter_returnsFalse_forPostOnLoginPath() {
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
    assertThat(filter.shouldNotFilter(req)).isFalse();
  }

  @Test
  void shouldNotFilter_returnsFalse_forPostOnRefreshPath() {
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/refresh");
    assertThat(filter.shouldNotFilter(req)).isFalse();
  }

  @Test
  void doFilterInternal_loginPath_notRateLimited_passesThroughWithBody() throws Exception {
    byte[] body = "{\"email\":\"user@example.com\",\"password\":\"secret\"}"
        .getBytes(StandardCharsets.UTF_8);
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
    req.setContent(body);
    req.setRemoteAddr("10.0.0.1");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    when(emailBlindIndexService.blindIndex("user@example.com")).thenReturn("hmac-value");
    when(rateLimitStore.tryConsume(startsWith("IP:"), anyInt(), anyInt()))
        .thenReturn(RateLimitResult.permit());
    when(rateLimitStore.tryConsume(startsWith("USER:"), anyInt(), anyInt()))
        .thenReturn(RateLimitResult.permit());

    filter.doFilterInternal(req, res, chain);

    verify(chain).doFilter(any(jakarta.servlet.ServletRequest.class),
        any(jakarta.servlet.ServletResponse.class));
    assertThat(res.getStatus()).isNotEqualTo(429);
  }

  @Test
  void doFilterInternal_loginPath_ipRateLimited_writes429AndSkipsChain() throws Exception {
    byte[] body = "{\"email\":\"user@example.com\",\"password\":\"secret\"}"
        .getBytes(StandardCharsets.UTF_8);
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
    req.setContent(body);
    req.setRemoteAddr("10.0.0.1");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    when(emailBlindIndexService.blindIndex("user@example.com")).thenReturn("hmac-value");
    when(rateLimitStore.tryConsume(startsWith("IP:"), anyInt(), anyInt()))
        .thenReturn(RateLimitResult.reject(300));
    when(rateLimitStore.tryConsume(startsWith("USER:"), anyInt(), anyInt()))
        .thenReturn(RateLimitResult.permit());

    filter.doFilterInternal(req, res, chain);

    assertThat(res.getStatus()).isEqualTo(429);
    assertThat(res.getHeader("Retry-After")).isEqualTo("300");
    assertThat(res.getContentType()).contains("application/problem+json");
    assertThat(res.getContentAsString()).contains("RATE_001");
    verify(chain, never()).doFilter(
        any(jakarta.servlet.ServletRequest.class),
        any(jakarta.servlet.ServletResponse.class));
  }

  @Test
  void doFilterInternal_refreshPath_ipRateLimited_writes429AndSkipsChain() throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/refresh");
    req.setRemoteAddr("10.0.0.2");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    when(rateLimitStore.tryConsume(startsWith("REFRESH_IP:"), anyInt(), anyInt()))
        .thenReturn(RateLimitResult.reject(300));

    filter.doFilterInternal(req, res, chain);

    assertThat(res.getStatus()).isEqualTo(429);
    assertThat(res.getHeader("Retry-After")).isEqualTo("300");
    verify(chain, never()).doFilter(
        any(jakarta.servlet.ServletRequest.class),
        any(jakarta.servlet.ServletResponse.class));
  }

  @Test
  void doFilterInternal_loginPath_malformedJson_ipOnlyCheck_passes() throws Exception {
    byte[] body = "not-json".getBytes(StandardCharsets.UTF_8);
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
    req.setContent(body);
    req.setRemoteAddr("10.0.0.3");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    when(rateLimitStore.tryConsume(startsWith("IP:"), anyInt(), anyInt()))
        .thenReturn(RateLimitResult.permit());

    filter.doFilterInternal(req, res, chain);

    // malformed JSON: no USER key check, just IP passes through
    verify(chain).doFilter(
        any(jakarta.servlet.ServletRequest.class),
        any(jakarta.servlet.ServletResponse.class));
    assertThat(res.getStatus()).isNotEqualTo(429);
  }
}
