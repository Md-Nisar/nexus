package com.example.nexus.identity.infrastructure.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.rbac.application.PermissionFreshnessService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Unit test verifying that {@link JwtAuthenticationFilter} matches public documentation
 * and health endpoints even with non-canonical paths, preventing false 401 rejections ([OR-3.1-02]).
 */
@Tag("UnitTest")
class JwtAuthenticationFilterPathMatchTest {

  private JwtPort jwtPort;
  private AuthenticationEntryPoint authenticationEntryPoint;
  private PublicEndpointRequestMatcher publicEndpoints;
  private PermissionFreshnessService permissionFreshness;
  private JwtAuthenticationFilter filter;

  @BeforeEach
  void setUp() {
    jwtPort = mock(JwtPort.class);
    authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
    publicEndpoints = mock(PublicEndpointRequestMatcher.class);
    permissionFreshness = mock(PermissionFreshnessService.class);
    filter = new JwtAuthenticationFilter(
        jwtPort, authenticationEntryPoint, publicEndpoints, permissionFreshness);
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "/swagger-ui/index.html",
      "/swagger-ui.html",
      "//swagger-ui//index.html",
      "/v3/api-docs",
      "/v3/api-docs/swagger-config",
      "/actuator/health",
      "/actuator/health/readiness",
      "/actuator/info"
  })
  void should_match_public_endpoints_with_non_canonical_paths(String path) throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    request.addHeader("Authorization", "Bearer invalid-or-expired-token");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    when(publicEndpoints.matches(request)).thenReturn(false);
    when(jwtPort.verify("invalid-or-expired-token"))
        .thenThrow(new AuthenticationException("AUTH_003", "Token expired"));

    filter.doFilter(request, response, chain);

    // Filter must allow public request to proceed to chain without 401 rejection
    verify(chain).doFilter(request, response);
    verify(authenticationEntryPoint, never()).commence(any(), any(), any());
  }

  @Test
  void should_reject_protected_endpoints_on_invalid_token() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/roles");
    request.addHeader("Authorization", "Bearer invalid-token");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    when(publicEndpoints.matches(request)).thenReturn(false);
    when(jwtPort.verify("invalid-token"))
        .thenThrow(new AuthenticationException("AUTH_003", "Token invalid"));

    filter.doFilter(request, response, chain);

    // Protected request must NOT proceed to chain and must be rejected
    verify(chain, never()).doFilter(any(), any());
    verify(authenticationEntryPoint).commence(any(), any(), any());
  }
}
