package com.example.nexus.identity.infrastructure.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.JwtClaims;
import jakarta.servlet.FilterChain;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

class JwtAuthenticationFilterTest {

  private JwtPort jwtPort;
  private AuthenticationEntryPoint entryPoint;
  private JwtAuthenticationFilter filter;

  @BeforeEach
  void setUp() {
    jwtPort = mock(JwtPort.class);
    entryPoint = mock(AuthenticationEntryPoint.class);
    filter = new JwtAuthenticationFilter(jwtPort, entryPoint);
    SecurityContextHolder.clearContext();
  }

  @Test
  void doFilter_noAuthorizationHeader_passesThrough_noSecurityContext() throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest();
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(req, res, chain);

    verify(chain).doFilter(req, res);
    verify(jwtPort, never()).verify(any());
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  @Test
  void doFilter_nonBearerScheme_passesThrough_withoutCallingJwt() throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("Authorization", "Basic dXNlcjpwYXNz");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(req, res, chain);

    verify(chain).doFilter(req, res);
    verify(jwtPort, never()).verify(any());
  }

  @Test
  void doFilter_validBearerJwt_setsAuthAndDetails_thenCallsChain() throws Exception {
    JwtClaims claims = new JwtClaims(
        "user-uuid-1", "tenant-uuid-1", true, List.of("USER"), 1000L, 1900L, "jti-abc", 1);

    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("Authorization", "Bearer valid.jwt.token");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    when(jwtPort.verify("valid.jwt.token")).thenReturn(claims);

    filter.doFilterInternal(req, res, chain);

    verify(chain).doFilter(req, res);
    verify(entryPoint, never()).commence(any(), any(), any());

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertThat(auth).isNotNull();
    assertThat(auth.getPrincipal()).isEqualTo("user-uuid-1");
    assertThat(auth.getAuthorities()).hasSize(1)
        .anySatisfy(a -> assertThat(a.getAuthority()).isEqualTo("ROLE_USER"));

    @SuppressWarnings("unchecked")
    Map<String, Object> details = (Map<String, Object>) auth.getDetails();
    assertThat(details)
        .containsEntry("tenantId", "tenant-uuid-1")
        .containsEntry("emailVerified", true)
        .containsEntry("tokenVersion", 1);
  }

  @Test
  void doFilter_invalidJwt_callsEntryPointAndSkipsChain() throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("Authorization", "Bearer bad.token");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    when(jwtPort.verify("bad.token"))
        .thenThrow(new AuthenticationException("AUTH_003", "Invalid token"));

    filter.doFilterInternal(req, res, chain);

    verify(entryPoint).commence(eq(req), eq(res), any());
    verify(chain, never()).doFilter(any(), any());
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }
}
