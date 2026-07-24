package com.example.nexus.common.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.infrastructure.web.JwtAuthenticationFilter;
import jakarta.servlet.FilterChain;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Exercises the real {@link JwtAuthenticationFilter} → {@link SecurityContextHolder} →
 * {@link AuthenticatedRequestDetails} path end to end via the public {@code doFilter} entry
 * point, guarding against the two sides of the {@code Authentication.getDetails()} contract
 * (production filter and consumer) drifting apart on key names (T-06).
 */
@Tag("UnitTest")
class AuthenticationDetailsContractTest {

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

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void should_produceConsumableDetails_when_filterPopulatesAuthenticationFromValidJwt()
      throws Exception {
    JwtClaims claims = new JwtClaims(
        "user-uuid-1",
        "tenant-uuid-1",
        true,
        List.of("USER"),
        List.of("user:read"),
        1000L,
        1900L,
        "jti-abc",
        1,
        JwtClaims.CURRENT_VERSION);
    when(jwtPort.verify("valid.jwt.token")).thenReturn(claims);

    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("Authorization", "Bearer valid.jwt.token");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(req, res, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertThat(auth).isNotNull();

    AuthenticatedRequestDetails details =
        AuthenticatedRequestDetails.fromAuthentication(auth, "user:read");

    assertThat(details.tenantId()).isEqualTo("tenant-uuid-1");
    assertThat(details.permissions()).containsExactly("user:read");
    assertThat(details.hasPermission("user:read")).isTrue();
    assertThat(details.hasPermission("user:delete")).isFalse();
  }
}
