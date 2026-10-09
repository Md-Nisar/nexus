package com.example.nexus.common.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.infrastructure.web.JwtAuthenticationFilter;
import com.example.nexus.identity.infrastructure.web.PublicEndpointRequestMatcher;
import com.example.nexus.rbac.application.FreshnessVerdict;
import com.example.nexus.rbac.application.PermissionFreshnessService;
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

  private static final String TENANT_ID = "00000000-0000-7000-8000-0000000000a1";

  private JwtPort jwtPort;
  private AuthenticationEntryPoint entryPoint;
  private PublicEndpointRequestMatcher publicEndpoints;
  private JwtAuthenticationFilter filter;

  @BeforeEach
  void setUp() {
    jwtPort = mock(JwtPort.class);
    entryPoint = mock(AuthenticationEntryPoint.class);
    publicEndpoints = mock(PublicEndpointRequestMatcher.class);
    PermissionFreshnessService freshness = mock(PermissionFreshnessService.class);
    when(freshness.check(any(), any(), anyLong(), anyLong())).thenReturn(FreshnessVerdict.FRESH);
    filter = new JwtAuthenticationFilter(jwtPort, entryPoint, publicEndpoints, freshness);
    SecurityContextHolder.clearContext();
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void should_produceConsumableDetails_when_filterPopulatesAuthenticationFromValidJwt()
      throws Exception {
    when(jwtPort.verify("valid.jwt.token")).thenReturn(claims());

    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("Authorization", "Bearer valid.jwt.token");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(req, res, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertThat(auth).isNotNull();

    AuthenticatedRequestDetails details =
        AuthenticatedRequestDetails.fromAuthentication(auth, "user:read");

    assertThat(details.tenantId()).isEqualTo(TENANT_ID);
    assertThat(details.permissions()).containsExactly("user:read");
    assertThat(details.hasPermission("user:read")).isTrue();
    assertThat(details.hasPermission("user:delete")).isFalse();
  }

  /**
   * US-018 RC-44.2: the permission-free principal set on a {@code @PublicEndpoint} request is a
   * well-formed snapshot that holds no permission, so it can never satisfy
   * {@code @RequiresPermission}.
   */
  @Test
  void should_denyEveryPermission_when_publicRequestPrincipalHasEmptyPermissions()
      throws Exception {
    when(jwtPort.verify("valid.jwt.token")).thenReturn(claims());
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("Authorization", "Bearer valid.jwt.token");
    when(publicEndpoints.matches(req)).thenReturn(true);

    filter.doFilter(req, new MockHttpServletResponse(), mock(FilterChain.class));

    AuthenticatedRequestDetails details = AuthenticatedRequestDetails.fromAuthentication(
        SecurityContextHolder.getContext().getAuthentication(), "user:read");
    assertThat(details.permissions()).isEmpty();
    assertThat(details.hasPermission("user:read")).isFalse();
  }

  private static JwtClaims claims() {
    return new JwtClaims(
        "00000000-0000-7000-8000-0000000000b1",
        TENANT_ID,
        true,
        List.of("USER"),
        List.of("user:read"),
        1000L,
        1900L,
        "jti-abc",
        1,
        JwtClaims.CURRENT_VERSION,
        0L);
  }
}
