package com.example.nexus.identity.infrastructure.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.infrastructure.security.JwtRs256Service;
import com.example.nexus.identity.infrastructure.security.RsaKeyConfig;
import com.example.nexus.rbac.application.RoleResolutionService;
import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

@Tag("UnitTest")
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
        .containsEntry("tokenVersion", 1)
        .containsEntry("permissions", List.of("user:read"));
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

  /**
   * US-018 T-005 / TS-10: a validly signed token without {@code tenant_id} used to pass
   * {@code verify()} with a null tenant and NPE in the filter's {@code Map.of} (a 500). Through
   * the real verifier it must now reach the entry point as a 401, with nothing escaping the filter.
   */
  @Test
  void should_return401AndNeverThrow_when_bearerTokenMissingTenantId() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair keyPair = kpg.generateKeyPair();
    RsaKeyConfig rsaKeyConfig = mock(RsaKeyConfig.class);
    when(rsaKeyConfig.getKeyPair()).thenReturn(keyPair);
    when(rsaKeyConfig.getKid()).thenReturn("test-kid");
    JwtRs256Service realVerifier = new JwtRs256Service(
        rsaKeyConfig,
        UUID::randomUUID,
        Clock.systemUTC(),
        900L,
        mock(RoleResolutionService.class),
        new SimpleMeterRegistry());
    AuthenticationEntryPoint unauthorized =
        (request, response, authException) -> response.setStatus(401);
    JwtAuthenticationFilter realFilter = new JwtAuthenticationFilter(realVerifier, unauthorized);

    Instant now = Instant.now();
    String tokenWithoutTenant = Jwts.builder()
        .subject(UUID.randomUUID().toString())
        // "tenant_id" claim intentionally omitted
        .claim("email_verified", true)
        .claim("roles", List.of("USER"))
        .claim("permissions", List.of("user:read"))
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(900)))
        .id(UUID.randomUUID().toString())
        .claim("token_version", 0)
        .claim("schema_version", JwtClaims.CURRENT_VERSION)
        .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
        .compact();
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("Authorization", "Bearer " + tokenWithoutTenant);
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    assertThatCode(() -> realFilter.doFilterInternal(req, res, chain))
        .doesNotThrowAnyException();
    assertThat(res.getStatus()).isEqualTo(401);
    verify(chain, never()).doFilter(any(), any());
  }
}
