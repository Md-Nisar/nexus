package com.example.nexus.identity.infrastructure.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.infrastructure.security.JwtRs256Service;
import com.example.nexus.identity.infrastructure.security.RsaKeyConfig;
import com.example.nexus.rbac.application.FreshnessVerdict;
import com.example.nexus.rbac.application.PermissionFreshnessService;
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

  private static final String USER_ID = "00000000-0000-7000-8000-0000000000b1";
  private static final String TENANT_ID = "00000000-0000-7000-8000-0000000000a1";
  private static final long TOKEN_EPOCH = 1_796_000_000_000L;

  private JwtPort jwtPort;
  private AuthenticationEntryPoint entryPoint;
  private PublicEndpointRequestMatcher publicEndpoints;
  private PermissionFreshnessService freshness;
  private JwtAuthenticationFilter filter;

  @BeforeEach
  void setUp() {
    jwtPort = mock(JwtPort.class);
    entryPoint = mock(AuthenticationEntryPoint.class);
    publicEndpoints = mock(PublicEndpointRequestMatcher.class);
    freshness = mock(PermissionFreshnessService.class);
    when(freshness.check(any(), any(), anyLong(), anyLong())).thenReturn(FreshnessVerdict.FRESH);
    filter = new JwtAuthenticationFilter(jwtPort, entryPoint, publicEndpoints, freshness);
    SecurityContextHolder.clearContext();
  }

  private static JwtClaims claims() {
    return new JwtClaims(
        USER_ID,
        TENANT_ID,
        true,
        List.of("USER"),
        List.of("user:read"),
        1000L,
        1900L,
        "jti-abc",
        1,
        JwtClaims.CURRENT_VERSION,
        TOKEN_EPOCH);
  }

  private static MockHttpServletRequest bearerRequest(String token) {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("Authorization", "Bearer " + token);
    return req;
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
    JwtClaims claims = claims();

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
    assertThat(auth.getPrincipal()).isEqualTo(USER_ID);
    assertThat(auth.getAuthorities()).hasSize(1)
        .anySatisfy(a -> assertThat(a.getAuthority()).isEqualTo("ROLE_USER"));

    @SuppressWarnings("unchecked")
    Map<String, Object> details = (Map<String, Object>) auth.getDetails();
    assertThat(details)
        .containsEntry("tenantId", TENANT_ID)
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
        freshness,
        new SimpleMeterRegistry());
    AuthenticationEntryPoint unauthorized =
        (request, response, authException) -> response.setStatus(401);
    JwtAuthenticationFilter realFilter =
        new JwtAuthenticationFilter(realVerifier, unauthorized, publicEndpoints, freshness);

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
  // -----------------------------------------------------------------------
  // US-018 T-009 (A9): one epoch check per non-public request
  // -----------------------------------------------------------------------

  @Test
  void should_return401Auth003AndSkipChain_when_staleEpochOnNonPublicRequest() throws Exception {
    MockHttpServletRequest req = bearerRequest("stale.jwt");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    when(jwtPort.verify("stale.jwt")).thenReturn(claims());
    when(freshness.check(any(), any(), anyLong(), anyLong())).thenReturn(FreshnessVerdict.STALE);

    filter.doFilterInternal(req, res, chain);

    verify(entryPoint).commence(eq(req), eq(res), any());
    verify(chain, never()).doFilter(any(), any());
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  @Test
  void should_proceedWithPrincipal_when_verdictSkippedError() throws Exception {
    MockHttpServletRequest req = bearerRequest("valid.jwt");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    when(jwtPort.verify("valid.jwt")).thenReturn(claims());
    when(freshness.check(any(), any(), anyLong(), anyLong())).thenReturn(FreshnessVerdict.SKIPPED_ERROR);

    filter.doFilterInternal(req, res, chain);

    verify(chain).doFilter(req, res);
    verify(entryPoint, never()).commence(any(), any(), any());
    assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal())
        .isEqualTo(USER_ID);
  }

  @Test
  void should_checkEpochExactlyOnceWithTokenTenantUserEpoch_when_nonPublicVerified()
      throws Exception {
    when(jwtPort.verify("valid.jwt")).thenReturn(claims());

    filter.doFilterInternal(
        bearerRequest("valid.jwt"), new MockHttpServletResponse(), mock(FilterChain.class));

    verify(freshness, times(1))
        .check(UUID.fromString(TENANT_ID), UUID.fromString(USER_ID), TOKEN_EPOCH, 1000L);
  }

  @Test
  void should_return401AndNeverThrow_when_verifiedClaimsHaveNonUuidSubject() throws Exception {
    MockHttpServletRequest req = bearerRequest("odd.jwt");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    JwtClaims valid = claims();
    when(jwtPort.verify("odd.jwt")).thenReturn(new JwtClaims(
        "not-a-uuid", valid.tenantId(), valid.emailVerified(), valid.roles(), valid.permissions(),
        valid.iat(), valid.exp(), valid.jti(), valid.tokenVersion(), valid.schemaVersion(),
        valid.permEpoch()));

    filter.doFilterInternal(req, res, chain);

    verify(entryPoint).commence(eq(req), eq(res), any());
    verify(chain, never()).doFilter(any(), any());
    verify(freshness, never()).check(any(), any(), anyLong(), anyLong());
  }

  @Test
  void should_notCheckEpoch_when_verificationFails() throws Exception {
    when(jwtPort.verify("bad.jwt"))
        .thenThrow(new AuthenticationException("AUTH_003", "Invalid token"));

    filter.doFilterInternal(
        bearerRequest("bad.jwt"), new MockHttpServletResponse(), mock(FilterChain.class));

    verify(freshness, never()).check(any(), any(), anyLong(), anyLong());
  }

  // -----------------------------------------------------------------------
  // US-018 T-011: degraded-closed answers 503 AUTH_005, never on a public request
  // -----------------------------------------------------------------------

  @Test
  void should_return503Auth005WithRetryAfter30_when_unavailableOnNonPublicRequest()
      throws Exception {
    MockHttpServletRequest req = bearerRequest("valid.jwt");
    req.setRequestURI("/api/v1/roles");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    when(jwtPort.verify("valid.jwt")).thenReturn(claims());
    when(freshness.check(any(), any(), anyLong(), anyLong())).thenReturn(FreshnessVerdict.UNAVAILABLE);

    filter.doFilterInternal(req, res, chain);

    assertThat(res.getStatus()).isEqualTo(503);
    assertThat(res.getHeader("Retry-After")).isEqualTo("30");
    assertThat(res.getContentType()).startsWith("application/problem+json");
    assertThat(res.getContentAsString())
        .contains("\"type\":\"about:blank\"", "\"title\":\"Service Unavailable\"",
            "\"status\":503", "\"code\":\"AUTH_005\"", "\"instance\":\"/api/v1/roles\"",
            "\"traceId\":");
    verify(chain, never()).doFilter(any(), any());
    verify(entryPoint, never()).commence(any(), any(), any());
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  @Test
  void should_escapeInstanceAndTraceId_when_503BodyBuilt() throws Exception {
    MockHttpServletRequest req = bearerRequest("valid.jwt");
    req.setRequestURI("/api/\"x\\y\n");
    MockHttpServletResponse res = new MockHttpServletResponse();
    when(jwtPort.verify("valid.jwt")).thenReturn(claims());
    when(freshness.check(any(), any(), anyLong(), anyLong())).thenReturn(FreshnessVerdict.UNAVAILABLE);
    org.slf4j.MDC.put("traceId", "trace\"1");
    try {
      filter.doFilterInternal(req, res, mock(FilterChain.class));
    } finally {
      org.slf4j.MDC.remove("traceId");
    }

    assertThat(res.getContentAsString())
        .contains("\"instance\":\"/api/\\\"x\\\\y\\u000a\"", "\"traceId\":\"trace\\\"1\"");
  }

  @Test
  void should_proceed_when_degradedOpenOnNonPublicRequest() throws Exception {
    MockHttpServletRequest req = bearerRequest("valid.jwt");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    when(jwtPort.verify("valid.jwt")).thenReturn(claims());
    when(freshness.check(any(), any(), anyLong(), anyLong())).thenReturn(FreshnessVerdict.SKIPPED_DEGRADED);

    filter.doFilterInternal(req, res, chain);

    verify(chain).doFilter(req, res);
    assertThat(res.getStatus()).isEqualTo(200);
  }

  @Test
  void should_pass_when_unavailableButRequestIsPublic() throws Exception {
    MockHttpServletRequest req = bearerRequest("valid.jwt");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    when(publicEndpoints.matches(req)).thenReturn(true);
    when(jwtPort.verify("valid.jwt")).thenReturn(claims());
    when(freshness.check(any(), any(), anyLong(), anyLong())).thenReturn(FreshnessVerdict.UNAVAILABLE);

    filter.doFilterInternal(req, res, chain);

    verify(chain).doFilter(req, res);
    assertThat(res.getStatus()).isEqualTo(200);
    assertThat(res.getHeader("Retry-After")).isNull();
  }

  // -----------------------------------------------------------------------
  // US-018 T-009 (RC-24, RC-44.2): a public request is never rejected
  // -----------------------------------------------------------------------

  @Test
  void should_neverReject_and_neverCheckEpoch_when_publicRequestHasStaleBearer()
      throws Exception {
    MockHttpServletRequest req = bearerRequest("stale.jwt");
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    when(publicEndpoints.matches(req)).thenReturn(true);
    when(jwtPort.verify("stale.jwt")).thenReturn(claims());
    when(freshness.check(any(), any(), anyLong(), anyLong())).thenReturn(FreshnessVerdict.STALE);

    filter.doFilterInternal(req, res, chain);

    verify(chain).doFilter(req, res);
    verify(entryPoint, never()).commence(any(), any(), any());
    verify(freshness, never()).check(any(), any(), anyLong(), anyLong());
  }

  @Test
  void should_proceedAnonymous_when_publicRequestHasExpiredBearer() throws Exception {
    KeyPair keyPair = rsaKeyPair();
    Instant issued = Instant.now().minusSeconds(3600);
    String expired = v3Token(keyPair, issued, issued.plusSeconds(900));

    assertPublicRequestProceedsAnonymously(realVerifier(keyPair), expired);
  }

  @Test
  void should_proceedAnonymous_when_publicRequestHasBadSignatureBearer() throws Exception {
    Instant now = Instant.now();
    String foreignSigned = v3Token(rsaKeyPair(), now, now.plusSeconds(900));

    assertPublicRequestProceedsAnonymously(realVerifier(rsaKeyPair()), foreignSigned);
  }

  @Test
  void should_setPrincipalWithEmptyPermissionsAndNoAuthorities_when_publicBearerVerifies()
      throws Exception {
    MockHttpServletRequest req = bearerRequest("valid.jwt");
    FilterChain chain = mock(FilterChain.class);
    when(publicEndpoints.matches(req)).thenReturn(true);
    when(jwtPort.verify("valid.jwt")).thenReturn(claims());
    Authentication[] seen = new Authentication[1];
    doAnswer(invocation -> {
      seen[0] = SecurityContextHolder.getContext().getAuthentication();
      return null;
    }).when(chain).doFilter(any(), any());

    filter.doFilterInternal(req, new MockHttpServletResponse(), chain);

    assertThat(seen[0]).isNotNull();
    assertThat(seen[0].getPrincipal()).isEqualTo(USER_ID);
    assertThat(seen[0].isAuthenticated()).isTrue();
    assertThat(seen[0].getAuthorities()).isEmpty();
    @SuppressWarnings("unchecked")
    Map<String, Object> details = (Map<String, Object>) seen[0].getDetails();
    assertThat(details)
        .containsEntry("permissions", List.of())
        .containsEntry("tenantId", TENANT_ID);
  }

  @Test
  void should_notConsultMatcher_when_noBearer() throws Exception {
    filter.doFilterInternal(
        new MockHttpServletRequest(), new MockHttpServletResponse(), mock(FilterChain.class));

    verify(publicEndpoints, never()).matches(any());
  }

  private void assertPublicRequestProceedsAnonymously(JwtPort verifier, String token)
      throws Exception {
    JwtAuthenticationFilter realFilter =
        new JwtAuthenticationFilter(verifier, entryPoint, publicEndpoints, freshness);
    MockHttpServletRequest req = bearerRequest(token);
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    when(publicEndpoints.matches(req)).thenReturn(true);

    realFilter.doFilterInternal(req, res, chain);

    verify(chain).doFilter(req, res);
    verify(entryPoint, never()).commence(any(), any(), any());
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  private JwtRs256Service realVerifier(KeyPair keyPair) {
    RsaKeyConfig rsaKeyConfig = mock(RsaKeyConfig.class);
    when(rsaKeyConfig.getKeyPair()).thenReturn(keyPair);
    when(rsaKeyConfig.getKid()).thenReturn("test-kid");
    return new JwtRs256Service(
        rsaKeyConfig,
        UUID::randomUUID,
        Clock.systemUTC(),
        900L,
        mock(RoleResolutionService.class),
        freshness,
        new SimpleMeterRegistry());
  }

  private static KeyPair rsaKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    return kpg.generateKeyPair();
  }

  private static String v3Token(KeyPair signer, Instant issuedAt, Instant expiresAt) {
    return Jwts.builder()
        .subject(USER_ID)
        .claim("tenant_id", TENANT_ID)
        .claim("email_verified", true)
        .claim("roles", List.of("USER"))
        .claim("permissions", List.of("user:read"))
        .issuedAt(Date.from(issuedAt))
        .expiration(Date.from(expiresAt))
        .id(UUID.randomUUID().toString())
        .claim("token_version", 0)
        .claim("schema_version", 3)
        .claim("perm_epoch", TOKEN_EPOCH)
        .signWith(signer.getPrivate(), Jwts.SIG.RS256)
        .compact();
  }
}
