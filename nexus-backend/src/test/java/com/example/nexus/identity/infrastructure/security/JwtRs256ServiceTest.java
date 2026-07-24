package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.User;
import com.example.nexus.rbac.application.RoleResolutionService;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import io.jsonwebtoken.Jwts;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.env.Environment;

@Tag("UnitTest")
class JwtRs256ServiceTest {

  private static RsaKeyConfig rsaKeyConfig;

  @BeforeAll
  static void setUpKeyConfig() throws Exception {
    Environment devEnv = mock(Environment.class);
    when(devEnv.getActiveProfiles()).thenReturn(new String[] {"dev"});
    rsaKeyConfig = new RsaKeyConfig(devEnv);
    rsaKeyConfig.init();
  }

  private RoleResolutionService roleResolutionServiceReturning(ResolvedPermissions resolved) {
    RoleResolutionService svc = mock(RoleResolutionService.class);
    when(svc.resolve(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
        .thenReturn(resolved);
    return svc;
  }

  private JwtRs256Service service(Clock clock) {
    return service(clock, new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
  }

  private JwtRs256Service service(Clock clock, ResolvedPermissions resolved) {
    return new JwtRs256Service(
        rsaKeyConfig, UUID::randomUUID, clock, 900L, roleResolutionServiceReturning(resolved));
  }

  private JwtRs256Service service(Clock clock, RoleResolutionService roleResolutionService) {
    return new JwtRs256Service(
        rsaKeyConfig, UUID::randomUUID, clock, 900L, roleResolutionService);
  }

  private User activeUser() {
    User user = mock(User.class);
    when(user.getId()).thenReturn(UUID.randomUUID());
    when(user.getTenantId()).thenReturn(UUID.randomUUID());
    when(user.getStatus()).thenReturn(UserStatus.ACTIVE);
    when(user.getTokenVersion()).thenReturn(0);
    return user;
  }

  @Test
  void should_issueAndVerifyRoundTrip_when_validUser() {
    JwtRs256Service svc = service(Clock.systemUTC());
    User user = activeUser();

    AccessTokenResult result = svc.issue(user);
    JwtClaims claims = svc.verify(result.token());

    assertThat(claims.sub()).isEqualTo(user.getId().toString());
    assertThat(claims.tenantId()).isEqualTo(user.getTenantId().toString());
    assertThat(claims.emailVerified()).isTrue();
    assertThat(claims.roles()).containsExactly("MEMBER");
    assertThat(claims.permissions()).containsExactly("user:read");
    assertThat(claims.tokenVersion()).isZero();
    assertThat(claims.schemaVersion()).isEqualTo(JwtClaims.CURRENT_VERSION);
    assertThat(claims.jti()).isEqualTo(result.jti());
    assertThat(claims.exp() - claims.iat()).isEqualTo(900L);
  }

  @Test
  void should_includeResolvedRolesAndPermissions_when_userHasMultipleRoles() {
    ResolvedPermissions resolved =
        new ResolvedPermissions(
            List.of("MEMBER", "TENANT_ADMIN"),
            List.of("tenant:read", "tenant:write", "user:read"));
    JwtRs256Service svc = service(Clock.systemUTC(), resolved);

    AccessTokenResult result = svc.issue(activeUser());
    JwtClaims claims = svc.verify(result.token());

    assertThat(claims.roles()).containsExactlyInAnyOrder("MEMBER", "TENANT_ADMIN");
    assertThat(claims.permissions())
        .containsExactlyInAnyOrder("tenant:read", "tenant:write", "user:read");
  }

  @Test
  void should_issueEmptyClaims_when_userHasNoRoles() {
    JwtRs256Service svc = service(Clock.systemUTC(), ResolvedPermissions.empty());

    AccessTokenResult result = svc.issue(activeUser());
    JwtClaims claims = svc.verify(result.token());

    assertThat(claims.roles()).isEmpty();
    assertThat(claims.permissions()).isEmpty();
  }

  @Test
  void should_setExpiresInSeconds_when_tokenIssued() {
    JwtRs256Service svc = service(Clock.systemUTC());

    AccessTokenResult result = svc.issue(activeUser());

    assertThat(result.expiresInSeconds()).isEqualTo(900L);
    assertThat(result.jti()).isNotBlank();
    assertThat(result.token()).isNotBlank();
  }

  @Test
  void should_throwAuthException_when_tokenExpired() {
    Instant issueTime = Instant.parse("2026-01-01T00:00:00Z");
    Instant verifyTime = issueTime.plusSeconds(1800); // 30 min later — past TTL + 30s skew

    JwtRs256Service issuer = service(Clock.fixed(issueTime, ZoneOffset.UTC));
    JwtRs256Service verifier = service(Clock.fixed(verifyTime, ZoneOffset.UTC));

    AccessTokenResult result = issuer.issue(activeUser());

    assertThatThrownBy(() -> verifier.verify(result.token()))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
  }

  @Test
  void should_throwAuthException_when_tokenMalformed() {
    JwtRs256Service svc = service(Clock.systemUTC());

    assertThatThrownBy(() -> svc.verify("not.a.jwt"))
        .isInstanceOf(AuthenticationException.class);
  }

  @Test
  void should_throwAuthException_when_tokenBlank() {
    JwtRs256Service svc = service(Clock.systemUTC());

    assertThatThrownBy(() -> svc.verify(""))
        .isInstanceOf(AuthenticationException.class);
  }

  @Test
  void should_setEmailVerifiedFalse_when_userStatusNotActive() {
    JwtRs256Service svc = service(Clock.systemUTC());
    User pendingUser = mock(User.class);
    when(pendingUser.getId()).thenReturn(UUID.randomUUID());
    when(pendingUser.getTenantId()).thenReturn(UUID.randomUUID());
    when(pendingUser.getStatus()).thenReturn(UserStatus.PENDING);
    when(pendingUser.getTokenVersion()).thenReturn(0);

    AccessTokenResult result = svc.issue(pendingUser);
    JwtClaims claims = svc.verify(result.token());

    assertThat(claims.emailVerified()).isFalse();
  }

  @Test
  void should_throwAuthException_AUTH_003_when_rolesClaim_absent() {
    // C1: null roles → List.copyOf(null) NPE → must be caught and mapped to AUTH_003
    Instant now = Instant.now();
    String crafted = Jwts.builder()
        .subject(UUID.randomUUID().toString())
        .claim("tenant_id", UUID.randomUUID().toString())
        .claim("email_verified", true)
        // "roles" claim intentionally omitted
        .claim("permissions", List.of("user:read"))
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(900)))
        .id(UUID.randomUUID().toString())
        .claim("token_version", 0)
        .claim("schema_version", JwtClaims.CURRENT_VERSION)
        .signWith(rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS256)
        .compact();

    JwtRs256Service svc = service(Clock.systemUTC());
    assertThatThrownBy(() -> svc.verify(crafted))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
  }

  @Test
  void should_throwAuthException_AUTH_003_when_permissionsClaim_absent() {
    Instant now = Instant.now();
    String crafted = Jwts.builder()
        .subject(UUID.randomUUID().toString())
        .claim("tenant_id", UUID.randomUUID().toString())
        .claim("email_verified", true)
        .claim("roles", List.of("MEMBER"))
        // "permissions" claim intentionally omitted
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(900)))
        .id(UUID.randomUUID().toString())
        .claim("token_version", 0)
        .claim("schema_version", JwtClaims.CURRENT_VERSION)
        .signWith(rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS256)
        .compact();

    JwtRs256Service svc = service(Clock.systemUTC());
    assertThatThrownBy(() -> svc.verify(crafted))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
  }

  @Test
  void should_throwAuthException_AUTH_003_when_tokenVersionClaim_absent() {
    // C2: null token_version → auto-unbox to int → NPE → must be caught and mapped to AUTH_003
    Instant now = Instant.now();
    String crafted = Jwts.builder()
        .subject(UUID.randomUUID().toString())
        .claim("tenant_id", UUID.randomUUID().toString())
        .claim("email_verified", true)
        .claim("roles", List.of("USER"))
        .claim("permissions", List.of("user:read"))
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(900)))
        .id(UUID.randomUUID().toString())
        // "token_version" claim intentionally omitted
        .claim("schema_version", JwtClaims.CURRENT_VERSION)
        .signWith(rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS256)
        .compact();

    JwtRs256Service svc = service(Clock.systemUTC());
    assertThatThrownBy(() -> svc.verify(crafted))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
  }

  @Test
  void should_throwAuthException_AUTH_003_when_schemaVersionClaim_absent() {
    Instant now = Instant.now();
    String crafted = Jwts.builder()
        .subject(UUID.randomUUID().toString())
        .claim("tenant_id", UUID.randomUUID().toString())
        .claim("email_verified", true)
        .claim("roles", List.of("USER"))
        .claim("permissions", List.of("user:read"))
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(900)))
        .id(UUID.randomUUID().toString())
        .claim("token_version", 0)
        // "schema_version" claim intentionally omitted
        .signWith(rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS256)
        .compact();

    JwtRs256Service svc = service(Clock.systemUTC());
    assertThatThrownBy(() -> svc.verify(crafted))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
  }

  @Test
  void should_sourcePermissionsResolutionAndTenantClaim_fromSameTenantId_when_tokenIssued() {
    RoleResolutionService roleResolutionService = mock(RoleResolutionService.class);
    ArgumentCaptor<UUID> tenantIdCaptor = ArgumentCaptor.forClass(UUID.class);
    when(roleResolutionService.resolve(any(), tenantIdCaptor.capture()))
        .thenReturn(new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
    JwtRs256Service svc = service(Clock.systemUTC(), roleResolutionService);
    User user = activeUser();

    AccessTokenResult result = svc.issue(user);
    JwtClaims claims = svc.verify(result.token());

    assertThat(tenantIdCaptor.getValue()).isEqualTo(user.getTenantId());
    assertThat(claims.tenantId()).isEqualTo(tenantIdCaptor.getValue().toString());
  }
}
