package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.User;
import com.example.nexus.rbac.application.PermissionFreshnessService;
import com.example.nexus.rbac.application.PermissionFreshnessService.MintEpoch;
import com.example.nexus.rbac.application.RoleResolutionService;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.math.BigInteger;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.core.env.Environment;

@Tag("UnitTest")
class JwtRs256ServiceTest {

  private static RsaKeyConfig rsaKeyConfig;

  private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
  private final PermissionFreshnessService freshness = mock(PermissionFreshnessService.class);

  @BeforeEach
  void stubVerifiedEpochZero() {
    when(freshness.mintEpoch(
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
        .thenReturn(new MintEpoch(0L, true));
  }

  @BeforeAll
  static void setUpKeyConfig() throws Exception {
    Environment devEnv = mock(Environment.class);
    when(devEnv.getActiveProfiles()).thenReturn(new String[] {"dev"});
    rsaKeyConfig = new RsaKeyConfig(devEnv);
    rsaKeyConfig.init();
  }

  private RoleResolutionService roleResolutionServiceReturning(ResolvedPermissions resolved) {
    RoleResolutionService svc = mock(RoleResolutionService.class);
    when(svc.resolve(
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.anyLong()))
        .thenReturn(resolved);
    return svc;
  }

  private JwtRs256Service service(Clock clock) {
    return service(clock, new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
  }

  private JwtRs256Service service(Clock clock, ResolvedPermissions resolved) {
    return new JwtRs256Service(
        rsaKeyConfig,
        UUID::randomUUID,
        clock,
        900L,
        roleResolutionServiceReturning(resolved),
        freshness,
        meterRegistry);
  }

  private JwtRs256Service service(Clock clock, RoleResolutionService roleResolutionService) {
    return new JwtRs256Service(
        rsaKeyConfig, UUID::randomUUID, clock, 900L, roleResolutionService, freshness,
        meterRegistry);
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
    when(roleResolutionService.resolve(any(), tenantIdCaptor.capture(), anyLong()))
        .thenReturn(new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
    JwtRs256Service svc = service(Clock.systemUTC(), roleResolutionService);
    User user = activeUser();

    AccessTokenResult result = svc.issue(user);
    JwtClaims claims = svc.verify(result.token());

    assertThat(tenantIdCaptor.getValue()).isEqualTo(user.getTenantId());
    assertThat(claims.tenantId()).isEqualTo(tenantIdCaptor.getValue().toString());
  }

  // -----------------------------------------------------------------------
  // US-018 T-009 (A9): perm_epoch is read before permissions (MC-7a) and minted in v3
  // -----------------------------------------------------------------------

  @Test
  void should_readEpochBeforeResolvingPermissions_when_issuing() {
    RoleResolutionService roleResolutionService = roleResolutionServiceReturning(
        new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
    User user = activeUser();

    service(Clock.systemUTC(), roleResolutionService).issue(user);

    InOrder order = inOrder(freshness, roleResolutionService);
    order.verify(freshness).mintEpoch(user.getTenantId(), user.getId());
    order.verify(roleResolutionService).resolve(user.getId(), user.getTenantId(), 0L);
  }

  /**
   * US-018 T-010 (Decision 17): the permission set is cached under the epoch the token carries,
   * which is exactly the one {@code mintEpoch} returned, read before the permissions.
   */
  @Test
  void should_resolvePermissionsUnderEpochReadFirst_when_issuing() {
    RoleResolutionService roleResolutionService = roleResolutionServiceReturning(
        new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
    User user = activeUser();
    long epoch = 1_796_000_000_123L;
    when(freshness.mintEpoch(user.getTenantId(), user.getId()))
        .thenReturn(new MintEpoch(epoch, true));
    JwtRs256Service svc = service(Clock.systemUTC(), roleResolutionService);

    JwtClaims claims = svc.verify(svc.issue(user).token());

    InOrder order = inOrder(freshness, roleResolutionService);
    order.verify(freshness).mintEpoch(user.getTenantId(), user.getId());
    order.verify(roleResolutionService).resolve(user.getId(), user.getTenantId(), epoch);
    assertThat(claims.permEpoch()).isEqualTo(epoch);
  }

  /** L-3: an epoch the store did not confirm names a cache key no bump deletes. */
  @Test
  void should_resolveWithoutCache_when_epochUnverified() {
    RoleResolutionService roleResolutionService = mock(RoleResolutionService.class);
    when(roleResolutionService.resolveUncached(
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
        .thenReturn(new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
    User user = activeUser();
    when(freshness.mintEpoch(user.getTenantId(), user.getId()))
        .thenReturn(new MintEpoch(1_796_000_000_000L, false));

    JwtRs256Service svc = service(Clock.systemUTC(), roleResolutionService);
    JwtClaims claims = svc.verify(svc.issue(user).token());

    org.mockito.Mockito.verify(roleResolutionService)
        .resolveUncached(user.getId(), user.getTenantId());
    org.mockito.Mockito.verify(roleResolutionService, org.mockito.Mockito.never())
        .resolve(
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.anyLong());
    assertThat(claims.permEpoch()).isEqualTo(1_796_000_000_000L);
  }

  @Test
  void should_resolveWithCacheUnderEpoch_when_epochVerified() {
    RoleResolutionService roleResolutionService = roleResolutionServiceReturning(
        new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
    User user = activeUser();
    when(freshness.mintEpoch(user.getTenantId(), user.getId()))
        .thenReturn(new MintEpoch(1_796_000_000_000L, true));

    service(Clock.systemUTC(), roleResolutionService).issue(user);

    org.mockito.Mockito.verify(roleResolutionService)
        .resolve(user.getId(), user.getTenantId(), 1_796_000_000_000L);
    org.mockito.Mockito.verify(roleResolutionService, org.mockito.Mockito.never())
        .resolveUncached(
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
  }

  @Test
  void should_mintV3WithPermEpoch_when_epochReadSucceeds() {
    User user = activeUser();
    when(freshness.mintEpoch(user.getTenantId(), user.getId()))
        .thenReturn(new MintEpoch(1_796_000_000_000L, true));
    JwtRs256Service svc = service(Clock.systemUTC());

    JwtClaims claims = svc.verify(svc.issue(user).token());

    assertThat(claims.schemaVersion()).isEqualTo(3);
    assertThat(claims.permEpoch()).isEqualTo(1_796_000_000_000L);
  }

  @Test
  void should_mintPermEpochZero_when_mintEpochReturnsZero() {
    JwtRs256Service svc = service(Clock.systemUTC());

    JwtClaims claims = svc.verify(svc.issue(activeUser()).token());

    assertThat(claims.permEpoch()).isZero();
  }

  @Test
  void should_verifyV2TokenAsEpochZero() {
    JwtClaims verified = service(Clock.systemUTC()).verify(signedToken(validClaims(2)));

    assertThat(verified.permEpoch()).isZero();
  }

  @Test
  void should_returnPermEpoch_when_v3TokenVerified() {
    Map<String, Object> claims = validClaims(3);
    claims.put("perm_epoch", 1_759_000_000_000L);

    assertThat(service(Clock.systemUTC()).verify(signedToken(claims)).permEpoch())
        .isEqualTo(1_759_000_000_000L);
  }

  @Test
  void should_returnPermEpoch_when_v3TokenEpochFitsInInteger() {
    Map<String, Object> claims = validClaims(3);
    claims.put("perm_epoch", 7);

    assertThat(service(Clock.systemUTC()).verify(signedToken(claims)).permEpoch()).isEqualTo(7L);
  }

  @Test
  void should_returnPermEpoch_when_v3TokenEpochIsLongMaxValue() {
    Map<String, Object> claims = validClaims(3);
    claims.put("perm_epoch", Long.MAX_VALUE);

    assertThat(service(Clock.systemUTC()).verify(signedToken(claims)).permEpoch())
        .isEqualTo(Long.MAX_VALUE);
  }

  @Test
  void should_rejectWithPermEpochReason_when_v3PermEpochExceedsLongRange() {
    Map<String, Object> claims = validClaims(3);
    claims.put("perm_epoch", BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE));

    assertRejectedWithReason(signedToken(claims), "perm_epoch");
  }

  @Test
  void should_ignorePermEpochClaim_when_v2TokenCarriesOne() {
    Map<String, Object> claims = validClaims(2);
    claims.put("perm_epoch", 1_759_000_000_000L);

    assertThat(service(Clock.systemUTC()).verify(signedToken(claims)).permEpoch()).isZero();
  }

  // -----------------------------------------------------------------------
  // US-018 T-005 (A11): schema_version must be in JwtClaims.ACCEPTED_VERSIONS (Decision 18)
  // -----------------------------------------------------------------------

  @Test
  void should_rejectWithSchemaVersionReason_when_schemaVersionIs1() {
    Map<String, Object> claims = validClaims(2);
    claims.put("schema_version", 1);

    assertRejectedWithReason(signedToken(claims), "schema_version");
  }

  @Test
  void should_rejectWithSchemaVersionReason_when_schemaVersionIs4() {
    Map<String, Object> claims = validClaims(3);
    claims.put("schema_version", 4);

    assertRejectedWithReason(signedToken(claims), "schema_version");
  }

  @Test
  void should_rejectWithSchemaVersionReason_when_schemaVersionIsString() {
    Map<String, Object> claims = validClaims(2);
    claims.put("schema_version", "2");

    assertRejectedWithReason(signedToken(claims), "schema_version");
  }

  @Test
  void should_rejectWithSchemaVersionReason_when_schemaVersionAbsent() {
    Map<String, Object> claims = validClaims(2);
    claims.remove("schema_version");

    assertRejectedWithReason(signedToken(claims), "schema_version");
  }

  @Test
  void should_acceptToken_when_schemaVersionIs2() {
    JwtClaims verified = service(Clock.systemUTC()).verify(signedToken(validClaims(2)));

    assertThat(verified.schemaVersion()).isEqualTo(2);
  }

  @Test
  void should_acceptToken_when_schemaVersionIs2WithoutPermEpoch() {
    Map<String, Object> claims = validClaims(2);

    assertThat(claims).doesNotContainKey("perm_epoch");
    assertThat(service(Clock.systemUTC()).verify(signedToken(claims)).schemaVersion())
        .isEqualTo(2);
  }

  @Test
  void should_acceptToken_when_schemaVersionIs3WithValidPermEpoch() {
    JwtClaims verified = service(Clock.systemUTC()).verify(signedToken(validClaims(3)));

    assertThat(verified.schemaVersion()).isEqualTo(3);
  }

  @Test
  void should_acceptToken_when_schemaVersionIs3WithPermEpochZero() {
    Map<String, Object> claims = validClaims(3);
    claims.put("perm_epoch", 0);

    assertThat(service(Clock.systemUTC()).verify(signedToken(claims)).schemaVersion())
        .isEqualTo(3);
  }

  @Test
  void should_acceptToken_when_schemaVersionIs3WithMillisecondPermEpoch() {
    // A Redis TIME millisecond value exceeds Integer.MAX_VALUE, so it deserializes as a Long.
    Map<String, Object> claims = validClaims(3);
    claims.put("perm_epoch", 1_759_000_000_000L);

    assertThat(service(Clock.systemUTC()).verify(signedToken(claims)).schemaVersion())
        .isEqualTo(3);
  }

  // -----------------------------------------------------------------------
  // US-018 T-005 (RC-40.1): v3 requires perm_epoch present and a non-negative long
  // -----------------------------------------------------------------------

  @Test
  void should_rejectWithPermEpochReason_when_schemaVersion3AndPermEpochMissing() {
    Map<String, Object> claims = validClaims(3);
    claims.remove("perm_epoch");

    assertRejectedWithReason(signedToken(claims), "perm_epoch");
  }

  @Test
  void should_rejectWithPermEpochReason_when_schemaVersion3AndPermEpochNegative() {
    Map<String, Object> claims = validClaims(3);
    claims.put("perm_epoch", -1);

    assertRejectedWithReason(signedToken(claims), "perm_epoch");
  }

  @Test
  void should_rejectWithPermEpochReason_when_schemaVersion3AndPermEpochIsString() {
    Map<String, Object> claims = validClaims(3);
    claims.put("perm_epoch", "5");

    assertRejectedWithReason(signedToken(claims), "perm_epoch");
  }

  @Test
  void should_rejectWithPermEpochReason_when_schemaVersion3AndPermEpochIsFractional() {
    Map<String, Object> claims = validClaims(3);
    claims.put("perm_epoch", 1.5);

    assertRejectedWithReason(signedToken(claims), "perm_epoch");
  }

  // -----------------------------------------------------------------------
  // US-018 T-005 (A11): tenant_id must be present and a canonical UUID string
  // -----------------------------------------------------------------------

  @Test
  void should_rejectWithTenantIdReason_when_tenantIdAbsent() {
    Map<String, Object> claims = validClaims(2);
    claims.remove("tenant_id");

    assertRejectedWithReason(signedToken(claims), "tenant_id");
  }

  @Test
  void should_rejectWithTenantIdReason_when_tenantIdNotAUuid() {
    Map<String, Object> claims = validClaims(2);
    claims.put("tenant_id", "t-1");

    assertRejectedWithReason(signedToken(claims), "tenant_id");
  }

  @Test
  void should_rejectWithTenantIdReason_when_tenantIdNotCanonicalUuid() {
    // UUID.fromString is lenient and parses this; the canonical round-trip check must not.
    Map<String, Object> claims = validClaims(2);
    claims.put("tenant_id", "1-1-1-1-1");

    assertRejectedWithReason(signedToken(claims), "tenant_id");
  }

  @Test
  void should_rejectWithTenantIdReason_when_tenantIdNotAString() {
    Map<String, Object> claims = validClaims(2);
    claims.put("tenant_id", 42);

    assertRejectedWithReason(signedToken(claims), "tenant_id");
  }

  @Test
  void should_rejectWithTenantIdReason_when_tenantIdIsUppercaseUuid() {
    // issue() only ever mints UUID.toString() (lowercase); tenant_id must be canonical too.
    Map<String, Object> claims = validClaims(2);
    claims.put("tenant_id", UUID.randomUUID().toString().toUpperCase(Locale.ROOT));

    assertRejectedWithReason(signedToken(claims), "tenant_id");
  }

  // -----------------------------------------------------------------------
  // US-018 T-005: pre-existing rejection paths carry their reason tag
  // -----------------------------------------------------------------------

  @Test
  void should_rejectWithExpiredReason_when_tokenExpired() {
    Instant issueTime = Instant.now().minusSeconds(3600);
    AccessTokenResult result =
        service(Clock.fixed(issueTime, ZoneOffset.UTC)).issue(activeUser());

    assertRejectedWithReason(result.token(), "expired");
  }

  @Test
  void should_rejectWithClaimsMissingReason_when_rolesClaimAbsent() {
    Map<String, Object> claims = validClaims(2);
    claims.remove("roles");

    assertRejectedWithReason(signedToken(claims), "claims_missing");
  }

  @Test
  void should_rejectWithClaimsMissingReason_when_rolesContainsNullElement() {
    Map<String, Object> claims = validClaims(2);
    claims.put("roles", Collections.singletonList(null));

    assertRejectedWithReason(signedToken(claims), "claims_missing");
  }

  @Test
  void should_rejectWithClaimsMissingReason_when_permissionsContainsNonStringElement() {
    Map<String, Object> claims = validClaims(2);
    claims.put("permissions", List.of(1));

    assertRejectedWithReason(signedToken(claims), "claims_missing");
  }

  @Test
  void should_notIncrementTokenRejected_when_tokenValid() {
    JwtRs256Service svc = service(Clock.systemUTC());

    svc.verify(svc.issue(activeUser()).token());

    assertThat(meterRegistry.find("nexus.auth.token_rejected").counters())
        .allSatisfy(counter -> assertThat(counter.count()).isZero());
  }

  /** All seven reasons report from startup, so the M6 baseline shows zeros, not gaps. */
  @Test
  void should_registerEveryRejectionReasonAtZero_when_serviceConstructed() {
    service(Clock.systemUTC());

    assertThat(meterRegistry.find("nexus.auth.token_rejected").counters())
        .extracting(counter -> counter.getId().getTag("reason"))
        .containsExactlyInAnyOrder("signature", "expired", "claims_missing", "schema_version",
            "tenant_id", "sub", "perm_epoch");
  }

  /**
   * Distinct from the test above: that one proves all seven tags exist; this one proves each
   * one's count is actually 0 right after construction, before any {@code verify()} call — the
   * literal "report 0 from startup" claim, not just "the gauge is registered".
   */
  @Test
  void should_reportZeroCount_when_serviceConstructedBeforeAnyVerifyCall() {
    service(Clock.systemUTC());

    assertThat(meterRegistry.find("nexus.auth.token_rejected").counters())
        .hasSize(7)
        .allSatisfy(counter -> assertThat(counter.count()).isZero());
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  /** Every claim a valid token of {@code schemaVersion} carries, except sub/iat/exp/jti. */
  private static Map<String, Object> validClaims(int schemaVersion) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("tenant_id", UUID.randomUUID().toString());
    claims.put("email_verified", true);
    claims.put("roles", List.of("MEMBER"));
    claims.put("permissions", List.of("user:read"));
    claims.put("token_version", 0);
    claims.put("schema_version", schemaVersion);
    if (schemaVersion == 3) {
      claims.put("perm_epoch", 1_000L);
    }
    return claims;
  }

  /** Signs {@code claims} with the service's own RS256 key, with a valid sub, iat, exp and jti. */
  private static String signedToken(Map<String, Object> claims) {
    Instant now = Instant.now();
    return Jwts.builder()
        .subject(UUID.randomUUID().toString())
        .claims(claims)
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(900)))
        .id(UUID.randomUUID().toString())
        .signWith(rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS256)
        .compact();
  }

  /** The token is rejected with 401 AUTH_003, counted exactly once under {@code reason}. */
  private void assertRejectedWithReason(String token, String reason) {
    JwtRs256Service svc = service(Clock.systemUTC());

    assertThatThrownBy(() -> svc.verify(token))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
    Counter counter =
        meterRegistry.find("nexus.auth.token_rejected").tag("reason", reason).counter();
    assertThat(counter).as("token_rejected{reason=%s}", reason).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }
}
