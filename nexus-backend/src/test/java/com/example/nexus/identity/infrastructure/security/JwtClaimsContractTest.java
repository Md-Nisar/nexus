package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.rbac.application.PermissionFreshnessService;
import com.example.nexus.rbac.application.PermissionFreshnessService.MintEpoch;
import com.example.nexus.rbac.application.RoleResolutionService;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.security.PublicKey;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;

/**
 * CI freeze gate for the JWT claims contract (T-033 / T-7.5).
 *
 * <p>Parses the token issued by {@link JwtRs256Service} directly with JJWT and asserts that
 * exactly the 11 expected claims are present — no more, no less. Adding any new claim (e.g.,
 * {@code email}) intentionally breaks this test to prevent accidental PII leakage.
 *
 * <p>No Spring context — pure JUnit 5 + JJWT.
 */
@Tag("UnitTest")
class JwtClaimsContractTest {

  private static final long PERM_EPOCH = 1_796_000_000_000L;

  private static RsaKeyConfig rsaKeyConfig;
  private static JwtRs256Service service;
  private static User testUser;

  @BeforeAll
  static void setUp() throws Exception {
    Environment devEnv = mock(Environment.class);
    when(devEnv.getActiveProfiles()).thenReturn(new String[]{"dev"});
    rsaKeyConfig = new RsaKeyConfig(devEnv);
    rsaKeyConfig.init();

    RoleResolutionService roleResolutionService = mock(RoleResolutionService.class);
    PermissionFreshnessService freshness = mock(PermissionFreshnessService.class);
    when(freshness.mintEpoch(
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
        .thenReturn(new MintEpoch(PERM_EPOCH, true));
    when(roleResolutionService.resolve(
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.anyLong()))
        .thenReturn(new ResolvedPermissions(List.of("USER"), List.of()));
    service =
        new JwtRs256Service(
            rsaKeyConfig,
            UUID::randomUUID,
            Clock.systemUTC(),
            900L,
            roleResolutionService,
            freshness,
            new SimpleMeterRegistry());

    testUser = mock(User.class);
    when(testUser.getId()).thenReturn(UUID.randomUUID());
    when(testUser.getTenantId()).thenReturn(UUID.randomUUID());
    when(testUser.getStatus()).thenReturn(UserStatus.ACTIVE);
    when(testUser.getTokenVersion()).thenReturn(0);
  }

  @Test
  void issued_token_matches_frozen_contract() {
    AccessTokenResult result = service.issue(testUser);

    PublicKey publicKey = rsaKeyConfig.getKeyPair().getPublic();
    Jws<Claims> jws = Jwts.parser()
        .verifyWith(publicKey)
        .build()
        .parseSignedClaims(result.token());

    Claims payload = jws.getPayload();
    JwsHeader header = jws.getHeader();

    // Exactly these 11 claims — freeze gate: adding any new claim breaks this test.
    // permissions/schema_version added in US-010 (schema_version bumped 1 -> 2 accordingly);
    // perm_epoch added in US-018 M7 (schema_version bumped 2 -> 3, frozen as v2 + perm_epoch).
    assertThat(payload.keySet()).containsExactlyInAnyOrder(
        "sub", "tenant_id", "email_verified", "roles", "permissions", "iat", "exp", "jti",
        "token_version", "schema_version", "perm_epoch");

    // No PII (T-7.5)
    assertThat(payload).doesNotContainKey("email");
    assertThat(payload).doesNotContainKey("name");
    assertThat(payload).doesNotContainKey("given_name");

    // Claim values
    assertThat(payload.get("roles", List.class)).containsExactly("USER");
    assertThat(payload.get("permissions", List.class)).isEmpty();
    assertThat(payload.get("email_verified", Boolean.class)).isTrue();
    assertThat(payload.get("token_version", Integer.class)).isEqualTo(0);
    assertThat(payload.get("schema_version", Integer.class)).isEqualTo(JwtClaims.CURRENT_VERSION);
    assertThat(JwtClaims.CURRENT_VERSION).isEqualTo(3);
    assertThat(payload.get("perm_epoch", Long.class)).isEqualTo(PERM_EPOCH);

    // TTL exactly 900 seconds
    long exp = payload.getExpiration().toInstant().getEpochSecond();
    long iat = payload.getIssuedAt().toInstant().getEpochSecond();
    assertThat(exp - iat).isEqualTo(900L);

    // Header shape
    assertThat(header.getAlgorithm()).isEqualTo("RS256");
    assertThat(header.get("kid")).isNotNull();
    assertThat(header.get("typ")).isEqualTo("JWT");
  }
}
