package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link JwtClaims}: immutability and correct field storage for JWT claim data.
 */
@Tag("UnitTest")
class JwtClaimsTest {

  /**
   * Verifies that all JWT claims are correctly stored and retrievable after construction.
   *
   * <p>Given: JwtClaims constructed with complete claim set
   * When: accessors called
   * Then: all fields return their original values
   */
  @Test
  void should_holdAllFields_when_constructed() {
    JwtClaims claims = new JwtClaims(
        "user-uuid",
        "tenant-uuid",
        true,
        List.of("TENANT_ADMIN"),
        List.of("tenant:read", "tenant:write"),
        1000L,
        1900L,
        "jti-uuid",
        0,
        JwtClaims.CURRENT_VERSION,
        1_796_000_000_000L);

    assertThat(claims.sub()).isEqualTo("user-uuid");
    assertThat(claims.tenantId()).isEqualTo("tenant-uuid");
    assertThat(claims.emailVerified()).isTrue();
    assertThat(claims.roles()).containsExactly("TENANT_ADMIN");
    assertThat(claims.permissions()).containsExactly("tenant:read", "tenant:write");
    assertThat(claims.iat()).isEqualTo(1000L);
    assertThat(claims.exp()).isEqualTo(1900L);
    assertThat(claims.jti()).isEqualTo("jti-uuid");
    assertThat(claims.tokenVersion()).isZero();
    assertThat(claims.schemaVersion()).isEqualTo(3);
    assertThat(claims.permEpoch()).isEqualTo(1_796_000_000_000L);
  }

  @Test
  void should_defensivelyCopy_roles_and_permissions() {
    List<String> mutableRoles = new java.util.ArrayList<>(List.of("MEMBER"));
    List<String> mutablePermissions = new java.util.ArrayList<>(List.of("user:read"));

    JwtClaims claims = new JwtClaims(
        "user-uuid",
        "tenant-uuid",
        true,
        mutableRoles,
        mutablePermissions,
        1000L,
        1900L,
        "jti-uuid",
        0,
        JwtClaims.CURRENT_VERSION,
        0L);
    mutableRoles.add("INJECTED");
    mutablePermissions.add("INJECTED");

    assertThat(claims.roles()).containsExactly("MEMBER");
    assertThat(claims.permissions()).containsExactly("user:read");
  }

  /** US-018 M7b (design §9.6): only the current schema version is accepted. */
  @Test
  void should_containExactlyVersion3_when_acceptedVersionsRead() {
    assertThat(JwtClaims.CURRENT_VERSION).isEqualTo(3);
    assertThat(JwtClaims.ACCEPTED_VERSIONS).containsExactly(3);
  }
}
