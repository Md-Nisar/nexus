package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link JwtClaims}: immutability and correct field storage for JWT claim data.
 */
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
        "user-uuid", "tenant-uuid", true, List.of("USER"), 1000L, 1900L, "jti-uuid", 0);

    assertThat(claims.sub()).isEqualTo("user-uuid");
    assertThat(claims.tenantId()).isEqualTo("tenant-uuid");
    assertThat(claims.emailVerified()).isTrue();
    assertThat(claims.roles()).containsExactly("USER");
    assertThat(claims.iat()).isEqualTo(1000L);
    assertThat(claims.exp()).isEqualTo(1900L);
    assertThat(claims.jti()).isEqualTo("jti-uuid");
    assertThat(claims.tokenVersion()).isZero();
  }
}
