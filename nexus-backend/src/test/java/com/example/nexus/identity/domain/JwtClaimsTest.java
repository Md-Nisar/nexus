package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class JwtClaimsTest {

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
