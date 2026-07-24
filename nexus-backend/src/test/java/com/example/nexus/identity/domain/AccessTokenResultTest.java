package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class AccessTokenResultTest {

  @Test
  void should_holdFields_when_constructed() {
    AccessTokenResult result = new AccessTokenResult("jwt.token.value", 900L, "jti-uuid");

    assertThat(result.token()).isEqualTo("jwt.token.value");
    assertThat(result.expiresInSeconds()).isEqualTo(900L);
    assertThat(result.jti()).isEqualTo("jti-uuid");
  }

  @Test
  void should_notExposeToken_in_toString() {
    AccessTokenResult result = new AccessTokenResult("sensitive-jwt-value", 900L, "jti-123");

    assertThat(result.toString()).doesNotContain("sensitive-jwt-value");
  }
}
