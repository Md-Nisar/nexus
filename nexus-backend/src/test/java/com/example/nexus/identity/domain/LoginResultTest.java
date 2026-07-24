package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class LoginResultTest {

  @Test
  void should_holdFields_when_constructed() {
    LoginResult result = new LoginResult("access.token", 900L, "user-id", "raw-refresh-token");

    assertThat(result.accessToken()).isEqualTo("access.token");
    assertThat(result.expiresInSeconds()).isEqualTo(900L);
    assertThat(result.userId()).isEqualTo("user-id");
    assertThat(result.rawRefreshToken()).isEqualTo("raw-refresh-token");
  }

  @Test
  void should_notExposeRawRefreshToken_in_toString() {
    LoginResult result = new LoginResult("token", 900L, "user-id", "secret-refresh-token-value");

    assertThat(result.toString()).doesNotContain("secret-refresh-token-value");
  }
}
