package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuthTokenTest {

  @Test
  void should_setRequiredFields_when_constructorCalled() {
    UUID id = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    Instant expiresAt = Instant.now().plusSeconds(3600);

    AuthToken token =
        new AuthToken(id, userId, AuthTokenType.VERIFICATION, "abc123hash", expiresAt);

    assertThat(token.getId()).isEqualTo(id);
    assertThat(token.getUserId()).isEqualTo(userId);
    assertThat(token.getType()).isEqualTo(AuthTokenType.VERIFICATION);
    assertThat(token.getTokenHash()).isEqualTo("abc123hash");
    assertThat(token.getExpiresAt()).isEqualTo(expiresAt);
  }

  @Test
  void should_defaultOptionalFieldsToNull_when_constructed() {
    AuthToken token =
        new AuthToken(
            UUID.randomUUID(),
            UUID.randomUUID(),
            AuthTokenType.RESET,
            "resethash",
            Instant.now().plusSeconds(600));

    assertThat(token.getConsumedAt()).isNull();
    assertThat(token.getCreatedAt()).isNull();
    assertThat(token.getUpdatedAt()).isNull();
  }
}
