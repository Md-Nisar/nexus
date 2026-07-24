package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
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

  @Test
  void should_setConsumedAt_when_consumeCalled() {
    AuthToken token = new AuthToken(
        UUID.randomUUID(), UUID.randomUUID(), AuthTokenType.VERIFICATION, "hash",
        Instant.now().plusSeconds(3600));
    Instant consumedAt = Instant.now();

    token.consume(consumedAt);

    assertThat(token.getConsumedAt()).isEqualTo(consumedAt);
  }

  @Test
  void should_setVerificationType_when_forVerificationFactoryCalled() {
    UUID id = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    Instant expiresAt = Instant.now().plusSeconds(86400);

    AuthToken token = AuthToken.forVerification(id, userId, "sha256hexhash", expiresAt);

    assertThat(token.getId()).isEqualTo(id);
    assertThat(token.getUserId()).isEqualTo(userId);
    assertThat(token.getType()).isEqualTo(AuthTokenType.VERIFICATION);
    assertThat(token.getTokenHash()).isEqualTo("sha256hexhash");
    assertThat(token.getExpiresAt()).isEqualTo(expiresAt);
    assertThat(token.getConsumedAt()).isNull();
  }

  @Test
  void should_setResetType_when_forResetFactoryCalled() {
    UUID id = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    Instant expiresAt = Instant.now().plusSeconds(3600);

    AuthToken token = AuthToken.forReset(id, userId, "sha256resethash", expiresAt);

    assertThat(token.getId()).isEqualTo(id);
    assertThat(token.getUserId()).isEqualTo(userId);
    assertThat(token.getType()).isEqualTo(AuthTokenType.RESET);
    assertThat(token.getTokenHash()).isEqualTo("sha256resethash");
    assertThat(token.getExpiresAt()).isEqualTo(expiresAt);
    assertThat(token.getConsumedAt()).isNull();
  }
}
