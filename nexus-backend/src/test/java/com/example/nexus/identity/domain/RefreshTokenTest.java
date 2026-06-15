package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class RefreshTokenTest {

  @Test
  void should_setRequiredFields_when_constructorCalled() {
    UUID id = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    UUID familyId = UUID.randomUUID();
    Instant expiresAt = Instant.now().plusSeconds(604800);

    RefreshToken token = new RefreshToken(id, userId, "tokenhash", familyId, expiresAt);

    assertThat(token.getId()).isEqualTo(id);
    assertThat(token.getUserId()).isEqualTo(userId);
    assertThat(token.getTokenHash()).isEqualTo("tokenhash");
    assertThat(token.getFamilyId()).isEqualTo(familyId);
    assertThat(token.getExpiresAt()).isEqualTo(expiresAt);
  }

  @Test
  void should_defaultRevokedAtToNull_when_constructed() {
    RefreshToken token =
        new RefreshToken(
            UUID.randomUUID(),
            UUID.randomUUID(),
            "anotherhash",
            UUID.randomUUID(),
            Instant.now().plusSeconds(604800));

    assertThat(token.getRevokedAt()).isNull();
    assertThat(token.getCreatedAt()).isNull();
    assertThat(token.getUpdatedAt()).isNull();
  }
}
