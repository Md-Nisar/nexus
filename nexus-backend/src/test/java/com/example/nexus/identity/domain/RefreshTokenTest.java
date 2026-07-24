package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
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

  @Test
  void should_setRevokedAt_when_revokeCalled() {
    RefreshToken token =
        new RefreshToken(
            UUID.randomUUID(), UUID.randomUUID(), "hash", UUID.randomUUID(),
            Instant.now().plusSeconds(604800));
    Instant revokedAt = Instant.now();

    token.revoke(revokedAt);

    assertThat(token.getRevokedAt()).isEqualTo(revokedAt);
  }

  @Test
  void should_remainRevoked_when_revokeCalledTwice() {
    RefreshToken token =
        new RefreshToken(
            UUID.randomUUID(), UUID.randomUUID(), "hash", UUID.randomUUID(),
            Instant.now().plusSeconds(604800));
    Instant first = Instant.now();
    Instant second = first.plusSeconds(1);

    token.revoke(first);
    token.revoke(second);

    assertThat(token.getRevokedAt()).isNotNull();
  }
}
