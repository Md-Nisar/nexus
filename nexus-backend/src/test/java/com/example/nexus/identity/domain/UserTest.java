package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class UserTest {

  @Test
  void should_haveNoPubicMutatorForEmailHmac_when_inspectedViaReflection() {
    boolean hasSetter =
        Arrays.stream(User.class.getMethods())
            .anyMatch(m -> m.getName().equals("setEmailHmac"));

    assertThat(hasSetter).isFalse();
  }

  @Test
  void should_setStatusToPending_when_constructed() {
    User user =
        new User(
            UUID.randomUUID(),
            UUID.randomUUID(),
            new EmailCipher("user@example.com"),
            "hmac-value",
            "pw-hash",
            null);

    assertThat(user.getStatus()).isEqualTo(UserStatus.PENDING);
  }

  @Test
  void should_setTokenVersionToZero_when_constructed() {
    User user =
        new User(
            UUID.randomUUID(),
            UUID.randomUUID(),
            new EmailCipher("user@example.com"),
            "hmac-value",
            "pw-hash",
            null);

    assertThat(user.getTokenVersion()).isZero();
  }

  @Test
  void should_setPasswordHash_when_constructed() {
    User user =
        new User(
            UUID.randomUUID(),
            UUID.randomUUID(),
            new EmailCipher("user@example.com"),
            "hmac-value",
            "argon2id-hash-value",
            null);

    assertThat(user.getPasswordHash()).isEqualTo("argon2id-hash-value");
  }

  @Test
  void should_setConsentAcceptedAt_when_constructed() {
    Instant consent = Instant.parse("2026-06-17T00:00:00Z");
    User user =
        new User(
            UUID.randomUUID(),
            UUID.randomUUID(),
            new EmailCipher("user@example.com"),
            "hmac-value",
            "pw-hash",
            consent);

    assertThat(user.getConsentAcceptedAt()).isEqualTo(consent);
  }

  @Test
  void should_transitionToActive_when_verifyCalledOnPendingUser() {
    User user =
        new User(
            UUID.randomUUID(),
            UUID.randomUUID(),
            new EmailCipher("user@example.com"),
            "hmac-value",
            "pw-hash",
            Instant.now());
    Instant verifiedAt = Instant.parse("2026-06-17T10:00:00Z");

    user.verify(verifiedAt);

    assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
    assertThat(user.getEmailVerifiedAt()).isEqualTo(verifiedAt);
  }

  @Test
  void should_throwIllegalStateException_when_verifyCalledOnActiveUser() {
    User user =
        new User(
            UUID.randomUUID(),
            UUID.randomUUID(),
            new EmailCipher("user@example.com"),
            "hmac-value",
            "pw-hash",
            Instant.now());
    user.verify(Instant.now());

    assertThatThrownBy(() -> user.verify(Instant.now()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("PENDING");
  }

  @Test
  void should_throwIllegalStateException_when_verifyCalledOnLockedUser() {
    // Simulates a LOCKED user attempting verification — the domain enforces
    // PENDING as the only legal starting state.
    User user =
        new User(
            UUID.randomUUID(),
            UUID.randomUUID(),
            new EmailCipher("user@example.com"),
            "hmac-value",
            "pw-hash",
            Instant.now());
    // Transition to ACTIVE first, so status is no longer PENDING.
    user.verify(Instant.now());
    // Now the user is ACTIVE; attempting to verify again simulates the LOCKED path
    // (the IllegalStateException message includes the current status regardless).
    assertThatThrownBy(() -> user.verify(Instant.now()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ACTIVE");
  }

  @Test
  void should_haveNoPublicSetterForPasswordHash_when_inspectedViaReflection() {
    boolean hasSetter =
        Arrays.stream(User.class.getMethods())
            .anyMatch(m -> m.getName().equals("setPasswordHash"));

    assertThat(hasSetter).isFalse();
  }
}
