package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

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
            "hmac-value");

    assertThat(user.getStatus()).isEqualTo(UserStatus.PENDING);
  }

  @Test
  void should_setTokenVersionToZero_when_constructed() {
    User user =
        new User(
            UUID.randomUUID(),
            UUID.randomUUID(),
            new EmailCipher("user@example.com"),
            "hmac-value");

    assertThat(user.getTokenVersion()).isZero();
  }
}
