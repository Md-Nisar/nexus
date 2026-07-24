package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class UserStatusTest {

  @Test
  void should_containAllExpectedValues_when_valuesListed() {
    assertThat(UserStatus.values())
        .containsExactly(
            UserStatus.PENDING, UserStatus.ACTIVE, UserStatus.LOCKED, UserStatus.DISABLED);
  }
}
