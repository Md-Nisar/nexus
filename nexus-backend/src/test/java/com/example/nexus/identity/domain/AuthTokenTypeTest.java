package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuthTokenTypeTest {

  @Test
  void should_containAllExpectedValues_when_valuesListed() {
    assertThat(AuthTokenType.values())
        .containsExactly(AuthTokenType.VERIFICATION, AuthTokenType.RESET);
  }
}
