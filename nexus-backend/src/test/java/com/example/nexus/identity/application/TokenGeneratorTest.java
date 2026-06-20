package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class TokenGeneratorTest {

  private final TokenGenerator generator = new TokenGenerator();

  @Test
  void generate_returns64CharLowercaseHex() {
    String token = generator.generate();
    assertThat(token).hasSize(64).matches("[0-9a-f]{64}");
  }

  @Test
  void generate_returnsDistinctValues_when_called1000Times() {
    Set<String> tokens = new HashSet<>();
    for (int i = 0; i < 1000; i++) {
      tokens.add(generator.generate());
    }
    assertThat(tokens).hasSize(1000);
  }
}
