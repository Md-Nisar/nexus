package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TokenHasherTest {

  private final TokenHasher hasher = new TokenHasher();

  /** Generate a valid 64-char hex token via TokenGenerator for use in tests. */
  private static String freshToken() {
    return new TokenGenerator().generate();
  }

  @Test
  void hash_isDeterministic_for_sameInput() {
    String token = freshToken();
    assertThat(hasher.hash(token)).isEqualTo(hasher.hash(token));
  }

  @Test
  void hash_returns64CharHex() {
    String result = hasher.hash(freshToken());
    assertThat(result).hasSize(64).matches("[0-9a-f]{64}");
  }

  @Test
  void hash_returnsDistinctHash_for_distinctInputs() {
    String hash1 = hasher.hash(freshToken());
    String hash2 = hasher.hash(freshToken());
    assertThat(hash1).isNotEqualTo(hash2);
  }

  @Test
  void hash_throwsIllegalArgumentException_when_inputIsNotHex() {
    // TokenHasher calls HexFormat.parseHex() internally; non-hex input causes
    // an IllegalArgumentException which propagates to the caller.
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> hasher.hash("not-valid-hex!!"))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
