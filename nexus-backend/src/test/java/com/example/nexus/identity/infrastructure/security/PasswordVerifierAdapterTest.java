package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

@Tag("UnitTest")
class PasswordVerifierAdapterTest {

  // Fast params for unit tests — not suitable for production
  private final Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 4096, 1);
  private final PasswordVerifierAdapter adapter = new PasswordVerifierAdapter(encoder);

  @Test
  void should_returnTrue_when_passwordMatchesHash() {
    String hash = encoder.encode("correct-password");

    assertThat(adapter.matches("correct-password", hash)).isTrue();
  }

  @Test
  void should_returnFalse_when_passwordDoesNotMatchHash() {
    String hash = encoder.encode("correct-password");

    assertThat(adapter.matches("wrong-password", hash)).isFalse();
  }
}
