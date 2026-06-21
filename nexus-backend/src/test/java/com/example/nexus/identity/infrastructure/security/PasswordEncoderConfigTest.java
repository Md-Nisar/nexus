package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

class PasswordEncoderConfigTest {

  // Instantiated directly with fast dev-profile params — no Spring context needed.
  private final Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 4096, 1);

  @Test
  void encode_returnsArgon2idPrefixedString() {
    PasswordHasherPort hasher = encoder::encode;
    assertThat(hasher.hash("testPassword123!")).startsWith("$argon2");
  }

  @Test
  void encode_producesDistinctEncodings_for_samePassword() {
    PasswordHasherPort hasher = encoder::encode;
    String first = hasher.hash("testPassword123!");
    String second = hasher.hash("testPassword123!");
    assertThat(first).isNotEqualTo(second);
  }
}
