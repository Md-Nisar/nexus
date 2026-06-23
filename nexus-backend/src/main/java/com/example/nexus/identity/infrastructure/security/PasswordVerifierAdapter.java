package com.example.nexus.identity.infrastructure.security;

import com.example.nexus.identity.application.port.out.PasswordVerifierPort;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Verifies raw passwords against Argon2id hashes using the application-configured encoder.
 * Separate from {@link PasswordEncoderConfig}'s {@code PasswordHasherPort} which only hashes.
 */
@Component
public class PasswordVerifierAdapter implements PasswordVerifierPort {

  private final Argon2PasswordEncoder encoder;

  public PasswordVerifierAdapter(Argon2PasswordEncoder encoder) {
    this.encoder = encoder;
  }

  @Override
  public boolean matches(String rawPassword, String encodedHash) {
    return encoder.matches(rawPassword, encodedHash);
  }
}
