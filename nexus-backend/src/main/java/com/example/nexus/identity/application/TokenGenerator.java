package com.example.nexus.identity.application;

import java.security.SecureRandom;
import java.util.HexFormat;
import org.springframework.stereotype.Service;

/**
 * Generates cryptographically random one-time tokens for email verification and password reset.
 *
 * <p>Each call to {@link #generate()} produces a 32-byte random value encoded as a 64-character
 * lowercase hex string. The raw token is sent to the user; its SHA-256 hash is stored in the
 * database (see {@link TokenHasher}).
 *
 * <p>{@link SecureRandom} is held as an instance field: it is thread-safe after construction and
 * avoids re-seeding overhead that would occur with repeated instantiation.
 */
@Service
public class TokenGenerator {

  private final SecureRandom secureRandom = new SecureRandom();

  /**
   * Generates a new 64-character lowercase hex token backed by 32 bytes of secure randomness.
   *
   * @return a 64-character lowercase hex string
   */
  public String generate() {
    byte[] bytes = new byte[32];
    secureRandom.nextBytes(bytes);
    return HexFormat.of().formatHex(bytes);
  }
}
