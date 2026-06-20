package com.example.nexus.identity.application.port.out;

/**
 * Port for hashing raw passwords using a strong adaptive algorithm (Argon2id, OWASP 2023).
 *
 * <p>Declared as a {@link FunctionalInterface} so it can be wired in infrastructure configuration
 * as a method reference: {@code encoder::encode}.
 */
@FunctionalInterface
public interface PasswordHasherPort {

  /**
   * Hashes a raw password. Each call produces a new, unique encoded string that includes the salt
   * and algorithm parameters — the result is never deterministic.
   *
   * @param rawPassword the plaintext password; must not be {@code null}
   * @return the encoded hash string
   */
  String hash(String rawPassword);
}
