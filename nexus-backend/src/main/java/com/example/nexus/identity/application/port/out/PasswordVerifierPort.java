package com.example.nexus.identity.application.port.out;

/**
 * Verifies a raw password against a stored encoded hash.
 *
 * <p>Separate from {@link PasswordHasherPort} which only hashes; this split allows use-cases to
 * depend on verification without being able to trigger hashing (principle of least privilege).
 * Implementations live in {@code identity.infrastructure.security}.
 */
public interface PasswordVerifierPort {

  /**
   * Returns {@code true} iff {@code rawPassword} matches {@code encodedHash}.
   *
   * @param rawPassword the plaintext password from the login request
   * @param encodedHash the Argon2id hash stored in the user record
   * @return {@code true} if the password matches, {@code false} otherwise
   */
  boolean matches(String rawPassword, String encodedHash);
}
