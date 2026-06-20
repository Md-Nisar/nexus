package com.example.nexus.identity.application;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.stereotype.Service;

/**
 * Computes the SHA-256 hash of a raw verification token for safe database storage.
 *
 * <p>Only the hash is persisted; the raw token is transmitted to the user and never stored.
 * A fresh {@link MessageDigest} instance is created on every call — {@link MessageDigest} is
 * not thread-safe and must not be shared.
 *
 * <p>Input convention: the raw token is a 64-character lowercase hex string (32 bytes).
 * The hash is computed over the raw bytes, not over the hex representation, to produce a
 * consistent 64-character hex output regardless of how the caller encodes the token.
 */
@Service
public class TokenHasher {

  /**
   * Hashes a raw token.
   *
   * @param rawToken 64-character lowercase hex string produced by {@link TokenGenerator#generate()}
   * @return 64-character lowercase hex SHA-256 hash of the underlying 32 raw bytes
   */
  public String hash(String rawToken) {
    byte[] rawBytes = HexFormat.of().parseHex(rawToken);
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of().formatHex(digest.digest(rawBytes));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not available on this JVM", e);
    }
  }
}
