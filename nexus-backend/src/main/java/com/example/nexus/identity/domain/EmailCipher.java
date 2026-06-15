package com.example.nexus.identity.domain;

/**
 * Wrapper for AES-256-GCM ciphertext of an email address; {@link #toString()} is redacted to
 * prevent PII leakage in logs (SEC-T3).
 */
public record EmailCipher(String value) {

  @Override
  public String toString() {
    return "EmailCipher[REDACTED]";
  }
}
