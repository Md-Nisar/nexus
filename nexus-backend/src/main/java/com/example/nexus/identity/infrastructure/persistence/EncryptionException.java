package com.example.nexus.identity.infrastructure.persistence;

/** Thrown when attribute encryption or decryption fails; message never includes PII (SEC-T3). */
public class EncryptionException extends RuntimeException {

  public EncryptionException(String message) {
    super(message);
  }
}
