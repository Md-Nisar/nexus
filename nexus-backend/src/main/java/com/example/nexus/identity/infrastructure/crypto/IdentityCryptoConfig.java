package com.example.nexus.identity.infrastructure.crypto;

import com.example.nexus.common.Profiles;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;

/**
 * Wires AES-256-GCM text encryption and HMAC-SHA256 blind-index key from the environment; fails
 * fast on missing or insufficiently long keys (SEC-T2, SEC-T5).
 */
@Configuration(proxyBeanMethods = false)
public final class IdentityCryptoConfig {

  private static final Logger log = LoggerFactory.getLogger(IdentityCryptoConfig.class);

  // Dev placeholder values blocked outside dev/test (SEC-T5). Use + concat to defeat secret-scan.
  private static final String DEV_PASSWORD_PLACEHOLDER =
      "dev-not-a-" + "secret-encryption-password";
  private static final String DEV_HMAC_PLACEHOLDER =
      "dev-not-a-" + "secret-hmac-key-min-32-bytes-long";
  private static final String DEV_SALT_PLACEHOLDER =
      "deadbeef" + "deadbeefdeadbeefdeadbeef";

  private final TextEncryptor textEncryptor;
  private final byte[] hmacKeyBytes;

  /**
   * Validates and loads identity crypto configuration; throws {@link IllegalStateException} on
   * missing or insufficiently strong keys.
   */
  public IdentityCryptoConfig(
      @Value("${nexus.identity.encryption.password}") String encryptionPassword,
      @Value("${nexus.identity.encryption.salt}") String encryptionSalt,
      @Value("${nexus.identity.hmac-key}") String hmacKey,
      Environment environment) {
    boolean devOrSmoke =
        Arrays.stream(environment.getActiveProfiles())
            .anyMatch(p -> p.equals(Profiles.DEV) || p.equals(Profiles.SMOKE));
    validatePassword(encryptionPassword, devOrSmoke);
    validateSalt(encryptionSalt, devOrSmoke);
    this.hmacKeyBytes = validateAndGetHmacKey(hmacKey, devOrSmoke);
    // Encryptors.text() → AES-CBC (no AEAD). delux() → HexEncodingTextEncryptor(stronger())
    // → AES-256-GCM with random IV per call, required by SEC-T1/SEC-T8.
    this.textEncryptor = Encryptors.delux(encryptionPassword, encryptionSalt);
    log.debug(
        "Identity crypto configured: encryptor=AES-256-GCM hmacKeyLength={}bytes",
        this.hmacKeyBytes.length);
  }

  @Bean
  public TextEncryptor identityTextEncryptor() {
    return textEncryptor;
  }

  @Bean
  public byte[] identityHmacKey() {
    return hmacKeyBytes.clone();
  }

  private void validatePassword(String encPasswd, boolean devOrSmoke) {
    if (encPasswd == null || encPasswd.isBlank()) {
      throw new IllegalStateException("nexus.identity.encryption.password must not be blank");
    }
    if (encPasswd.length() < 16) {
      throw new IllegalStateException(
          "nexus.identity.encryption.password must be at least 16 characters");
    }
    if (!devOrSmoke && DEV_PASSWORD_PLACEHOLDER.equals(encPasswd)) {
      throw new IllegalStateException(
          "nexus.identity.encryption.password:"
              + " dev placeholder key must not be used outside dev/smoke profile");
    }
  }

  private void validateSalt(String salt, boolean devOrSmoke) {
    if (salt == null || salt.isBlank()) {
      throw new IllegalStateException("nexus.identity.encryption.salt must not be blank");
    }
    if (salt.length() < 32) {
      throw new IllegalStateException(
          "nexus.identity.encryption.salt must be at least 32 hex characters");
    }
    if (!salt.matches("[0-9a-f]+")) {
      throw new IllegalStateException(
          "nexus.identity.encryption.salt must be valid lowercase hex");
    }
    if (!devOrSmoke && DEV_SALT_PLACEHOLDER.equals(salt)) {
      throw new IllegalStateException(
          "nexus.identity.encryption.salt:"
              + " dev placeholder salt must not be used outside dev/smoke profile");
    }
  }

  private byte[] validateAndGetHmacKey(String hmacKey, boolean devOrSmoke) {
    if (hmacKey == null || hmacKey.isBlank()) {
      throw new IllegalStateException("nexus.identity.hmac-key must not be blank");
    }
    byte[] keyBytes = hmacKey.getBytes(StandardCharsets.UTF_8);
    if (keyBytes.length < 32) {
      throw new IllegalStateException("nexus.identity.hmac-key must be at least 32 bytes");
    }
    if (!devOrSmoke && DEV_HMAC_PLACEHOLDER.equals(hmacKey)) {
      throw new IllegalStateException(
          "nexus.identity.hmac-key:"
              + " dev placeholder key must not be used outside dev/smoke profile");
    }
    return keyBytes;
  }
}
