package com.example.nexus.identity.infrastructure.crypto;

import org.springframework.boot.actuate.endpoint.SanitizingFunction;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers a {@link SanitizingFunction} that masks sensitive {@code nexus.identity.*} properties
 * in the Actuator {@code /actuator/env} endpoint (SEC-T6).
 *
 * <p>Spring Boot 4 removed the deprecated {@code management.endpoint.env.keys-to-sanitize} YAML
 * property. The supported replacement is a {@link SanitizingFunction} bean, which is invoked for
 * every property key that the env endpoint exposes.
 *
 * <p>Covered properties:
 *
 * <ul>
 *   <li>{@code nexus.identity.encryption.password} — AES-256-GCM master password
 *   <li>{@code nexus.identity.encryption.salt} — KDF salt (not matched by Boot defaults)
 *   <li>{@code nexus.identity.hmac-key} — HMAC-SHA256 blind-index key
 *   <li>{@code nexus.jwt.private-key-pem} — RSA private key PEM (ADR-0007)
 * </ul>
 */
@Configuration
public class IdentityActuatorSanitizer {

  /** Returns a {@link SanitizingFunction} that masks sensitive identity property values. */
  @Bean
  public SanitizingFunction identityKeySanitizer() {
    return data -> {
      String key = data.getKey();
      if (isSensitive(key.toLowerCase(java.util.Locale.ROOT))) {
        return data.withSanitizedValue();
      }
      return data;
    };
  }

  private boolean isSensitive(String lowerKey) {
    boolean isIdentityProperty =
        lowerKey.startsWith("nexus.identity.") || lowerKey.startsWith("nexus_identity_");
    boolean isIdentitySensitive = isIdentityProperty
        && (lowerKey.contains("password")
            || lowerKey.contains("salt")
            || lowerKey.contains("hmac")
            || lowerKey.contains("key"));

    boolean isJwtProperty = lowerKey.startsWith("nexus.jwt.") || lowerKey.startsWith("nexus_jwt_");
    boolean isJwtSensitive = isJwtProperty && lowerKey.contains("private");

    return isIdentitySensitive || isJwtSensitive;
  }
}
