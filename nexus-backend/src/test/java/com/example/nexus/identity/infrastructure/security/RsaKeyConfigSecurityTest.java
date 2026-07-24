package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.identity.infrastructure.crypto.IdentityActuatorSanitizer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.endpoint.SanitizableData;
import org.springframework.boot.actuate.endpoint.SanitizingFunction;

/**
 * Security-focused unit tests for the actuator sanitization of RSA key configuration
 * properties (IMPL-13 / T-5.2).
 *
 * <p>Verifies that {@link IdentityActuatorSanitizer#identityKeySanitizer()} masks the RSA
 * private-key PEM when exposed via the Actuator {@code /actuator/env} endpoint, and that
 * the public-key PEM (which is safe to publish via the JWKS endpoint) is left unchanged.
 *
 * <p>Uses a {@code null} {@link org.springframework.core.env.PropertySource} as permitted by
 * the {@link SanitizableData} constructor — the sanitizer evaluates the key name only,
 * never the property source origin.
 *
 * <p>No Spring context — pure JUnit 5.
 */
@Tag("UnitTest")
class RsaKeyConfigSecurityTest {

  // -----------------------------------------------------------------------
  // T-5.2: Actuator sanitization of JWT key properties
  // -----------------------------------------------------------------------

  /**
   * T-5.2: The {@code nexus.jwt.private-key-pem} property contains sensitive RSA key material
   * and must be masked in actuator responses. The sanitizing function must replace its value
   * with {@link SanitizableData#SANITIZED_VALUE}.
   *
   * <p>Also verifies that {@code nexus.jwt.public-key-pem} is NOT masked — the public key is
   * intentionally exposed via the JWKS endpoint and must not be hidden from operators.
   */
  @Test
  void should_sanitizePrivateKeyPem_in_actuatorEnv() {
    IdentityActuatorSanitizer sanitizer = new IdentityActuatorSanitizer();
    SanitizingFunction fn = sanitizer.identityKeySanitizer();

    // Private key: must be masked regardless of the actual PEM content
    SanitizableData sensitive = new SanitizableData(
        null,
        "nexus.jwt.private-key-pem",
        "-----BEGIN PRIVATE KEY-----abc");

    assertThat(fn.apply(sensitive).getValue())
        .as("Private RSA key PEM must be masked in actuator env output")
        .isEqualTo(SanitizableData.SANITIZED_VALUE);

    // Public key: must NOT be masked — it is published via /jwks endpoint
    SanitizableData benign = new SanitizableData(
        null,
        "nexus.jwt.public-key-pem",
        "-----BEGIN PUBLIC KEY-----xyz");

    assertThat(fn.apply(benign).getValue())
        .as("Public RSA key PEM must remain unmasked in actuator env output")
        .isEqualTo("-----BEGIN PUBLIC KEY-----xyz");
  }
}
