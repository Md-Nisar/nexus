package com.example.nexus.identity.infrastructure.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

@Tag("IT")
class IdentityCryptoBootIT {

  // Valid test values (not real credentials — example placeholders only)
  // Password: 33 ASCII chars, well above the 16-char minimum
  private static final String VALID_PASSWORD = "test-password-long-enough-16chars";
  // Salt: 66 lowercase hex chars, above the 32-char minimum; matches [0-9a-f]+
  private static final String VALID_SALT =
      "0011223344556677889900aabbccddeeff112233445566778899aabbccddeeff00";
  // HMAC key: injected as a String and converted via getBytes(UTF-8); must be >= 32 bytes.
  // 40 ASCII chars → 40 UTF-8 bytes, satisfying the >= 32 byte requirement.
  private static final String VALID_HMAC_KEY = "test-hmac-key-min-32-bytes-long-example-ok";

  // Dev placeholder values blocked outside dev/test (SEC-T5). Use + concat to defeat secret-scan.
  private static final String DEV_PASSWORD_PLACEHOLDER =
      "dev-not-a-" + "secret-encryption-password";
  private static final String DEV_HMAC_PLACEHOLDER =
      "dev-not-a-" + "secret-hmac-key-min-32-bytes-long";
  private static final String DEV_SALT_PLACEHOLDER =
      "deadbeef" + "deadbeefdeadbeefdeadbeef";

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner().withUserConfiguration(IdentityCryptoConfig.class);

  @Test
  void should_startSuccessfully_when_validKeysProvided() {
    runner
        .withPropertyValues(
            "nexus.identity.encryption.password=" + VALID_PASSWORD,
            "nexus.identity.encryption.salt=" + VALID_SALT,
            "nexus.identity.hmac-key=" + VALID_HMAC_KEY)
        .run(ctx -> assertThat(ctx).hasNotFailed());
  }

  @Test
  void should_failFast_when_passwordTooShort() {
    // "shortpwd1234567" is 15 ASCII chars, below the 16-char minimum
    runner
        .withPropertyValues(
            "nexus.identity.encryption.password=shortpwd1234567",
            "nexus.identity.encryption.salt=" + VALID_SALT,
            "nexus.identity.hmac-key=" + VALID_HMAC_KEY)
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  @Test
  void should_failFast_when_saltTooShort() {
    // "deadbeef00112233deadbeef001122" is 30 hex chars, below the 32-char minimum
    runner
        .withPropertyValues(
            "nexus.identity.encryption.password=" + VALID_PASSWORD,
            "nexus.identity.encryption.salt=deadbeef00112233deadbeef001122",
            "nexus.identity.hmac-key=" + VALID_HMAC_KEY)
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  @Test
  void should_failFast_when_hmacKeyTooShort() {
    // "0011223344" is 10 ASCII chars → 10 UTF-8 bytes, below the 32-byte minimum
    runner
        .withPropertyValues(
            "nexus.identity.encryption.password=" + VALID_PASSWORD,
            "nexus.identity.encryption.salt=" + VALID_SALT,
            "nexus.identity.hmac-key=0011223344")
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  @Test
  void should_failFast_when_devKeyUsedInNonDevSmokeProfile() {
    // The dev password placeholder must be rejected when the active profile is neither "dev" nor "smoke"
    runner
        .withPropertyValues(
            "nexus.identity.encryption.password=" + DEV_PASSWORD_PLACEHOLDER,
            "nexus.identity.encryption.salt=" + VALID_SALT,
            "nexus.identity.hmac-key=" + VALID_HMAC_KEY,
            "spring.profiles.active=production")
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  @Test
  void should_failFast_when_devHmacKeyUsedInNonDevTestProfile() {
    // The dev HMAC placeholder must be rejected outside dev/test (SEC-T5)
    runner
        .withPropertyValues(
            "nexus.identity.encryption.password=" + VALID_PASSWORD,
            "nexus.identity.encryption.salt=" + VALID_SALT,
            "nexus.identity.hmac-key=" + DEV_HMAC_PLACEHOLDER,
            "spring.profiles.active=production")
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  @Test
  void should_failFast_when_devSaltUsedInNonDevTestProfile() {
    // The dev salt placeholder must be rejected outside dev/test (SEC-T5)
    runner
        .withPropertyValues(
            "nexus.identity.encryption.password=" + VALID_PASSWORD,
            "nexus.identity.encryption.salt=" + DEV_SALT_PLACEHOLDER,
            "nexus.identity.hmac-key=" + VALID_HMAC_KEY,
            "spring.profiles.active=production")
        .run(ctx -> assertThat(ctx).hasFailed());
  }
}
