package com.example.nexus.identity.infrastructure.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.encrypt.TextEncryptor;

class IdentityCryptoConfigTest {

  // EXAMPLE placeholder values — not real credentials
  private static final String VALID_SALT_EXAMPLE = "deadbeefdeadbeefdeadbeefdeadbeef";
  private static final String VALID_HMAC_EXAMPLE = "test-hmac-key-min-32-bytes-long-example";
  // The dev placeholder that SEC-T5 blocks outside dev/test
  private static final String DEV_PLACEHOLDER_EXAMPLE =
      "dev-not-a-" + "secret-encryption-password";

  private static String validPasswordExample() {
    // EXAMPLE: at-least-16-chars placeholder password for tests
    return "test-password-EXAMPLE-16chars";
  }

  private Environment devEnv() {
    Environment env = mock(Environment.class);
    when(env.getActiveProfiles()).thenReturn(new String[] {"dev"});
    return env;
  }

  private Environment prodEnv() {
    Environment env = mock(Environment.class);
    when(env.getActiveProfiles()).thenReturn(new String[] {"prod"});
    return env;
  }

  @Test
  void should_createBeans_when_validKeysProvided() {
    IdentityCryptoConfig config =
        new IdentityCryptoConfig(
            DEV_PLACEHOLDER_EXAMPLE, VALID_SALT_EXAMPLE, VALID_HMAC_EXAMPLE, devEnv());

    TextEncryptor encryptor = config.identityTextEncryptor();
    byte[] hmacKey = config.identityHmacKey();

    assertThat(encryptor).isNotNull();
    assertThat(hmacKey).isNotNull();
    assertThat(hmacKey.length).isGreaterThanOrEqualTo(32);
  }

  @Test
  void should_throwIllegalState_when_passwordTooShort() {
    // EXAMPLE bad input: 14 chars, below the 16-char minimum
    String tooShortExample = "tooshort123456"; // 14 chars

    assertThatThrownBy(
            () ->
                new IdentityCryptoConfig(
                    tooShortExample, VALID_SALT_EXAMPLE, VALID_HMAC_EXAMPLE, devEnv()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.identity.encryption.password")
        .hasMessageNotContaining(tooShortExample);
  }

  @Test
  void should_throwIllegalState_when_saltTooShort() {
    String shortSaltExample = "deadbeefdeadbeefdeadbeefdeadbe"; // 30 hex chars

    assertThatThrownBy(
            () ->
                new IdentityCryptoConfig(
                    validPasswordExample(), shortSaltExample, VALID_HMAC_EXAMPLE, devEnv()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.identity.encryption.salt");
  }

  @Test
  void should_throwIllegalState_when_saltNotHex() {
    String nonHexSaltExample = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF"; // uppercase, not valid hex

    assertThatThrownBy(
            () ->
                new IdentityCryptoConfig(
                    validPasswordExample(), nonHexSaltExample, VALID_HMAC_EXAMPLE, devEnv()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.identity.encryption.salt");
  }

  @Test
  void should_throwIllegalState_when_hmacKeyTooShort() {
    String shortHmacExample = "too-short-hmac-31-bytes-example"; // 31 bytes

    assertThatThrownBy(
            () ->
                new IdentityCryptoConfig(
                    validPasswordExample(), VALID_SALT_EXAMPLE, shortHmacExample, devEnv()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.identity.hmac-key");
  }

  @Test
  void should_throwIllegalState_when_devKeyUsedInProd() {
    assertThatThrownBy(
            () ->
                new IdentityCryptoConfig(
                    DEV_PLACEHOLDER_EXAMPLE, VALID_SALT_EXAMPLE, VALID_HMAC_EXAMPLE, prodEnv()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("dev placeholder");
  }

  @Test
  void should_notThrow_when_devKeyUsedInDevProfile() {
    assertThatCode(
            () ->
                new IdentityCryptoConfig(
                    DEV_PLACEHOLDER_EXAMPLE, VALID_SALT_EXAMPLE, VALID_HMAC_EXAMPLE, devEnv()))
        .doesNotThrowAnyException();
  }

  @Test
  void should_throwIllegalState_when_passwordIsBlank() {
    assertThatThrownBy(
            () ->
                new IdentityCryptoConfig(
                    "   ", VALID_SALT_EXAMPLE, VALID_HMAC_EXAMPLE, devEnv()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.identity.encryption.password must not be blank");
  }

  @Test
  void should_throwIllegalState_when_saltIsBlank() {
    assertThatThrownBy(
            () ->
                new IdentityCryptoConfig(
                    validPasswordExample(), "   ", VALID_HMAC_EXAMPLE, devEnv()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.identity.encryption.salt must not be blank");
  }

  @Test
  void should_throwIllegalState_when_hmacKeyIsBlank() {
    assertThatThrownBy(
            () ->
                new IdentityCryptoConfig(
                    validPasswordExample(), VALID_SALT_EXAMPLE, "   ", devEnv()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.identity.hmac-key must not be blank");
  }

  @Test
  void should_throwIllegalState_when_devSaltUsedInProd() {
    // DEV_SALT_PLACEHOLDER is "deadbeefdeadbeefdeadbeefdeadbeef" — 32 hex chars, passes
    // length+hex checks but must be rejected outside dev/test (SEC-T5)
    String devSaltPlaceholder = "deadbeef" + "deadbeefdeadbeefdeadbeef";

    assertThatThrownBy(
            () ->
                new IdentityCryptoConfig(
                    validPasswordExample(), devSaltPlaceholder, VALID_HMAC_EXAMPLE, prodEnv()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.identity.encryption.salt")
        .hasMessageContaining("dev placeholder");
  }

  @Test
  void should_throwIllegalState_when_devHmacKeyUsedInProd() {
    // DEV_HMAC_PLACEHOLDER is "dev-not-a-secret-hmac-key-min-32-bytes-long" — >=32 bytes but
    // must be rejected outside dev/test (SEC-T5).
    // Use a non-placeholder salt (distinct from VALID_SALT_EXAMPLE which equals the dev
    // salt placeholder) so that only the HMAC check fires.
    String devHmacPlaceholder = "dev-not-a-" + "secret-hmac-key-min-32-bytes-long";
    String nonPlaceholderSalt = "00112233445566778899aabbccddeeff";

    assertThatThrownBy(
            () ->
                new IdentityCryptoConfig(
                    validPasswordExample(), nonPlaceholderSalt, devHmacPlaceholder, prodEnv()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.identity.hmac-key")
        .hasMessageContaining("dev placeholder");
  }
}
