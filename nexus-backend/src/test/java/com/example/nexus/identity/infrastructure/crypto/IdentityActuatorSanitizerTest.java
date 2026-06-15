package com.example.nexus.identity.infrastructure.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.endpoint.SanitizableData;
import org.springframework.boot.actuate.endpoint.SanitizingFunction;
import org.springframework.core.env.PropertySource;

class IdentityActuatorSanitizerTest {

  private SanitizingFunction sanitizer;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    IdentityActuatorSanitizer config = new IdentityActuatorSanitizer();
    sanitizer = config.identityKeySanitizer();
  }

  @SuppressWarnings("unchecked")
  private SanitizableData dataFor(String key, Object value) {
    PropertySource<?> source = mock(PropertySource.class);
    return new SanitizableData((PropertySource<Object>) source, key, value);
  }

  @Test
  void should_sanitize_when_keyContainsSalt() {
    SanitizableData result = sanitizer.apply(dataFor("nexus.identity.encryption.salt", "abc123"));

    assertThat(result.getValue()).isEqualTo(SanitizableData.SANITIZED_VALUE);
  }

  @Test
  void should_sanitize_when_keyContainsHmac() {
    SanitizableData result = sanitizer.apply(dataFor("nexus.identity.hmac-key", "supersecret"));

    assertThat(result.getValue()).isEqualTo(SanitizableData.SANITIZED_VALUE);
  }

  @Test
  void should_sanitize_when_keyContainsPassword() {
    SanitizableData result =
        sanitizer.apply(dataFor("nexus.identity.encryption.password", "mysecretpassword"));

    assertThat(result.getValue()).isEqualTo(SanitizableData.SANITIZED_VALUE);
  }

  @Test
  void should_notSanitize_when_keyIsOutsideIdentityNamespace() {
    // "some.api.key" contains "key" but is not under nexus.identity.* — must not be masked
    SanitizableData result = sanitizer.apply(dataFor("some.api.key", "apikey-value"));

    assertThat(result.getValue()).isEqualTo("apikey-value");
  }

  @Test
  void should_notSanitize_when_keyIsNonSensitive() {
    SanitizableData result = sanitizer.apply(dataFor("spring.application.name", "nexus-backend"));

    assertThat(result.getValue()).isEqualTo("nexus-backend");
  }

  @Test
  void should_notSanitize_when_keyIsEmpty() {
    SanitizableData result = sanitizer.apply(dataFor("", "somevalue"));

    assertThat(result.getValue()).isEqualTo("somevalue");
  }

  @Test
  void should_sanitize_when_keyContainsSaltCaseInsensitive() {
    SanitizableData result = sanitizer.apply(dataFor("NEXUS_IDENTITY_ENCRYPTION_SALT", "abc123"));

    assertThat(result.getValue()).isEqualTo(SanitizableData.SANITIZED_VALUE);
  }

  @Test
  void should_notSanitize_when_identityKeyHasNoSensitiveWord() {
    // nexus.identity.* namespace but no password/salt/hmac/key word — must NOT be masked
    SanitizableData result =
        sanitizer.apply(dataFor("nexus.identity.enabled", "true"));

    assertThat(result.getValue()).isEqualTo("true");
  }

  @Test
  void should_sanitize_when_envVarFormContainsHmac() {
    // Environment-variable form NEXUS_IDENTITY_HMAC_KEY (Boot converts _ to . in relaxed binding)
    SanitizableData result =
        sanitizer.apply(dataFor("NEXUS_IDENTITY_HMAC_KEY", "supersecret"));

    assertThat(result.getValue()).isEqualTo(SanitizableData.SANITIZED_VALUE);
  }

  @Test
  void should_notSanitize_when_nonIdentityKeyContainsPassword() {
    // Contains "password" but is NOT under nexus.identity.* — must not be masked
    SanitizableData result =
        sanitizer.apply(dataFor("spring.datasource.password", "dbpass"));

    assertThat(result.getValue()).isEqualTo("dbpass");
  }
}
