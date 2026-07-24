package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class EmailCipherTest {

  @Test
  void should_returnRedacted_when_toStringCalled() {
    var cipher = new EmailCipher("secret@example.com");

    assertThat(cipher.toString()).isEqualTo("EmailCipher[REDACTED]");
    assertThat(cipher.toString()).doesNotContain("secret@example.com");
  }

  @Test
  void should_returnOriginalValue_when_valueAccessorCalled() {
    var cipher = new EmailCipher("user@example.com");

    assertThat(cipher.value()).isEqualTo("user@example.com");
  }

  @Test
  void should_beEqual_when_sameValueWrapped() {
    var a = new EmailCipher("same@example.com");
    var b = new EmailCipher("same@example.com");

    assertThat(a).isEqualTo(b);
  }
}
