package com.example.nexus.identity.application.event;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class DomainEventToStringTest {

  @Test
  void verificationEmailEvent_toString_masksEmailAndRedactsToken() {
    var event = new VerificationEmailEvent("alice@example.com", "super-secret-raw-token", UUID.fromString("00000000-0000-0000-0000-000000000001"));
    String result = event.toString();
    assertThat(result).contains("a***@example.com");
    assertThat(result).contains("<redacted>");
    assertThat(result).doesNotContain("super-secret-raw-token");
    assertThat(result).doesNotContain("alice@example.com");
  }

  @Test
  void accountExistsEmailEvent_toString_masksEmail() {
    var event = new AccountExistsEmailEvent("bob@example.com");
    String result = event.toString();
    assertThat(result).contains("b***@example.com");
    assertThat(result).doesNotContain("bob@example.com");
  }

  @Test
  void passwordResetEmailEvent_toString_masksEmailAndRedactsToken() {
    // SEC-3: raw token must never appear in log output; email must be masked.
    var event = new PasswordResetEmailEvent(
        "carol@example.com",
        "super-secret-reset-token",
        UUID.fromString("00000000-0000-0000-0000-000000000002"));

    String result = event.toString();

    assertThat(result).contains("<redacted>");
    assertThat(result).contains("c***@example.com");
    assertThat(result).doesNotContain("super-secret-reset-token");
    assertThat(result).doesNotContain("carol@example.com");
  }
}
