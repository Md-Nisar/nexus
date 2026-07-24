package com.example.nexus.identity.infrastructure.mail;

import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import com.example.nexus.common.observation.ExecutionObserver;

@Tag("UnitTest")
class LoggingMailSenderAdapterTest {

  private final LoggingMailSenderAdapter adapter = new LoggingMailSenderAdapter(new ExecutionObserver(null));

  @Test
  void sendVerificationEmail_completesWithoutThrowing() {
    assertThatCode(() -> adapter.sendVerificationEmail("alice@example.com", "a".repeat(64)))
        .doesNotThrowAnyException();
  }

  @Test
  void sendAccountExistsEmail_completesWithoutThrowing() {
    assertThatCode(() -> adapter.sendAccountExistsEmail("bob@example.com"))
        .doesNotThrowAnyException();
  }

  @Test
  void sendPasswordResetEmail_completesWithoutThrowing() {
    assertThatCode(() -> adapter.sendPasswordResetEmail("carol@example.com", "a".repeat(64)))
        .doesNotThrowAnyException();
  }

  @Test
  void sendPasswordResetEmail_doesNotLogRawToken() {
    // SEC-3: raw token must not appear in toString output
    String rawToken = "a".repeat(64);
    String eventString = new com.example.nexus.identity.application.event
        .PasswordResetEmailEvent("carol@example.com", rawToken, java.util.UUID.randomUUID())
        .toString();

    org.assertj.core.api.Assertions.assertThat(eventString).doesNotContain(rawToken);
    org.assertj.core.api.Assertions.assertThat(eventString).contains("<redacted>");
  }
}
