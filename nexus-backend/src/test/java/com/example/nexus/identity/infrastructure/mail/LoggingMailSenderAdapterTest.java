package com.example.nexus.identity.infrastructure.mail;

import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Test;

class LoggingMailSenderAdapterTest {

  private final LoggingMailSenderAdapter adapter = new LoggingMailSenderAdapter();

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
}
