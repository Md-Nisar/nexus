package com.example.nexus.identity.infrastructure.mail;

import static org.mockito.Mockito.verify;

import com.example.nexus.identity.application.event.AccountExistsEmailEvent;
import com.example.nexus.identity.application.event.PasswordResetEmailEvent;
import com.example.nexus.identity.application.event.VerificationEmailEvent;
import com.example.nexus.identity.application.port.out.MailSenderPort;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MailEventListenerTest {

  private MailSenderPort mailSenderPort;
  private MailEventListener listener;

  @BeforeEach
  void setUp() {
    mailSenderPort = org.mockito.Mockito.mock(MailSenderPort.class);
    listener = new MailEventListener(
        mailSenderPort,
        new com.example.nexus.common.observation.ExecutionObserver(null)
    );
  }

  @Test
  void onVerificationEmail_delegatesRawTokenAndAddress_toPort() {
    VerificationEmailEvent event =
        new VerificationEmailEvent("alice@example.com", "rawtoken123", UUID.randomUUID());

    listener.onVerificationEmail(event);

    verify(mailSenderPort).sendVerificationEmail("alice@example.com", "rawtoken123");
  }

  @Test
  void onAccountExists_delegatesAddress_toPort() {
    AccountExistsEmailEvent event = new AccountExistsEmailEvent("bob@example.com");

    listener.onAccountExists(event);

    verify(mailSenderPort).sendAccountExistsEmail("bob@example.com");
  }

  @Test
  void onPasswordReset_delegatesRawTokenAndAddress_toPort() {
    PasswordResetEmailEvent event =
        new PasswordResetEmailEvent("carol@example.com", "rawresettoken", UUID.randomUUID());

    listener.onPasswordReset(event);

    verify(mailSenderPort).sendPasswordResetEmail("carol@example.com", "rawresettoken");
  }
}
