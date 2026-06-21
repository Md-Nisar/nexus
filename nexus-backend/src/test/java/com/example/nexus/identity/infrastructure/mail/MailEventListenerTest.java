package com.example.nexus.identity.infrastructure.mail;

import static org.mockito.Mockito.verify;

import com.example.nexus.identity.application.event.AccountExistsEmailEvent;
import com.example.nexus.identity.application.event.VerificationEmailEvent;
import com.example.nexus.identity.application.port.out.MailSenderPort;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MailEventListenerTest {

  @Mock
  private MailSenderPort mailSenderPort;

  @InjectMocks
  private MailEventListener listener;

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
}
