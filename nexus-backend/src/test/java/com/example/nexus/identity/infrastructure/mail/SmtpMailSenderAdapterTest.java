package com.example.nexus.identity.infrastructure.mail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import com.example.nexus.common.observation.ExecutionObserver;

@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class SmtpMailSenderAdapterTest {

  private static final String FROM = "noreply@nexus.test";
  private static final String BASE_URL = "http://localhost:2000";

  @Mock
  private JavaMailSender javaMailSender;

  private SmtpMailSenderAdapter adapter;

  @BeforeEach
  void setUp() {
    adapter = new SmtpMailSenderAdapter(javaMailSender, FROM, BASE_URL, new ExecutionObserver(null));
  }

  @Test
  void sendVerificationEmail_setsToFromSubjectAndUrlInBody() {
    String rawToken = "a".repeat(64);

    adapter.sendVerificationEmail("alice@example.com", rawToken);

    ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
    verify(javaMailSender).send(captor.capture());
    SimpleMailMessage msg = captor.getValue();
    assertThat(msg.getTo()).containsExactly("alice@example.com");
    assertThat(msg.getFrom()).isEqualTo(FROM);
    assertThat(msg.getSubject()).isEqualTo("Verify your Nexus email address");
    assertThat(msg.getText()).contains(BASE_URL + "/auth/verify-email?token=" + rawToken);
  }

  @Test
  void sendAccountExistsEmail_setsToFromAndSubject() {
    adapter.sendAccountExistsEmail("bob@example.com");

    ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
    verify(javaMailSender).send(captor.capture());
    SimpleMailMessage msg = captor.getValue();
    assertThat(msg.getTo()).containsExactly("bob@example.com");
    assertThat(msg.getFrom()).isEqualTo(FROM);
    assertThat(msg.getSubject()).isEqualTo("You already have a Nexus account");
  }

  @Test
  void sendPasswordResetEmail_setsToFromSubjectAndResetUrlInBody() {
    // Verifies the reset URL is constructed correctly from frontendBaseUrl + path + token (SEC-3).
    String rawToken = "b".repeat(64);

    adapter.sendPasswordResetEmail("carol@example.com", rawToken);

    ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
    verify(javaMailSender).send(captor.capture());
    SimpleMailMessage msg = captor.getValue();
    assertThat(msg.getTo()).containsExactly("carol@example.com");
    assertThat(msg.getFrom()).isEqualTo(FROM);
    assertThat(msg.getSubject()).isEqualTo("Reset your Nexus password");
    assertThat(msg.getText()).contains(BASE_URL + "/auth/reset-password?token=" + rawToken);
  }
}
