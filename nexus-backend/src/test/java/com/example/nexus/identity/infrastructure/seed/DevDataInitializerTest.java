package com.example.nexus.identity.infrastructure.seed;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Unit tests for {@link DevDataInitializer} (dev-profile E2E test-user seed). */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class DevDataInitializerTest {

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");

  @Mock private UserRegistrationPort userRegistrationPort;
  @Mock private PasswordHasherPort passwordHasherPort;
  @Mock private UuidGenerator uuidGenerator;

  private EmailBlindIndexService emailBlindIndexService;
  private DevDataInitializer initializer;

  @BeforeEach
  void setUp() {
    emailBlindIndexService = new EmailBlindIndexService(
        "dev-not-a-secret-hmac-key-min-32-bytes-long".getBytes());
    initializer = new DevDataInitializer(
        userRegistrationPort, emailBlindIndexService, passwordHasherPort, uuidGenerator, TENANT_ID);
  }

  @Test
  void run_userDoesNotExist_seedsAndActivatesUser() {
    when(userRegistrationPort.findByTenantAndEmailHmac(eq(TENANT_ID), any())).thenReturn(
        Optional.empty());
    when(passwordHasherPort.hash("TestPass99!")).thenReturn("hashed-password");
    when(uuidGenerator.newId()).thenReturn(UUID.randomUUID());
    when(userRegistrationPort.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

    initializer.run(null);

    ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
    verify(userRegistrationPort, org.mockito.Mockito.times(2)).save(captor.capture());
    User savedUser = captor.getValue();
    assertThat(savedUser.getStatus()).isEqualTo(UserStatus.ACTIVE);
    assertThat(savedUser.getTenantId()).isEqualTo(TENANT_ID);
  }

  @Test
  void run_userAlreadyExists_skipsSeeding() {
    User existing = new User(
        UUID.randomUUID(),
        TENANT_ID,
        new EmailCipher("test@example.com"),
        "existing-hmac",
        "existing-hash",
        Instant.now());
    when(userRegistrationPort.findByTenantAndEmailHmac(eq(TENANT_ID), any())).thenReturn(
        Optional.of(existing));

    initializer.run(null);

    verify(userRegistrationPort, never()).save(any());
    verify(passwordHasherPort, never()).hash(any());
  }
}
