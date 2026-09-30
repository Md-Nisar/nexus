package com.example.nexus.identity.infrastructure.seed;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.RbacRoleNames;
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
  private static final UUID ADMIN_ROLE_ID = UUID.fromString("019f6839-1810-7000-8000-00000000000a");

  @Mock private UserRegistrationPort userRegistrationPort;
  @Mock private PasswordHasherPort passwordHasherPort;
  @Mock private UuidGenerator uuidGenerator;
  @Mock private UserRoleAssignmentPort userRoleAssignmentPort;

  private EmailBlindIndexService emailBlindIndexService;
  private DevDataInitializer initializer;

  @BeforeEach
  void setUp() {
    emailBlindIndexService = new EmailBlindIndexService(
        "dev-not-a-secret-hmac-key-min-32-bytes-long".getBytes());
    initializer = new DevDataInitializer(
        userRegistrationPort, emailBlindIndexService, passwordHasherPort, uuidGenerator,
        userRoleAssignmentPort, TENANT_ID);
  }

  @Test
  void run_userDoesNotExist_seedsAndActivatesUser() {
    when(userRegistrationPort.findByTenantAndEmailHmac(eq(TENANT_ID), any())).thenReturn(
        Optional.empty());
    when(passwordHasherPort.hash("TestPass99!")).thenReturn("hashed-password");
    when(uuidGenerator.newId()).thenReturn(UUID.randomUUID());
    when(userRegistrationPort.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
    stubAdminRole();

    initializer.run(null);

    ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
    verify(userRegistrationPort, times(2)).save(captor.capture());
    User savedUser = captor.getValue();
    assertThat(savedUser.getStatus()).isEqualTo(UserStatus.ACTIVE);
    assertThat(savedUser.getTenantId()).isEqualTo(TENANT_ID);
    verify(userRoleAssignmentPort)
        .assign(savedUser.getId(), ADMIN_ROLE_ID, TENANT_ID, savedUser.getId());
  }

  @Test
  void run_userAlreadyExistsWithoutRole_skipsSeedingButGrantsRole() {
    User existing = existingUser();
    when(userRegistrationPort.findByTenantAndEmailHmac(eq(TENANT_ID), any())).thenReturn(
        Optional.of(existing));
    stubAdminRole();
    when(userRoleAssignmentPort.hasActiveAssignment(existing.getId(), ADMIN_ROLE_ID))
        .thenReturn(false);

    initializer.run(null);

    verify(userRegistrationPort, never()).save(any());
    verify(passwordHasherPort, never()).hash(any());
    verify(userRoleAssignmentPort)
        .assign(existing.getId(), ADMIN_ROLE_ID, TENANT_ID, existing.getId());
  }

  @Test
  void run_userAlreadyHasRole_changesNothing() {
    User existing = existingUser();
    when(userRegistrationPort.findByTenantAndEmailHmac(eq(TENANT_ID), any())).thenReturn(
        Optional.of(existing));
    stubAdminRole();
    when(userRoleAssignmentPort.hasActiveAssignment(existing.getId(), ADMIN_ROLE_ID))
        .thenReturn(true);

    initializer.run(null);

    verify(userRegistrationPort, never()).save(any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  @Test
  void run_adminRoleMissing_seedsUserWithoutFailingStartup() {
    User existing = existingUser();
    when(userRegistrationPort.findByTenantAndEmailHmac(eq(TENANT_ID), any())).thenReturn(
        Optional.of(existing));
    when(userRoleAssignmentPort.findRoleIdByName(TENANT_ID, RbacRoleNames.TENANT_ADMIN))
        .thenReturn(Optional.empty());

    initializer.run(null);

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  private void stubAdminRole() {
    when(userRoleAssignmentPort.findRoleIdByName(TENANT_ID, RbacRoleNames.TENANT_ADMIN))
        .thenReturn(Optional.of(ADMIN_ROLE_ID));
  }

  private static User existingUser() {
    return new User(
        UUID.randomUUID(),
        TENANT_ID,
        new EmailCipher("test@example.com"),
        "existing-hmac",
        "existing-hash",
        Instant.now());
  }
}
