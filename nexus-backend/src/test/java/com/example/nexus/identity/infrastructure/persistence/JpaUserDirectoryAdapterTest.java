package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.rbac.application.port.out.DirectoryUser;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class JpaUserDirectoryAdapterTest {

  @Mock
  private JpaUserRepository userRepository;

  @InjectMocks
  private JpaUserDirectoryAdapter adapter;

  @Test
  void should_returnTenantId_when_userExists() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    User user = mock(User.class);
    when(user.getTenantId()).thenReturn(tenantId);
    when(userRepository.findById(userId)).thenReturn(Optional.of(user));

    Optional<UUID> result = adapter.findTenantId(userId);

    assertThat(result).contains(tenantId);
    verify(userRepository).findById(userId);
  }

  @Test
  void should_returnEmpty_when_userDoesNotExist() {
    UUID userId = UUID.randomUUID();
    when(userRepository.findById(userId)).thenReturn(Optional.empty());

    Optional<UUID> result = adapter.findTenantId(userId);

    assertThat(result).isEmpty();
    verify(userRepository).findById(userId);
  }

  // US-018 T-007 (03-design.md §7.1): the break-glass target lookup — tenant and ACTIVE-ness only,
  // so rbac never sees identity's UserStatus.

  @Test
  void should_returnTenantAndActiveTrue_when_userIsActive() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    User user = mock(User.class);
    when(user.getTenantId()).thenReturn(tenantId);
    when(user.getStatus()).thenReturn(UserStatus.ACTIVE);
    when(userRepository.findById(userId)).thenReturn(Optional.of(user));

    Optional<DirectoryUser> result = adapter.findUser(userId);

    assertThat(result).contains(new DirectoryUser(tenantId, true));
  }

  @ParameterizedTest
  @EnumSource(value = UserStatus.class, names = "ACTIVE", mode = EnumSource.Mode.EXCLUDE)
  void should_returnActiveFalse_when_userIsNotActive(UserStatus status) {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    User user = mock(User.class);
    when(user.getTenantId()).thenReturn(tenantId);
    when(user.getStatus()).thenReturn(status);
    when(userRepository.findById(userId)).thenReturn(Optional.of(user));

    Optional<DirectoryUser> result = adapter.findUser(userId);

    assertThat(result).contains(new DirectoryUser(tenantId, false));
  }

  @Test
  void should_returnEmptyDirectoryUser_when_userDoesNotExist() {
    UUID userId = UUID.randomUUID();
    when(userRepository.findById(userId)).thenReturn(Optional.empty());

    assertThat(adapter.findUser(userId)).isEmpty();
  }
}
