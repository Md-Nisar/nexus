package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.rbac.application.port.out.DirectoryUser;
import com.example.nexus.rbac.application.port.out.DirectoryUserStatus;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
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

  // US-018 A7, O-7 and L-2: the statuses of the target and the administrator holders, read with a
  // locking read inside the grant transaction, mapped to rbac's port-local status.

  @Test
  void should_passTenantAndIdsAsBytes_andMapEveryReturnedRowToItsStatus_when_lockingUserStatuses() {
    UUID tenantId = UUID.randomUUID();
    UUID active = UUID.randomUUID();
    UUID disabled = UUID.randomUUID();
    when(userRepository.lockStatusesByIds(any(), any()))
        .thenReturn(List.of(row(active, "ACTIVE"), row(disabled, "DISABLED")));

    Map<UUID, DirectoryUserStatus> result =
        adapter.lockUserStatuses(tenantId, Set.of(active, disabled));

    assertThat(result)
        .containsExactlyInAnyOrderEntriesOf(
            Map.of(active, DirectoryUserStatus.ACTIVE, disabled, DirectoryUserStatus.DISABLED));
    @SuppressWarnings("unchecked")
    ArgumentCaptor<Collection<byte[]>> ids = ArgumentCaptor.forClass(Collection.class);
    ArgumentCaptor<byte[]> tenant = ArgumentCaptor.forClass(byte[].class);
    verify(userRepository).lockStatusesByIds(ids.capture(), tenant.capture());
    assertThat(ids.getValue()).containsExactlyInAnyOrder(toBytes(active), toBytes(disabled));
    assertThat(tenant.getValue()).isEqualTo(toBytes(tenantId));
  }

  @ParameterizedTest
  @EnumSource(UserStatus.class)
  void should_mapEveryIdentityStatusToTheSameNamedDirectoryStatus(UserStatus status) {
    UUID userId = UUID.randomUUID();
    when(userRepository.lockStatusesByIds(any(), any()))
        .thenReturn(List.of(row(userId, status.name())));

    Map<UUID, DirectoryUserStatus> result =
        adapter.lockUserStatuses(UUID.randomUUID(), Set.of(userId));

    assertThat(result).containsExactly(Map.entry(userId, DirectoryUserStatus.valueOf(status.name())));
  }

  @Test
  void should_omitUsersTheLockingReadDidNotReturn() {
    when(userRepository.lockStatusesByIds(any(), any())).thenReturn(List.of());

    assertThat(adapter.lockUserStatuses(UUID.randomUUID(), Set.of(UUID.randomUUID()))).isEmpty();
  }

  private static JpaUserRepository.UserStatusRow row(UUID id, String status) {
    return new JpaUserRepository.UserStatusRow() {
      @Override
      public byte[] getId() {
        return toBytes(id);
      }

      @Override
      public String getStatus() {
        return status;
      }
    };
  }

  private static byte[] toBytes(UUID uuid) {
    return ByteBuffer.allocate(16)
        .putLong(uuid.getMostSignificantBits())
        .putLong(uuid.getLeastSignificantBits())
        .array();
  }
}
