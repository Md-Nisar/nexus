package com.example.nexus.rbac.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.domain.IdGenerator;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class JpaUserRoleRepositoryDeadlockTest {

  @Mock private JpaUserRoleRepository userRoleRepository;
  @Mock private JpaRoleRepository roleRepository;
  @Mock private JpaPermissionCatalogueRepository permissionCatalogueRepository;
  @Mock private IdGenerator idGenerator;

  @Captor private ArgumentCaptor<List<byte[]>> roleIdsCaptor;

  private JpaUserRoleAssignmentAdapter adapter;

  @BeforeEach
  void setUp() {
    adapter =
        new JpaUserRoleAssignmentAdapter(
            userRoleRepository, roleRepository, permissionCatalogueRepository, idGenerator);
  }

  @Test
  void should_sort_role_ids_strictly_by_unsigned_bytes() {
    UUID idNegative = UUID.fromString("80000000-0000-0000-0000-000000000000");
    UUID idPositive = UUID.fromString("01000000-0000-0000-0000-000000000000");
    UUID tenantId = UUID.randomUUID();

    assertThat(idNegative.compareTo(idPositive))
        .as("Java signed compareTo treats 0x80 as negative")
        .isLessThan(0);

    when(userRoleRepository.lockActiveAssignmentHoldersByRoles(any(), any()))
        .thenReturn(List.of());

    adapter.lockActiveAssignmentHolders(tenantId, List.of(idNegative, idPositive));

    verify(userRoleRepository).lockActiveAssignmentHoldersByRoles(roleIdsCaptor.capture(), any());
    List<byte[]> capturedBytes = roleIdsCaptor.getValue();

    assertThat(capturedBytes).hasSize(2);
    assertThat(Arrays.compareUnsigned(capturedBytes.get(0), capturedBytes.get(1))).isLessThan(0);
    assertThat(capturedBytes.get(0)).isEqualTo(toBytes(idPositive));
    assertThat(capturedBytes.get(1)).isEqualTo(toBytes(idNegative));
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
