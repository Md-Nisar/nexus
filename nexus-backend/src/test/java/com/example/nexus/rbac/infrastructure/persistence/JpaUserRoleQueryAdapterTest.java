package com.example.nexus.rbac.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.domain.PermissionViaRole;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class JpaUserRoleQueryAdapterTest {

  private final JpaUserRoleRepository repository = mock(JpaUserRoleRepository.class);
  private final JpaUserRoleQueryAdapter adapter = new JpaUserRoleQueryAdapter(repository);
  private final UUID userId = UUID.randomUUID();
  private final UUID tenantId = UUID.randomUUID();

  @Test
  void should_delegateTheTwoMintTimeReads_unchanged() {
    when(repository.findActiveRoleNames(userId, tenantId)).thenReturn(List.of("MEMBER"));
    when(repository.findActivePermissionNames(userId, tenantId)).thenReturn(List.of("user:read"));

    assertThat(adapter.findActiveRoleNames(userId, tenantId)).containsExactly("MEMBER");
    assertThat(adapter.findActivePermissionNames(userId, tenantId)).containsExactly("user:read");
  }

  @Test
  void should_delegatePermissionRolePairsWithTheTenant_when_findingEffectivePermissions() {
    PermissionViaRole row = new PermissionViaRole("audit:read", UUID.randomUUID());
    when(repository.findActivePermissionsViaRoles(userId, tenantId)).thenReturn(List.of(row));

    assertThat(adapter.findActivePermissionsViaRoles(userId, tenantId)).containsExactly(row);
  }
}
