package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class UserRoleTest {

  @Test
  void should_setRequiredFields_when_constructorCalled() {
    UUID id = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    UUID assignedBy = UUID.randomUUID();

    UserRole userRole = new UserRole(id, userId, roleId, tenantId, assignedBy);

    assertThat(userRole.getId()).isEqualTo(id);
    assertThat(userRole.getUserId()).isEqualTo(userId);
    assertThat(userRole.getRoleId()).isEqualTo(roleId);
    assertThat(userRole.getTenantId()).isEqualTo(tenantId);
    assertThat(userRole.getAssignedBy()).isEqualTo(assignedBy);
  }

  @Test
  void should_defaultDbManagedFieldsToNull_when_constructed() {
    UserRole userRole =
        new UserRole(
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID());

    assertThat(userRole.getAssignedAt()).isNull();
    assertThat(userRole.getRevokedAt()).isNull();
    assertThat(userRole.getActiveKey()).isNull();
  }
}
