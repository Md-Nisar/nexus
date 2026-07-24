package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RolePermissionTest {

  @Test
  void should_setRequiredFields_when_constructorCalled() {
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();

    RolePermission rolePermission = new RolePermission(roleId, permissionId);

    assertThat(rolePermission.getRoleId()).isEqualTo(roleId);
    assertThat(rolePermission.getPermissionId()).isEqualTo(permissionId);
  }

  @Test
  void should_defaultCreatedAtToNull_when_constructed() {
    RolePermission rolePermission = new RolePermission(UUID.randomUUID(), UUID.randomUUID());

    assertThat(rolePermission.getCreatedAt()).isNull();
  }
}
