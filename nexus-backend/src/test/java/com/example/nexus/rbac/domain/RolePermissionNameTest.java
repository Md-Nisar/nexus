package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RolePermissionNameTest {

  @Test
  void should_exposeRoleIdAndPermissionName_when_constructed() {
    UUID roleId = UUID.randomUUID();
    String permissionName = "user:write";

    RolePermissionName rolePermissionName = new RolePermissionName(roleId, permissionName);

    assertThat(rolePermissionName.roleId()).isEqualTo(roleId);
    assertThat(rolePermissionName.permissionName()).isEqualTo(permissionName);
  }
}
