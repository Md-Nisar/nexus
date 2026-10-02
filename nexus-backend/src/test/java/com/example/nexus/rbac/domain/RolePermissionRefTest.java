package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RolePermissionRefTest {

  @Test
  void should_exposeRoleIdAndPermissionId_when_constructed() {
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();

    RolePermissionRef ref = new RolePermissionRef(roleId, permissionId);

    assertThat(ref.roleId()).isEqualTo(roleId);
    assertThat(ref.permissionId()).isEqualTo(permissionId);
  }

  @Test
  void should_beEqual_when_sameIds() {
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();

    assertThat(new RolePermissionRef(roleId, permissionId))
        .isEqualTo(new RolePermissionRef(roleId, permissionId))
        .hasSameHashCodeAs(new RolePermissionRef(roleId, permissionId));
  }
}
