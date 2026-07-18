package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class RolePermissionIdTest {

  @Test
  void should_setBothFields_when_allArgsConstructorCalled() {
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();

    RolePermissionId id = new RolePermissionId(roleId, permissionId);

    assertThat(id.getRoleId()).isEqualTo(roleId);
    assertThat(id.getPermissionId()).isEqualTo(permissionId);
  }

  @Test
  void should_beEqualAndShareHashCode_when_bothFieldsMatch() {
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();

    RolePermissionId first = new RolePermissionId(roleId, permissionId);
    RolePermissionId second = new RolePermissionId(roleId, permissionId);

    assertThat(first).isEqualTo(second);
    assertThat(first.hashCode()).isEqualTo(second.hashCode());
  }

  @Test
  void should_notBeEqual_when_roleIdDiffers() {
    UUID permissionId = UUID.randomUUID();

    RolePermissionId first = new RolePermissionId(UUID.randomUUID(), permissionId);
    RolePermissionId second = new RolePermissionId(UUID.randomUUID(), permissionId);

    assertThat(first).isNotEqualTo(second);
  }

  @Test
  void should_notBeEqual_when_permissionIdDiffers() {
    UUID roleId = UUID.randomUUID();

    RolePermissionId first = new RolePermissionId(roleId, UUID.randomUUID());
    RolePermissionId second = new RolePermissionId(roleId, UUID.randomUUID());

    assertThat(first).isNotEqualTo(second);
  }

  @Test
  void should_allowNoArgConstruction_when_requiredByJpa() {
    RolePermissionId id = new RolePermissionId();

    assertThat(id.getRoleId()).isNull();
    assertThat(id.getPermissionId()).isNull();
  }
}
