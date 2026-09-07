package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RbacDangerousPermissionsTest {

  @Test
  void should_containRoleWriteUserWriteTenantWrite_when_checked() {
    assertThat(RbacDangerousPermissions.NAMES)
        .containsExactlyInAnyOrder("role:write", "user:write", "tenant:write");
  }

  @Test
  void should_returnTrue_when_permissionNameMatchesCaseInsensitively() {
    assertThat(RbacDangerousPermissions.contains("role:write")).isTrue();
    assertThat(RbacDangerousPermissions.contains("ROLE:WRITE")).isTrue();
    assertThat(RbacDangerousPermissions.contains("User:Write")).isTrue();
    assertThat(RbacDangerousPermissions.contains("tenant:write")).isTrue();
  }

  @Test
  void should_returnFalse_when_permissionNameIsNotDangerous() {
    assertThat(RbacDangerousPermissions.contains("user:read")).isFalse();
    assertThat(RbacDangerousPermissions.contains("role:read")).isFalse();
  }

  @Test
  void should_returnFalse_when_permissionNameIsNull() {
    assertThat(RbacDangerousPermissions.contains(null)).isFalse();
  }
}
