package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RbacRoleNamesTest {

  @Test
  void should_defineTenantAdminConstant_when_referenced() {
    assertThat(RbacRoleNames.TENANT_ADMIN).isEqualTo("TENANT_ADMIN");
  }

  @Test
  void should_matchTenantAdmin_when_comparedCaseInsensitively() {
    assertThat(RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase("Tenant_Admin")).isTrue();
    assertThat(RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase("MEMBER")).isFalse();
  }
}
