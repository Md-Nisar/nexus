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

  @Test
  void should_defineMemberConstant_when_referenced() {
    assertThat(RbacRoleNames.MEMBER).isEqualTo("MEMBER");
  }

  @Test
  void should_includeTenantAdminAndMemberInReservedSet_when_referenced() {
    assertThat(RbacRoleNames.RESERVED).containsExactlyInAnyOrder("TENANT_ADMIN", "MEMBER");
  }

  @Test
  void should_returnTrue_when_isReservedCheckedCaseInsensitively() {
    assertThat(RbacRoleNames.isReserved("TENANT_ADMIN")).isTrue();
    assertThat(RbacRoleNames.isReserved("tenant_admin")).isTrue();
    assertThat(RbacRoleNames.isReserved("MEMBER")).isTrue();
    assertThat(RbacRoleNames.isReserved("Member")).isTrue();
  }

  @Test
  void should_returnFalse_when_isReservedCheckedForNonReservedName() {
    assertThat(RbacRoleNames.isReserved("Sales Manager")).isFalse();
  }

  @Test
  void should_returnFalse_when_isReservedCheckedWithNull() {
    assertThat(RbacRoleNames.isReserved(null)).isFalse();
  }
}
