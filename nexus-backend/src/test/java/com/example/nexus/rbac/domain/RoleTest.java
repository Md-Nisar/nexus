package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RoleTest {

  @Test
  void should_setRequiredFields_when_constructorCalled() {
    UUID id = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();

    Role role =
        new Role(id, tenantId, "TENANT_ADMIN", "Full administrative control within the tenant", true);

    assertThat(role.getId()).isEqualTo(id);
    assertThat(role.getTenantId()).isEqualTo(tenantId);
    assertThat(role.getName()).isEqualTo("TENANT_ADMIN");
    assertThat(role.getDescription()).isEqualTo("Full administrative control within the tenant");
    assertThat(role.isSystemRole()).isTrue();
  }

  @Test
  void should_defaultAuditTimestampsToNull_when_constructed() {
    Role role =
        new Role(
            UUID.randomUUID(),
            UUID.randomUUID(),
            "MEMBER",
            "Standard member with read access to users",
            true);

    assertThat(role.getCreatedAt()).isNull();
    assertThat(role.getUpdatedAt()).isNull();
  }

  @Test
  void should_allowNullDescription_when_constructedWithoutOne() {
    Role role = new Role(UUID.randomUUID(), UUID.randomUUID(), "CUSTOM", null, false);

    assertThat(role.getDescription()).isNull();
    assertThat(role.isSystemRole()).isFalse();
  }
}
