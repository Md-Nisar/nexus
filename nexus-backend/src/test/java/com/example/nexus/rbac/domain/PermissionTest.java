package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class PermissionTest {

  @Test
  void should_setRequiredFields_when_constructorCalled() {
    UUID id = UUID.randomUUID();

    Permission permission = new Permission(id, "user:read", "Read user accounts and profiles");

    assertThat(permission.getId()).isEqualTo(id);
    assertThat(permission.getName()).isEqualTo("user:read");
    assertThat(permission.getDescription()).isEqualTo("Read user accounts and profiles");
  }

  @Test
  void should_defaultCreatedAtToNull_when_constructed() {
    Permission permission =
        new Permission(UUID.randomUUID(), "tenant:write", "Create and modify tenant configuration");

    assertThat(permission.getCreatedAt()).isNull();
  }
}
