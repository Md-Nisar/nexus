package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class PermissionViewTest {

  @Test
  void should_exposeAllFields_when_constructed() {
    UUID id = UUID.randomUUID();

    PermissionView view = new PermissionView(id, "role:write", "Create and modify roles");

    assertThat(view.id()).isEqualTo(id);
    assertThat(view.name()).isEqualTo("role:write");
    assertThat(view.description()).isEqualTo("Create and modify roles");
  }
}
