package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RoleViewTest {

  @Test
  void should_exposeAllFields_when_constructed() {
    UUID id = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    Instant createdAt = Instant.now();

    RoleView view = new RoleView(id, tenantId, "Sales Manager", "Manages sales team", false, createdAt);

    assertThat(view.id()).isEqualTo(id);
    assertThat(view.tenantId()).isEqualTo(tenantId);
    assertThat(view.name()).isEqualTo("Sales Manager");
    assertThat(view.description()).isEqualTo("Manages sales team");
    assertThat(view.systemRole()).isFalse();
    assertThat(view.createdAt()).isEqualTo(createdAt);
  }
}
