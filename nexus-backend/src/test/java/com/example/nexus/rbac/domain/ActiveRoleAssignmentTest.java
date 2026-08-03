package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class ActiveRoleAssignmentTest {

  @Test
  void should_exposeAllFields_when_constructed() {
    UUID userId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    UUID assignedBy = UUID.randomUUID();

    ActiveRoleAssignment assignment =
        new ActiveRoleAssignment(userId, roleId, "TENANT_ADMIN", assignedAt, assignedBy);

    assertThat(assignment.userId()).isEqualTo(userId);
    assertThat(assignment.roleId()).isEqualTo(roleId);
    assertThat(assignment.roleName()).isEqualTo("TENANT_ADMIN");
    assertThat(assignment.assignedAt()).isEqualTo(assignedAt);
    assertThat(assignment.assignedBy()).isEqualTo(assignedBy);
  }
}
