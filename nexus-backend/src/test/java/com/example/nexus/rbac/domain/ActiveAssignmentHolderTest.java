package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class ActiveAssignmentHolderTest {

  @Test
  void should_exposeAssignmentIdUserIdRoleIdAndAssignedBy_when_constructed() {
    UUID assignmentId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    UUID assignedBy = UUID.randomUUID();

    ActiveAssignmentHolder holder =
        new ActiveAssignmentHolder(assignmentId, userId, roleId, assignedBy);

    assertThat(holder.assignmentId()).isEqualTo(assignmentId);
    assertThat(holder.userId()).isEqualTo(userId);
    assertThat(holder.roleId()).isEqualTo(roleId);
    assertThat(holder.assignedBy()).isEqualTo(assignedBy);
  }
}
