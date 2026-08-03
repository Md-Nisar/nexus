package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class ActiveAssignmentRefTest {

  @Test
  void should_exposeIdAndAssignedAt_when_constructed() {
    UUID id = UUID.randomUUID();
    Instant assignedAt = Instant.now();

    ActiveAssignmentRef ref = new ActiveAssignmentRef(id, assignedAt);

    assertThat(ref.id()).isEqualTo(id);
    assertThat(ref.assignedAt()).isEqualTo(assignedAt);
  }
}
