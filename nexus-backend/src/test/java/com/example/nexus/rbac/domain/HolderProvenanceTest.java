package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class HolderProvenanceTest {

  @Test
  void should_exposeBothIds_when_constructed() {
    UUID user = UUID.randomUUID();
    UUID assigner = UUID.randomUUID();

    HolderProvenance holder = new HolderProvenance(user, assigner);

    assertThat(holder.userId()).isEqualTo(user);
    assertThat(holder.assignedBy()).isEqualTo(assigner);
  }

  @Test
  void should_beEqual_when_bothIdsMatch() {
    UUID user = UUID.randomUUID();
    UUID assigner = UUID.randomUUID();

    assertThat(new HolderProvenance(user, assigner))
        .isEqualTo(new HolderProvenance(user, assigner))
        .hasSameHashCodeAs(new HolderProvenance(user, assigner));
  }
}
