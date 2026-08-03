package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RoleChangeActorTest {

  @Test
  void should_exposeUserIdAndTenantId_when_constructed() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();

    RoleChangeActor actor = new RoleChangeActor(userId, tenantId);

    assertThat(actor.userId()).isEqualTo(userId);
    assertThat(actor.tenantId()).isEqualTo(tenantId);
  }
}
