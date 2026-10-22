package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** The small value types of the access-review reads (US-018 C3). */
@Tag("UnitTest")
class AccessReviewRecordsTest {

  @Test
  void should_dropOnlyAssignedBy_when_aRoleHolderIsRedacted() {
    UUID user = UUID.randomUUID();
    UUID assignment = UUID.randomUUID();
    Instant at = Instant.now();

    RoleHolder redacted = new RoleHolder(user, assignment, at, UUID.randomUUID()).withAssignedByRedacted();

    assertThat(redacted).isEqualTo(new RoleHolder(user, assignment, at, null));
  }

  @Test
  void should_copyViaRoleIdsDefensively_when_aPermissionHolderIsBuilt() {
    List<UUID> roles = new ArrayList<>(List.of(UUID.randomUUID()));
    PermissionHolder holder = new PermissionHolder(UUID.randomUUID(), roles);

    roles.add(UUID.randomUUID());

    assertThat(holder.viaRoleIds()).hasSize(1);
    assertThatThrownBy(() -> holder.viaRoleIds().add(UUID.randomUUID()))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void should_copyViaRoleIdsDefensively_when_anEffectivePermissionIsBuilt() {
    List<UUID> roles = new ArrayList<>(List.of(UUID.randomUUID()));
    EffectivePermission permission = new EffectivePermission("audit:read", roles);

    roles.clear();

    assertThat(permission.viaRoleIds()).hasSize(1);
    assertThat(permission.name()).isEqualTo("audit:read");
  }

  @Test
  void should_carryTheProjectionFacts_when_viaRoleRowsAreBuilt() {
    UUID user = UUID.randomUUID();
    UUID role = UUID.randomUUID();

    assertThat(new UserViaRole(user, role).userId()).isEqualTo(user);
    assertThat(new PermissionViaRole("user:read", role).roleId()).isEqualTo(role);
  }
}
