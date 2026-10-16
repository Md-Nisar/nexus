package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-018 MC-H' (04-tasks.md T-019): the per-role partition of M13 (the caller's held {@code (role,
 * permission)} snapshot) equals what M14 (a role's permission ids, tenant-scoped) returns when
 * called per role, over a fixture matrix: a normal role, a zero-permission role, a whole-catalogue
 * role, a role of a foreign tenant assigned in this tenant, and (US-018 T-026) a soft-deleted role
 * that still has a hand-made active assignment, which M13 must not report and M14 must fail closed
 * on.
 *
 * <p>Requires Docker (Testcontainers); written in M3 and not run where Docker is unavailable.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class HeldPermissionPartitionIT {

  @Autowired private UserRoleAssignmentPort port;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  @Test
  void should_partitionM13PerRoleExactlyAsM14_when_fixtureMatrixIsHeld() {
    UUID tenantId = uuidGenerator.newId();
    UUID foreignTenantId = uuidGenerator.newId();
    User user = seedUser(tenantId);
    Role normal = seedRole(tenantId, "HPP-NORMAL");
    grant(normal, "audit:read", "role:read");
    Role empty = seedRole(tenantId, "HPP-EMPTY");
    Role whole = seedRole(tenantId, "HPP-WHOLE");
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions",
        whole.getId().toString());
    Role foreign = seedRole(foreignTenantId, "HPP-FOREIGN");
    grant(foreign, "audit:read");
    Role deleted = seedRole(tenantId, "HPP-DELETED");
    grant(deleted, "audit:read");
    List<Role> roles = List.of(normal, empty, whole, foreign);
    for (Role role : roles) {
      userRoleRepository.save(
          new UserRole(uuidGenerator.newId(), user.getId(), role.getId(), tenantId, user.getId()));
    }
    // A deleted role with an ACTIVE assignment is an invariant break (RC-36.4), forged here on
    // purpose: the read-side filters are defense in depth for exactly this state.
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), deleted.getId(), tenantId, user.getId()));
    jdbc.update(
        "UPDATE roles SET deleted_at = CURRENT_TIMESTAMP(6) WHERE id = UUID_TO_BIN(?)",
        deleted.getId().toString());

    Map<UUID, Set<UUID>> m13ByRole = new HashMap<>();
    for (RolePermissionRef ref : port.findHeldRolePermissionIdsForAuthorization(user.getId(), tenantId)) {
      m13ByRole.computeIfAbsent(ref.roleId(), k -> new HashSet<>()).add(ref.permissionId());
    }

    for (Role role : roles) {
      Optional<Set<UUID>> m14 = port.findPermissionIdsForRole(role.getId(), tenantId);
      assertThat(m13ByRole.getOrDefault(role.getId(), Set.of()))
          .as("M13 partition of role %s equals M14", role.getName())
          .isEqualTo(m14.orElse(Set.of()));
    }
    assertThat(port.findPermissionIdsForRole(foreign.getId(), tenantId))
        .as("M14 fails closed for a role outside the tenant")
        .isEmpty();
    assertThat(m13ByRole.keySet().stream().filter(id -> id.equals(foreign.getId())))
        .as("M13 never reports the foreign-tenant role")
        .isEmpty();
    assertThat(m13ByRole.keySet())
        .as("M13 never reports a soft-deleted role, even one with an active assignment")
        .doesNotContain(deleted.getId());
    assertThat(port.findPermissionIdsForRole(deleted.getId(), tenantId))
        .as("M14 fails closed for a soft-deleted role")
        .isEmpty();
    assertThat(m13ByRole.get(whole.getId())).isEqualTo(port.findCatalogueIds());
    assertThat(m13ByRole.keySet().stream().collect(Collectors.toSet()))
        .doesNotContain(empty.getId());
  }

  private User seedUser(UUID tenantId) {
    String email = "hpp-" + UUID.randomUUID() + "@example.test";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    user.verify(Instant.now());
    return userRepository.save(user);
  }

  private Role seedRole(UUID tenantId, String prefix) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, prefix + "-" + UUID.randomUUID(), "hpp", false));
  }

  private void grant(Role role, String... permissionNames) {
    for (String name : permissionNames) {
      jdbc.update(
          "INSERT INTO role_permissions (role_id, permission_id) "
              + "SELECT UUID_TO_BIN(?), id FROM permissions WHERE name = ?",
          role.getId().toString(),
          name);
    }
  }
}
