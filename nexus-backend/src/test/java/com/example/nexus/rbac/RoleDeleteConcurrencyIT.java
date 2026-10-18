package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleHasHoldersException;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-018 T-025 / C1 (03-design.md 11.1; RC-36.1, RC-46.2): races {@code assign} against {@code
 * softDeleteRole} on one role, 50 times each, against real MySQL.
 *
 * <ul>
 *   <li><b>Invariant (RC-36.1):</b> after every race no ACTIVE {@code user_roles} row references a
 *       deleted role. Each attempt ends in exactly one of "assign 201, then delete 409 {@code
 *       RBAC_009}" or "delete 204, then assign 404".
 *   <li><b>No 500 on an admin-defining target (RC-46.2):</b> a holder-less admin-defining custom
 *       role, where assign and DELETE both take the set lock first; an InnoDB deadlock (1213) would
 *       surface here as an unexpected exception type and fail the run.
 * </ul>
 *
 * Service-level, as {@code RoleAssignmentIT}: the HTTP mapping of these exceptions is the controller
 * and {@code GlobalExceptionHandler} slice tests' concern. Fixtures use a fresh tenant per test and
 * custom roles only.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleDeleteConcurrencyIT {

  private static final int ATTEMPTS = 50;

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  /** RC-36.1: never an active row on a deleted role (non-admin-defining target, no set lock). */
  @Test
  void should_neverLeaveAnActiveRowOnADeletedRole_when_assignRacesDeleteFiftyTimes()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser(tenantId);
    // user:role:assign and role:write through a custom role; the target roles below carry nothing.
    Role actorRole = seedRole(tenantId, "ACTOR");
    attach(actorRole, RbacSeededPermissionIds.USER_ROLE_ASSIGN);
    attach(actorRole, RbacSeededPermissionIds.ROLE_WRITE);
    assignDirect(actorUser, actorRole, tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);

    List<String> outcomes = new ArrayList<>();
    for (int i = 0; i < ATTEMPTS; i++) {
      Role target = seedRole(tenantId, "RACE");
      outcomes.add(race(actor, target, seedUser(tenantId)));
    }

    assertThat(outcomes).allMatch(o -> o.equals("ASSIGNED_THEN_409") || o.equals("DELETED_THEN_404"));
    assertThat(activeRowsOnDeletedRoles(tenantId)).isZero();
  }

  /** RC-46.2: assign versus DELETE of a holder-less admin-defining custom role, no 500 ever. */
  @Test
  void should_neverFailWithAnUnexpectedError_when_assignRacesDeleteOfAnAdminDefiningRole()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser(tenantId);
    // The actor is an administrator through ADMIN2, a role other than the ones being raced.
    Role admin2 = seedRole(tenantId, "ADMIN2");
    attachWholeCatalogue(admin2);
    assignDirect(actorUser, admin2, tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);

    List<String> outcomes = new ArrayList<>();
    for (int i = 0; i < ATTEMPTS; i++) {
      Role target = seedRole(tenantId, "ADMIN-RACE");
      attachWholeCatalogue(target);
      outcomes.add(race(actor, target, seedUser(tenantId)));
    }

    assertThat(outcomes).allMatch(o -> o.equals("ASSIGNED_THEN_409") || o.equals("DELETED_THEN_404"));
    assertThat(activeRowsOnDeletedRoles(tenantId)).isZero();
  }

  /**
   * One race: assign and delete released together by a barrier. Any exception other than the four
   * expected ones propagates out of {@code future.get()} and fails the test (that is how a 500-class
   * deadlock would surface).
   */
  private String race(RoleChangeActor actor, Role target, User targetUser) throws Exception {
    CyclicBarrier barrier = new CyclicBarrier(2);
    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      Future<String> assign =
          executor.submit(
              (Callable<String>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    try {
                      roleAssignmentService.assign(
                          actor, targetUser.getId(), target.getId(), RequestContext.UNKNOWN);
                      return "ASSIGNED";
                    } catch (ResourceNotFoundException e) {
                      return "ASSIGN_404";
                    }
                  });
      Future<String> delete =
          executor.submit(
              (Callable<String>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    try {
                      roleManagementService.softDeleteRole(
                          actor, target.getId(), RequestContext.UNKNOWN);
                      return "DELETED";
                    } catch (RoleHasHoldersException e) {
                      return "DELETE_409";
                    }
                  });
      String a = assign.get(30, TimeUnit.SECONDS);
      String d = delete.get(30, TimeUnit.SECONDS);
      return switch (a + "/" + d) {
        case "ASSIGNED/DELETE_409" -> "ASSIGNED_THEN_409";
        case "ASSIGN_404/DELETED" -> "DELETED_THEN_404";
        default -> "UNEXPECTED_" + a + "/" + d;
      };
    } finally {
      executor.shutdownNow();
    }
  }

  private int activeRowsOnDeletedRoles(UUID tenantId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
                + "WHERE ur.tenant_id = ? AND r.deleted_at IS NOT NULL AND ur.revoked_at IS NULL",
            Integer.class,
            toBytes(tenantId));
    return count == null ? -1 : count;
  }

  private User seedUser(UUID tenantId) {
    String email = "rdc-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private Role seedRole(UUID tenantId, String tag) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RDC-" + tag + "-" + UUID.randomUUID(), null, false));
  }

  private void attach(Role role, UUID permissionId) {
    rolePermissionRepository.save(new RolePermission(role.getId(), permissionId));
  }

  private void attachWholeCatalogue(Role role) {
    List<byte[]> ids = jdbc.query("SELECT id FROM permissions", (rs, i) -> rs.getBytes(1));
    for (byte[] id : ids) {
      ByteBuffer buf = ByteBuffer.wrap(id);
      attach(role, new UUID(buf.getLong(), buf.getLong()));
    }
  }

  private void assignDirect(User user, Role role, UUID tenantId) {
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), role.getId(), tenantId, user.getId()));
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
