package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * US-015 T-010 (AC11's dedicated test; 03-design.md §5.2; 03b-threat-model.md T-E14), re-cast by
 * US-018 T-017 (04-tasks.md: "attach cases rewritten as A3 cases; detach cases kept as outcome
 * assertions; union-holder detach -> 403"). Stays entirely at the SERVICE layer ({@link
 * RoleManagementService} autowired directly, no HTTP); the HTTP 403 shape is covered by {@code
 * RolePermissionSecurityIT}.
 *
 * <p><b>What changed and why.</b> AC11 (an attach of a dangerous permission requires an active
 * {@code TENANT_ADMIN}, decided by a fresh LOCKING read, Q11) and D13 (the same for detach) are
 * retired: ADR-0021 D2 replaces the attach gate with A3, where the caller must HOLD the permission
 * being attached, and D5 replaces the detach gate with role-subset. Both read the caller's
 * holdings in a non-locking snapshot (M13), deliberately: a locking read driven by {@code
 * fk_user_roles_user} would be a new acquisition outside the set-lock region (ADR-0018 D6).
 *
 * <p><b>The concurrent-revocation case, retired and replaced.</b> The former "non-negotiable"
 * test proved that Q11 was a genuine locking read by pausing it behind an uncommitted revocation
 * and showing that it then saw the committed state. That assertion belongs to a control that no
 * longer exists, so it is retired, not inverted. The accepted residual that replaces it (RES-27, Low)
 * is pinned by {@link
 * #should_attachOnTheSnapshotWithoutBlocking_when_theCallersAssignmentIsRevokedByAnUncommittedTransaction_RES27()}:
 * the attach does not block on the revoker's lock (so A3 adds no lock acquisition), and it decides
 * from the snapshot. The window is the transaction's first consistent read to the M13 read, and it
 * is bounded by the milliseconds between them on this path, which takes no lock.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleManagementAdminGateIT {

  private static final UUID ROLE_WRITE_PERMISSION_ID = RbacSeededPermissionIds.ROLE_WRITE;
  private static final UUID AUDIT_READ_PERMISSION_ID = RbacSeededPermissionIds.AUDIT_READ;
  private static final UUID USER_READ_PERMISSION_ID = RbacSeededPermissionIds.USER_READ;

  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private PlatformTransactionManager transactionManager;

  private ExecutorService executor;

  @AfterEach
  void shutdownExecutor() {
    if (executor != null) {
      executor.shutdownNow();
    }
  }

  // ── Attach: A3 cases ─────────────────────────────────────────────────────────────────────

  /** An administrator (the whole catalogue) holds {@code role:write}, so A3 lets them attach it. */
  @Test
  void should_attachSucceed_when_callerHoldsThePermissionThroughAnAdministratorRole() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedNamedRole(tenantId, "TENANT_ADMIN", "positive-admin-role");
    grantWholeCatalogue(adminRole.getId());
    UUID adminUserId = seedUser("positive-admin", tenantId).getId();
    seedActiveAssignment(tenantId, adminRole.getId(), adminUserId, adminUserId);
    RoleChangeActor actor = new RoleChangeActor(adminUserId, tenantId);
    Role targetRole = seedRole("positive-target", tenantId);

    PermissionView attached =
        roleManagementService.attachPermission(
            actor, targetRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext());

    assertThat(attached.name()).isEqualTo("role:write");
    assertThat(rolePermissionCount(targetRole.getId(), ROLE_WRITE_PERMISSION_ID)).isEqualTo(1);
  }

  /**
   * Row 11, the intended loosening: the name-based AC11 gate is gone, so a {@code role:write}
   * holder who is NOT an administrator may attach {@code role:write} itself (they hold it, so they
   * could have granted it). What bounds an attach now is holdings, for every permission alike.
   */
  @Test
  void should_attachRoleWrite_when_aNonAdministratorHoldsRoleWrite() {
    UUID tenantId = uuidGenerator.newId();
    Role callerRole = seedRole("loosened-caller-role", tenantId);
    grantPermission(callerRole.getId(), ROLE_WRITE_PERMISSION_ID);
    UUID callerUserId = seedUser("loosened-caller", tenantId).getId();
    seedActiveAssignment(tenantId, callerRole.getId(), callerUserId, callerUserId);
    RoleChangeActor actor = new RoleChangeActor(callerUserId, tenantId);
    Role targetRole = seedRole("loosened-target", tenantId);

    roleManagementService.attachPermission(
        actor, targetRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext());

    assertThat(rolePermissionCount(targetRole.getId(), ROLE_WRITE_PERMISSION_ID)).isEqualTo(1);
  }

  /**
   * A3 on a caller who is NOT an administrator and does not hold the permission: 403
   * GRANT_EXCEEDS_CALLER and no row. (Replaces {@code
   * should_throwNotTenantAdmin_when_callerHasNoActiveTenantAdminAssignment}; the decision is now
   * about holdings, not the name {@code TENANT_ADMIN}.)
   */
  @Test
  void should_throwGrantExceedsCaller_when_callerDoesNotHoldRoleWriteToAttach() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedNamedRole(tenantId, "TENANT_ADMIN", "negative-admin-role");
    grantWholeCatalogue(adminRole.getId());
    // The tenant's administrator role genuinely exists and is held -- by SOMEONE ELSE.
    UUID someoneElseId = seedUser("negative-someone-else", tenantId).getId();
    seedActiveAssignment(tenantId, adminRole.getId(), someoneElseId, someoneElseId);
    // The caller holds the endpoint permission only through a role that carries role:write ... and
    // user:read, but not the permission they try to attach.
    Role callerRole = seedRole("negative-caller-role", tenantId);
    grantPermission(callerRole.getId(), ROLE_WRITE_PERMISSION_ID);
    UUID callerUserId = seedUser("negative-caller", tenantId).getId();
    seedActiveAssignment(tenantId, callerRole.getId(), callerUserId, callerUserId);
    RoleChangeActor actor = new RoleChangeActor(callerUserId, tenantId);
    Role targetRole = seedRole("negative-target", tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.attachPermission(
                    actor, targetRole.getId(), USER_READ_PERMISSION_ID, requestContext()))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    assertThat(rolePermissionCount(targetRole.getId(), USER_READ_PERMISSION_ID))
        .as("a denied attach must never leave a role_permissions row")
        .isZero();
  }

  /**
   * The non-dangerous attach gap A3 closes: {@code audit:read} never reached AC11, so before A3 a
   * {@code role:write} holder could attach it without holding it.
   */
  @Test
  void should_throwGrantExceedsCaller_when_roleWriteHolderWithoutAuditReadAttachesAuditRead() {
    UUID tenantId = uuidGenerator.newId();
    Role callerRole = seedRole("a3-caller-role", tenantId);
    grantPermission(callerRole.getId(), ROLE_WRITE_PERMISSION_ID);
    UUID callerUserId = seedUser("a3-caller", tenantId).getId();
    seedActiveAssignment(tenantId, callerRole.getId(), callerUserId, callerUserId);
    RoleChangeActor actor = new RoleChangeActor(callerUserId, tenantId);
    Role targetRole = seedRole("a3-target", tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.attachPermission(
                    actor, targetRole.getId(), AUDIT_READ_PERMISSION_ID, requestContext()))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> {
              assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER);
              assertThat(e.getRequiredPermission()).isEqualTo("role:write");
            });

    assertThat(rolePermissionCount(targetRole.getId(), AUDIT_READ_PERMISSION_ID))
        .as("a denied attach must never leave a role_permissions row")
        .isZero();
  }

  // ── Detach: role-subset outcomes (rows 12 and 19) ────────────────────────────────────────

  /** The caller holds every permission of the role: detach succeeds (204 at the HTTP layer). */
  @Test
  void should_detach_when_callerHoldsEveryPermissionOfTheRole() {
    UUID tenantId = uuidGenerator.newId();
    Role callerRole = seedRole("detach-ok-caller-role", tenantId);
    grantPermission(callerRole.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(callerRole.getId(), USER_READ_PERMISSION_ID);
    UUID callerUserId = seedUser("detach-ok-caller", tenantId).getId();
    seedActiveAssignment(tenantId, callerRole.getId(), callerUserId, callerUserId);
    RoleChangeActor actor = new RoleChangeActor(callerUserId, tenantId);
    Role targetRole = seedRole("detach-ok-target", tenantId);
    grantPermission(targetRole.getId(), USER_READ_PERMISSION_ID);

    roleManagementService.detachPermission(
        actor, targetRole.getId(), USER_READ_PERMISSION_ID, requestContext());

    assertThat(rolePermissionCount(targetRole.getId(), USER_READ_PERMISSION_ID)).isZero();
  }

  /** The caller lacks one permission of the role: 403, the pairing stays (role-subset). */
  @Test
  void should_throwGrantExceedsCaller_when_callerLacksAPermissionOfTheRoleBeingDetachedFrom() {
    UUID tenantId = uuidGenerator.newId();
    Role callerRole = seedRole("detach-deny-caller-role", tenantId);
    grantPermission(callerRole.getId(), ROLE_WRITE_PERMISSION_ID);
    UUID callerUserId = seedUser("detach-deny-caller", tenantId).getId();
    seedActiveAssignment(tenantId, callerRole.getId(), callerUserId, callerUserId);
    RoleChangeActor actor = new RoleChangeActor(callerUserId, tenantId);
    Role targetRole = seedRole("detach-deny-target", tenantId);
    grantPermission(targetRole.getId(), USER_READ_PERMISSION_ID);

    assertThatThrownBy(
            () ->
                roleManagementService.detachPermission(
                    actor, targetRole.getId(), USER_READ_PERMISSION_ID, requestContext()))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    assertThat(rolePermissionCount(targetRole.getId(), USER_READ_PERMISSION_ID)).isEqualTo(1);
  }

  /**
   * Row 19 / RC-26.2 (T-E34): a UNION-holder -- the whole catalogue only across two partial roles
   * -- passes the subset comparison on a custom admin-defining role but is not an administrator,
   * so they cannot demote it: 403 and the pairing stays.
   */
  @Test
  void should_throwGrantExceedsCaller_when_unionHolderDetachesFromACustomAdminDefiningRole() {
    UUID tenantId = uuidGenerator.newId();
    Role customAdminRole = seedRole("union-custom-admin", tenantId);
    grantWholeCatalogue(customAdminRole.getId());
    Role halfA = seedRole("union-half-a", tenantId);
    Role halfB = seedRole("union-half-b", tenantId);
    grantCatalogueHalf(halfA.getId(), 0);
    grantCatalogueHalf(halfB.getId(), 1);
    UUID unionHolderId = seedUser("union-holder", tenantId).getId();
    seedActiveAssignment(tenantId, halfA.getId(), unionHolderId, unionHolderId);
    seedActiveAssignment(tenantId, halfB.getId(), unionHolderId, unionHolderId);
    RoleChangeActor actor = new RoleChangeActor(unionHolderId, tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.detachPermission(
                    actor, customAdminRole.getId(), USER_READ_PERMISSION_ID, requestContext()))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    assertThat(rolePermissionCount(customAdminRole.getId(), USER_READ_PERMISSION_ID)).isEqualTo(1);
  }

  /**
   * RC-26.2: an administrator whose ONLY admin-defining role is the one being detached from may
   * not detach: no single detach removes the administrator status the caller relies on.
   */
  @Test
  void should_throwGrantExceedsCaller_when_theCallersOnlyAdminDefiningRoleIsTheOneBeingDetached() {
    UUID tenantId = uuidGenerator.newId();
    Role customAdminRole = seedRole("only-custom-admin", tenantId);
    grantWholeCatalogue(customAdminRole.getId());
    UUID adminId = seedUser("only-custom-admin-holder", tenantId).getId();
    seedActiveAssignment(tenantId, customAdminRole.getId(), adminId, adminId);
    RoleChangeActor actor = new RoleChangeActor(adminId, tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.detachPermission(
                    actor, customAdminRole.getId(), USER_READ_PERMISSION_ID, requestContext()))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    assertThat(rolePermissionCount(customAdminRole.getId(), USER_READ_PERMISSION_ID)).isEqualTo(1);
  }

  /** An administrator through ANOTHER role may detach from a custom admin-defining role. */
  @Test
  void should_detach_when_callerIsAnAdministratorThroughAnotherRole() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedNamedRole(tenantId, "TENANT_ADMIN", "detach-other-admin");
    grantWholeCatalogue(adminRole.getId());
    Role customAdminRole = seedRole("detach-other-custom-admin", tenantId);
    grantWholeCatalogue(customAdminRole.getId());
    UUID adminId = seedUser("detach-other-admin-holder", tenantId).getId();
    seedActiveAssignment(tenantId, adminRole.getId(), adminId, adminId);
    RoleChangeActor actor = new RoleChangeActor(adminId, tenantId);

    roleManagementService.detachPermission(
        actor, customAdminRole.getId(), USER_READ_PERMISSION_ID, requestContext());

    assertThat(rolePermissionCount(customAdminRole.getId(), USER_READ_PERMISSION_ID)).isZero();
  }

  // ── RES-27: the snapshot is the accepted residual, and the attach does not block ───────────

  @Test
  void should_attachOnTheSnapshotWithoutBlocking_when_theCallersAssignmentIsRevokedByAnUncommittedTransaction_RES27()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedNamedRole(tenantId, "TENANT_ADMIN", "concurrent-admin-role");
    grantWholeCatalogue(adminRole.getId());
    UUID adminUserId = seedUser("concurrent-admin", tenantId).getId();
    UserRole assignment =
        seedActiveAssignment(tenantId, adminRole.getId(), adminUserId, adminUserId);
    RoleChangeActor actor = new RoleChangeActor(adminUserId, tenantId);
    Role targetRole = seedRole("concurrent-target", tenantId);

    CountDownLatch updateExecuted = new CountDownLatch(1);
    CountDownLatch releaseCommit = new CountDownLatch(1);
    executor = Executors.newFixedThreadPool(2);

    // T2 (revoker): opens ITS OWN transaction, executes the revoke UPDATE (acquiring InnoDB's
    // exclusive row lock synchronously), then holds the transaction open -- uncommitted -- until
    // signaled.
    Future<Integer> revokeFuture =
        executor.submit(
            () ->
                new TransactionTemplate(transactionManager)
                    .execute(
                        status -> {
                          int affected =
                              userRoleRepository.revokeById(assignment.getId(), Instant.now());
                          updateExecuted.countDown();
                          awaitUninterruptibly(releaseCommit);
                          return affected;
                        }));

    assertThat(updateExecuted.await(5, TimeUnit.SECONDS))
        .as("T2's revoke UPDATE must execute (uncommitted) within the timeout")
        .isTrue();

    // T1 (attacher): the REAL attachPermission call, started only AFTER T2's update is confirmed
    // executed. A3's M13 is a plain snapshot read, so it must NOT block on T2's exclusive lock:
    // this is the property that keeps A3 outside the lock family (ADR-0018 D6, MC-A). A bounded
    // get that throws TimeoutException would mean A3 had become a locking read.
    Future<PermissionView> attachFuture =
        executor.submit(
            () ->
                roleManagementService.attachPermission(
                    actor, targetRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext()));
    PermissionView attached = attachFuture.get(10, TimeUnit.SECONDS);

    // The residual, stated exactly (RES-27): the attach decided from the snapshot, so it succeeded
    // on authority that T2 is revoking. Accepted (Low): a milliseconds window on a path that takes
    // no lock, and both actions are audited. This assertion pins the residual so that closing or
    // widening it is a deliberate decision, not a side effect.
    assertThat(attached.name()).isEqualTo("role:write");

    releaseCommit.countDown();
    assertThat(revokeFuture.get(5, TimeUnit.SECONDS)).as("T2's revoke itself must succeed").isEqualTo(1);
    assertThat(rolePermissionCount(targetRole.getId(), ROLE_WRITE_PERMISSION_ID)).isEqualTo(1);
  }

  private static void awaitUninterruptibly(CountDownLatch latch) {
    try {
      // Bounded so a defect elsewhere in this test can't hang the whole suite forever.
      boolean released = latch.await(15, TimeUnit.SECONDS);
      if (!released) {
        throw new IllegalStateException("releaseCommit latch was never released within 15s");
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
  }

  // ── Fixtures / helpers ───────────────────────────────────────────────────────────────────

  private User seedUser(String tag, UUID tenantId) {
    String email = "rmag-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedRole(String tag, UUID tenantId) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RMAG-" + tag + "-" + UUID.randomUUID().toString().substring(0, 8), null,
            false));
  }

  /** A role with the given literal name (a case of the name no longer matters). */
  private Role seedNamedRole(UUID tenantId, String literalName, String tag) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, literalName, tag, false));
  }

  private void grantPermission(UUID roleId, UUID permissionId) {
    rolePermissionRepository.save(new RolePermission(roleId, permissionId));
  }

  /** Makes {@code roleId} admin-defining (ADR-0021 D3): attaches every catalogue permission. */
  private void grantWholeCatalogue(UUID roleId) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions",
        toBytes(roleId));
  }

  /** Attaches the catalogue permissions whose position in id order has the given parity. */
  private void grantCatalogueHalf(UUID roleId, int parity) {
    java.util.List<UUID> ids =
        jdbc.query(
            "SELECT id FROM permissions ORDER BY id",
            (rs, rowNum) -> {
              ByteBuffer buf = ByteBuffer.wrap(rs.getBytes(1));
              return new UUID(buf.getLong(), buf.getLong());
            });
    for (int i = 0; i < ids.size(); i++) {
      if (i % 2 == parity) {
        grantPermission(roleId, ids.get(i));
      }
    }
  }

  private UserRole seedActiveAssignment(UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "RoleManagementAdminGateIT");
  }

  private int rolePermissionCount(UUID roleId, UUID permissionId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM role_permissions WHERE role_id = ? AND permission_id = ?",
            Integer.class,
            toBytes(roleId),
            toBytes(permissionId));
    return count == null ? 0 : count;
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
