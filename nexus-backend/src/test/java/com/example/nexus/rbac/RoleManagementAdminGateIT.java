package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

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
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
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
 * US-015 T-010, AC11's dedicated test (03-design.md §5.2, §7.2 D8's RC-5a ArchUnit rule;
 * 03b-threat-model.md T-E14 -- "the single most important test in the entire story"). Non-
 * negotiable per {@code 04-tasks.md} T-010.
 *
 * <p>Stays entirely at the SERVICE layer ({@link RoleManagementService} autowired directly, no
 * HTTP) -- its job is proving AC11's DB-level guarantee, not re-proving the HTTP 403 shape (already
 * covered by {@code RolePermissionSecurityIT} Scenarios 9/10).
 *
 * <p><b>The concurrent-revocation case's design, and why it is a 2-thread, {@link CountDownLatch}
 * -orchestrated directed interleaving rather than the N-thread {@code CyclicBarrier} "simultaneous
 * race" pattern {@code ActiveAssignmentIT}/{@code RefreshTokenRotationIT} use elsewhere in this
 * codebase:</b> AC11's guarantee is about READ FRESHNESS under a controlled interleaving, not
 * "exactly one winner races a unique constraint". {@code
 * UserRoleAssignmentPort#hasActiveAdminAssignment} (Q11) is mandated to be a fresh, LOCKING
 * ({@code PESSIMISTIC_READ}/{@code FOR SHARE}) read specifically because a plain (non-locking)
 * read inside the same transaction would reuse the REPEATABLE-READ snapshot established by an
 * earlier read in that same transaction ({@code
 * RoleManagementService#verifyCallerIsActiveTenantAdmin}'s Q3, which runs first) and could
 * therefore MISS a revocation that commits after that snapshot was taken. Proving this requires
 * directed ordering -- pause the attach transaction's OWN locking read until a concurrent
 * revocation has genuinely executed (uncommitted) against the exact same row, confirm the locking
 * read actually BLOCKS on that uncommitted row (the mechanical, not inferred, proof that Q11 is a
 * real locking read), then release the revocation's commit and confirm the locking read then sees
 * the fresh, post-commit state. A CyclicBarrier's simultaneous start cannot express or verify this
 * ordering; only directed, latch-controlled interleaving can.
 *
 * <p>Mechanism: thread T2 opens its own {@link TransactionTemplate} transaction and executes
 * {@code JpaUserRoleRepository#revokeById} (the same targeted {@code UPDATE ... WHERE id = ? AND
 * revoked_at IS NULL} production code path uses) -- which acquires InnoDB's exclusive row lock
 * immediately, synchronously, on execution -- but does not let its transaction commit until
 * signaled. Thread T1 is the REAL {@link RoleManagementService#attachPermission} call on its own
 * thread/transaction: Q3 (role-by-name, a different table, unlocked) runs first, then Q11 attempts
 * to acquire a SHARED lock on the exact row T2 already holds EXCLUSIVELY (uncommitted) and blocks.
 * The test asserts this blocking is real (a bounded {@code Future#get} throws {@link
 * TimeoutException}), then releases T2's commit, then asserts T1's Q11 -- which reads the LATEST
 * COMMITTED row version regardless of T1's own transaction snapshot -- now correctly sees {@code
 * revoked_at IS NOT NULL} and denies the attach.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleManagementAdminGateIT {

  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");

  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
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

  // ── Positive: an active TENANT_ADMIN successfully attaches a dangerous permission ──────

  @Test
  void should_attachSucceed_when_callerIsActiveTenantAdmin() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedNamedRole(tenantId, "TENANT_ADMIN", "positive-admin-role");
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

  // ── Negative: caller holds role:write via a custom role, but no active TENANT_ADMIN ─────

  @Test
  void should_throwNotTenantAdmin_when_callerHasNoActiveTenantAdminAssignment() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedNamedRole(tenantId, "TENANT_ADMIN", "negative-admin-role");
    // The tenant's TENANT_ADMIN role genuinely exists and is held -- by SOMEONE ELSE, never the
    // caller below. This distinguishes this case from the R-10 fail-closed "no TENANT_ADMIN role
    // exists at all" branch, already covered in RolePermissionSecurityIT.
    UUID someoneElseId = seedUser("negative-someone-else", tenantId).getId();
    seedActiveAssignment(tenantId, adminRole.getId(), someoneElseId, someoneElseId);
    UUID callerUserId = seedUser("negative-caller", tenantId).getId();
    RoleChangeActor actor = new RoleChangeActor(callerUserId, tenantId);
    Role targetRole = seedRole("negative-target", tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.attachPermission(
                    actor, targetRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext()))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    assertThat(rolePermissionCount(targetRole.getId(), ROLE_WRITE_PERMISSION_ID))
        .as("a denied attach must never leave a role_permissions row")
        .isZero();
  }

  // ── The non-negotiable case ──────────────────────────────────────────────────────────────

  @Test
  void should_denyAttach_when_callersAdminAssignmentIsRevokedInAConcurrentTransactionBetweenQ3AndQ11()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedNamedRole(tenantId, "TENANT_ADMIN", "concurrent-admin-role");
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
    // executed -- Q3 runs unlocked, then Q11 must block on T2's exclusive lock.
    Future<PermissionView> attachFuture =
        executor.submit(
            () ->
                roleManagementService.attachPermission(
                    actor, targetRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext()));

    // Mechanical proof that Q11 is a genuine LOCKING read: T1 must still be blocked a short,
    // bounded time after T2's update executed -- if this does NOT throw TimeoutException, Q11 is
    // not actually taking a lock on the row.
    assertThatThrownBy(() -> attachFuture.get(2, TimeUnit.SECONDS))
        .as("T1's Q11 locking read must be genuinely blocked by T2's uncommitted exclusive lock"
            + " on the same user_roles row")
        .isInstanceOf(TimeoutException.class);

    // Release T2 -> it commits the revocation, releasing the lock.
    releaseCommit.countDown();
    Integer revokeAffectedRows = revokeFuture.get(5, TimeUnit.SECONDS);
    assertThat(revokeAffectedRows).as("T2's revoke itself must succeed").isEqualTo(1);

    // T1 unblocks. PESSIMISTIC_READ/FOR SHARE reads the LATEST COMMITTED row version -- it does
    // NOT honor T1's own REPEATABLE-READ snapshot (established by Q3's earlier read) -- so Q11
    // must now see revoked_at IS NOT NULL and deny the attach. This is the exact property that
    // distinguishes the mandated locking read from the forbidden non-locking shortcut (T-E14).
    try {
      attachFuture.get(5, TimeUnit.SECONDS);
      fail("expected attachPermission to be denied once T2's revocation committed");
    } catch (ExecutionException e) {
      assertThat(e.getCause())
          .as("after T2 commits, T1's attach must fail with NOT_TENANT_ADMIN, never succeed on a"
              + " stale pre-revocation snapshot")
          .isInstanceOf(InsufficientPermissionException.class)
          .satisfies(
              cause ->
                  assertThat(((InsufficientPermissionException) cause).getReason())
                      .isEqualTo(DenialReason.NOT_TENANT_ADMIN));
    }

    assertThat(rolePermissionCount(targetRole.getId(), ROLE_WRITE_PERMISSION_ID))
        .as("the attach must have been genuinely rejected -- no role_permissions row, not a"
            + " stale-snapshot false positive")
        .isZero();
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
        new Role(uuidGenerator.newId(), tenantId, "RMAG-" + tag + "-" + UUID.randomUUID(), null,
            false));
  }

  /** Overload for the literal role name {@code "TENANT_ADMIN"} AC11 matches on. */
  private Role seedNamedRole(UUID tenantId, String literalName, String tag) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, literalName, tag, false));
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
