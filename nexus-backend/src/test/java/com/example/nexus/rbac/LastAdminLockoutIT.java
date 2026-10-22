package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.AttachProvenanceConflictException;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleClassificationChangedException;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionSetVersion;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaPermissionCatalogueRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.MySQLContainer;

/**
 * US-012 T-018 (04-tasks.md; 03-design.md §5.2 M1/§3.2; 03b-threat-model.md T-D3): the AC5
 * last-admin lockout guard in {@link RoleAssignmentService#revoke}, permanently codifying the
 * threat model's empirical finding that M1's locking read confines the {@code FOR UPDATE} lock
 * scope to one tenant's {@code TENANT_ADMIN} rows (driven by the {@code fk_user_roles_role} FK
 * index, never a full table scan) and that revocations of the same tenant's admin assignments
 * therefore serialize correctly under concurrency.
 *
 * <p><strong>Concurrency-harness note</strong> (mirrors the discrepancy flagged in {@link
 * ActiveAssignmentIT}'s own Javadoc): {@code SecureEventServiceConcurrencyTest} is a single-
 * threaded Mockito unit test with no {@code ExecutorService}/{@code CyclicBarrier} and no
 * Testcontainers — it is not a real concurrency harness. {@link #should_completeWithoutDeadlock_when_eightConcurrentRevokesRaceWithAnActiveAdminCaller()}
 * (Harness A) below instead mirrors {@code RefreshTokenRotationIT#concurrent_rotation_single_winner} /
 * {@code ActiveAssignmentIT#should_allowExactlyOneWinner_when_eightConcurrentActiveInsertsRace}:
 * an 8-thread pool, a {@link CyclicBarrier}, and {@link Future} collection against a live
 * Testcontainers MySQL instance — an actual multi-thread race, not a sequential simulation.
 * {@link #should_blockEveryThread_when_eightConcurrentSelfRevokesRaceForTheLastAdmin()} (Harness
 * B) and {@link #should_completeWithoutDeadlock_when_mixedPrivilegedRoleChangesRaceAcrossBothVerbs()}
 * (Harness C, US-016 T-015 / 03-design.md §7.4) round out the same shape against two other
 * populations — see each harness's own Javadoc for what it proves.
 *
 * <p><strong>Bootstrap-tenant fixture choice, deliberate:</strong> the first two scenarios
 * reuse the migration-seeded bootstrap tenant ({@code 00000000-0000-7000-8000-000000000001})
 * and its real seeded {@code TENANT_ADMIN} role ({@code 019f6839-1810-…-00000000000a}) —
 * on purpose, per 04-tasks.md T-018's own reasoning: a hardcoded-bootstrap-role-id
 * implementation bug would pass both of these scenarios by accident, since they happen to run
 * in that exact tenant. {@link #should_blockRevocation_when_nonBootstrapTenantHasOnlyOneActiveAdmin()}
 * is the scenario that actually catches that class of bug, using a freshly generated tenant and
 * a freshly created {@code TENANT_ADMIN}-named role that the resolve-by-{@code (tenant, name)}
 * path must reach correctly. Because the bootstrap tenant's admin-role row count is shared,
 * mutable state across this whole IT suite, {@link #cleanUpBootstrapTenantFixtures()} force-
 * revokes (via raw JDBC, bypassing the guard under test) every row this class creates there, so
 * each bootstrap-tenant test starts from a verified zero baseline ({@link
 * #assertBootstrapTenantAdminBaselineIsZero()}) regardless of execution order.
 */
// A-5 (04-tasks.md T-015): raised for the whole class so harness C's denied non-admin thread
// (and any future reshaping of it) can never be silently suppressed by the default
// max-denials=5 transitioning this actor into the throttled state mid-run — which would let
// harness C pass for the wrong reason (a pre-throttled 403 short-circuits BEFORE M11's lock is
// even acquired, defeating the X-lock-then-403 path harness C exists to exercise). Chosen over
// @DynamicPropertySource: this is a plain @Value, not an @ConditionalOnProperty bean, so the
// Spring Boot 4 DynamicPropertyRegistrar-runs-after-component-scan gotcha (see
// TestcontainersConfiguration's own comment) does not apply either way, but
// @SpringBootTest(properties=...) is the already-established pattern in this codebase for this
// exact kind of override (RateLimitIT, LoginLockoutIT, RegisterAtomicityIT, et al.) and resolves
// before context refresh, sidestepping the question entirely.
// Harness C runs 11 truly concurrent threads (CyclicBarrier-released together), each opening its
// own JPA transaction/connection; Spring Boot's Hikari default (10) is one short of that, so one
// thread is guaranteed to queue for a pool slot -- a connection-pool artifact, not a deadlock,
// that was eating into harness C's awaitTermination budget. Raised past 11 with headroom for the
// scheduled AuthEventRetryBuffer.drain job sharing the same pool. US-019 T-019 adds two B8
// threads (13 in all), each briefly holding a second connection for its after-commit holder read,
// so the pool is raised again.
@SpringBootTest(
    properties = {
      "nexus.rbac.denial-throttle.max-denials=100",
      "spring.datasource.hikari.maximum-pool-size=20"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class LastAdminLockoutIT {

  private static final UUID BOOTSTRAP_TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID BOOTSTRAP_TENANT_ADMIN_ROLE_ID =
      UUID.fromString("019f6839-1810-7000-8000-00000000000a");

  // Seeded literals — V5__rbac_schema.sql header comment (same constants used elsewhere in this
  // package, e.g. RoleRevocationSymmetryIT/RoleAssignmentEscalationIT) — used by Harness C only.
  private static final UUID USER_WRITE_PERMISSION_ID = RbacSeededPermissionIds.USER_WRITE;
  private static final UUID ROLE_WRITE_PERMISSION_ID = RbacSeededPermissionIds.ROLE_WRITE;
  // RC-56.7 (US-019 T-020) only.
  private static final UUID AUDIT_READ_ID = RbacSeededPermissionIds.AUDIT_READ;

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaPermissionCatalogueRepository permissionCatalogueRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private MySQLContainer<?> mysqlContainer;
  @Autowired private MeterRegistry meterRegistry;
  @Autowired private PlatformTransactionManager transactionManager;

  private static final String TIMER_LOCK_HOLD = "nexus.rbac.privileged_revoke_lock_hold";

  /** Rows created against the shared bootstrap-tenant admin role, force-revoked in {@link #cleanUpBootstrapTenantFixtures()}. */
  private final List<UUID> bootstrapAdminAssignmentIdsToClean = new ArrayList<>();

  @AfterEach
  void cleanUpBootstrapTenantFixtures() {
    for (UUID id : bootstrapAdminAssignmentIdsToClean) {
      forceRevokeDirectly(id);
    }
    bootstrapAdminAssignmentIdsToClean.clear();
  }

  // ── Scenario 1: last admin in the tenant, self-revocation ──────────────────────────────

  @Test
  void should_blockRevocationAndKeepRowActive_when_revokingTenantsOnlyActiveAdminAssignment() {
    assertBootstrapTenantAdminBaselineIsZero();

    User admin = seedUser(BOOTSTRAP_TENANT_ID, "solo");
    UserRole assignment = seedActiveAdminAssignment(BOOTSTRAP_TENANT_ID,
        BOOTSTRAP_TENANT_ADMIN_ROLE_ID, admin.getId(), admin.getId());
    bootstrapAdminAssignmentIdsToClean.add(assignment.getId());

    RoleChangeActor actor = new RoleChangeActor(admin.getId(), BOOTSTRAP_TENANT_ID);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, admin.getId(), BOOTSTRAP_TENANT_ADMIN_ROLE_ID, requestContext()))
        .isInstanceOf(LastAdminRoleException.class)
        .extracting(e -> ((LastAdminRoleException) e).code())
        .isEqualTo("RBAC_002");

    assertThat(isActive(assignment.getId()))
        .as("the tenant's only active TENANT_ADMIN assignment must remain active after a"
            + " blocked revoke — the row must never be silently touched on a 409 path")
        .isTrue();
  }

  // ── Scenario 2 (US-016 T-015, rewritten 409→403): a non-admin caller, not self-revocation ──

  /**
   * US-016 §6.4: after this story, the AC5 `size() &lt;= 1` lockout branch is reachable ONLY for
   * self-revocation — to reach it at all, the caller must already have passed the privilege gate
   * (D1: gate before AC5), which requires the caller to hold an active {@code TENANT_ADMIN}
   * assignment themselves. This fixture's {@code differentCaller} genuinely holds none, so
   * against a real database (unlike the mock-constructible state
   * {@code RoleAssignmentServiceTest#should_throwLastAdminRoleException_..._differentAdminRevoking_syntheticStateSeeDesign64}
   * keeps as a guard-shape proof) this now fails the gate itself and never reaches AC5 at all —
   * hence 403 {@code NOT_TENANT_ADMIN}, not 409 {@code RBAC_002}.
   */
  @Test
  void should_return403_when_nonAdminAttemptsToRevokeTheTenantsLastAdmin() {
    assertBootstrapTenantAdminBaselineIsZero();

    User targetAdmin = seedUser(BOOTSTRAP_TENANT_ID, "target");
    // Deliberately NOT itself an active TENANT_ADMIN -- per §6.4 this caller can never reach the
    // AC5 branch at all now; the gate denies first.
    User differentCaller = seedUser(BOOTSTRAP_TENANT_ID, "caller");
    UserRole assignment = seedActiveAdminAssignment(BOOTSTRAP_TENANT_ID,
        BOOTSTRAP_TENANT_ADMIN_ROLE_ID, targetAdmin.getId(), targetAdmin.getId());
    bootstrapAdminAssignmentIdsToClean.add(assignment.getId());

    RoleChangeActor actor = new RoleChangeActor(differentCaller.getId(), BOOTSTRAP_TENANT_ID);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, targetAdmin.getId(), BOOTSTRAP_TENANT_ADMIN_ROLE_ID, requestContext()))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    assertThat(isActive(assignment.getId()))
        .as("a revocation attempted by someone other than the target admin must be blocked"
            + " identically to self-revocation — still the load-bearing invariant even though"
            + " the guard that now fires first is the privilege gate, not AC5 (§6.4)")
        .isTrue();
  }

  // ── Harness A (US-016 T-015, 03-design.md §7.4): lock order / no deadlock ──────────────

  /**
   * Seeds a fresh tenant with THREE active {@code TENANT_ADMIN} assignments: {@code caller}
   * (the actor, and — the fix this story requires — now genuinely an active admin himself, so
   * the privilege gate passes) plus {@code admin1}/{@code admin2}. 8 threads race to revoke
   * either {@code admin1} or {@code admin2} (never the caller's own row), synchronized via a
   * {@link CyclicBarrier} so they fire as close to simultaneously as possible.
   *
   * <p>Because M1's lock ({@code SELECT … WHERE role_id = :roleId AND tenant_id = :tenantId …
   * FOR UPDATE}) covers every admin row in the tenant regardless of which specific one a caller
   * targets, all 8 attempts fully serialize against each other (D2, §7.2 step 2). Whichever
   * thread's M1 read executes first for a given target sees all three rows still active (size
   * 3, never {@code <= 1}), passes AC5, and revokes its own target. Every subsequent thread
   * targeting the SAME row it already lost either fails at {@code findAssignmentRefOrThrow}
   * (the row is no longer active) or loses the M6 affected-row race at the final {@code
   * UPDATE} — both surface identically as {@link ResourceNotFoundException} (404, "already
   * revoked", Res. 7's contract). AC5 itself never fires here: after both {@code admin1} and
   * {@code admin2} are gone, the caller remains the tenant's sole admin, but nobody targets the
   * caller's own row, so the {@code size() <= 1 && contains(ref.id())} branch is never reached.
   * A raw {@code DataAccessException} or any other exception type is not a legitimate outcome
   * and fails the test loudly. Proves D2 directly, 8-way: this is the ordering that deadlocks
   * under the rejected alternative (§7.3 option (b)).
   */
  @Test
  void should_completeWithoutDeadlock_when_eightConcurrentRevokesRaceWithAnActiveAdminCaller()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "conc");
    User caller = seedUser(tenantId, "conc-caller");
    User admin1 = seedUser(tenantId, "conc-admin1");
    User admin2 = seedUser(tenantId, "conc-admin2");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), caller.getId(), caller.getId());
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin1.getId(), caller.getId());
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin2.getId(), caller.getId());

    RoleChangeActor actor = new RoleChangeActor(caller.getId(), tenantId);
    // Baseline, not a raw post-run assertion: this timer carries no tenantId tag (unbounded,
    // 03-design.md §7.5), so its "revoked"/"lockout" series accumulate across every test in this
    // shared-Spring-context class, not just this one -- the delta is what this harness proves.
    long revokedTimerBaseline = timerCount(TIMER_LOCK_HOLD, "revoked");

    // MC-6 (RC-9.2, 03-design.md §7.2 step 2 / §6.4): both D2's serialization claim and §6.4's
    // "structurally unreachable" proof depend on M1's next-key/gap lock blocking concurrent
    // INSERTs into the role_id = adminRoleId range, which requires REPEATABLE READ -- MySQL's
    // default, but nothing in the codebase pins it. Kept inline in this test body (not
    // @BeforeAll) so a future refactor cannot silently drop it. Asserted here only (not
    // duplicated into Harness B/C) -- this is the direct successor of the concurrency test that
    // originally carried this assertion, and T-014 already discharged "asserted at least once".
    assertThat(jdbc.queryForObject("SELECT @@transaction_isolation", String.class))
        .as("this concurrency harness's serialization claim requires REPEATABLE READ")
        .isEqualTo("REPEATABLE-READ");

    int threadCount = 8;
    CyclicBarrier barrier = new CyclicBarrier(threadCount);
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<String>> futures = new ArrayList<>();

    for (int i = 0; i < threadCount; i++) {
      UUID target = (i % 2 == 0) ? admin1.getId() : admin2.getId();
      futures.add(
          executor.submit(
              (Callable<String>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    try {
                      roleAssignmentService.revoke(
                          actor, target, adminRole.getId(), requestContext());
                      return "SUCCESS";
                    } catch (LastAdminRoleException e) {
                      return "LOCKOUT";
                    } catch (ResourceNotFoundException e) {
                      return "LOST_RACE";
                    }
                  }));
    }

    executor.shutdown();
    boolean terminated = executor.awaitTermination(15, TimeUnit.SECONDS);
    assertThat(terminated).as("all 8 threads must complete within the timeout").isTrue();

    int successCount = 0;
    int lockoutCount = 0;
    int lostRaceCount = 0;
    for (Future<String> future : futures) {
      // future.get() rethrows for anything NOT already caught above -- an unexpected exception
      // type (e.g. a raw DataAccessException) fails this loop loudly rather than being silently
      // absorbed.
      String outcome = future.get();
      switch (outcome) {
        case "SUCCESS" -> successCount++;
        case "LOCKOUT" -> lockoutCount++;
        case "LOST_RACE" -> lostRaceCount++;
        default -> throw new IllegalStateException("Unexpected outcome: " + outcome);
      }
    }

    assertThat(successCount).as("exactly one thread wins per target (2 targets)").isEqualTo(2);
    assertThat(lockoutCount)
        .as("with an active-admin caller in the set, AC5 must never fire on this population")
        .isZero();
    assertThat(lostRaceCount)
        .as("the other 3 threads per target must lose the race, never error")
        .isEqualTo(6);
    assertThat(successCount + lockoutCount + lostRaceCount)
        .as("every thread must resolve to one of the three safe outcomes")
        .isEqualTo(threadCount);
    assertThat(countActiveAdminAssignments(tenantId, adminRole.getId()))
        .as("the tenant must retain exactly the caller as its one remaining active admin")
        .isEqualTo(1);
    // RC-9.5 / D18 (03-design.md §7.5): the composed lock-hold timer's "revoked" outcome must
    // have recorded one sample per real winner under genuine concurrent contention on the SAME
    // admin-row set -- not merely the count/tag-shape a single-threaded unit test with a mocked
    // Timer.Sample can prove. No duration threshold is asserted (that would be timing-dependent
    // and flaky); only that the composed timer actually participated exactly as many times as
    // there were successful revokes, measured as a delta against this test's own baseline.
    assertThat(timerCount(TIMER_LOCK_HOLD, "revoked") - revokedTimerBaseline)
        .as("D18's composed timer must record exactly one 'revoked' sample per winning thread")
        .isEqualTo((long) successCount);
  }

  // ── Harness B (US-016 T-015, 03-design.md §7.4): AC5 in its now-only-reachable shape ────

  /**
   * Seeds a fresh tenant with exactly ONE active {@code TENANT_ADMIN} assignment, held by the
   * actor, then launches 8 threads that all attempt to revoke that SAME row (self-revocation),
   * synchronized via a {@link CyclicBarrier}.
   *
   * <p>Unlike Harness A, this is fully deterministic rather than merely probable: every
   * thread's M1 read locks the same single-row set {@code {caller's own assignment}} — size 1,
   * containing {@code ref.id()} — so the {@code size() <= 1 && contains(ref.id())} branch of
   * AC5 fires for every single thread, regardless of acquisition order. No thread can ever
   * reach the final {@code UPDATE}, so {@code LOST_RACE}/{@code SUCCESS} are structurally
   * impossible outcomes here. Per §6.4's proof, this self-revocation population is the ONLY
   * population left reachable for the AC5 branch after this story's privilege gate lands — this
   * harness is the mechanical proof that the guard of last resort still fires correctly under a
   * real 8-way race in that population, not merely in the single-threaded scenario 1.
   */
  @Test
  void should_blockEveryThread_when_eightConcurrentSelfRevokesRaceForTheLastAdmin()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "selfconc");
    User soleAdmin = seedUser(tenantId, "selfconc-admin");
    UserRole assignment =
        seedActiveAdminAssignment(tenantId, adminRole.getId(), soleAdmin.getId(), soleAdmin.getId());

    RoleChangeActor actor = new RoleChangeActor(soleAdmin.getId(), tenantId);
    // Baseline delta, same rationale as Harness A: this timer's tags are shared class-wide.
    long lockoutTimerBaseline = timerCount(TIMER_LOCK_HOLD, "lockout");

    int threadCount = 8;
    CyclicBarrier barrier = new CyclicBarrier(threadCount);
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<String>> futures = new ArrayList<>();

    for (int i = 0; i < threadCount; i++) {
      futures.add(
          executor.submit(
              (Callable<String>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    try {
                      roleAssignmentService.revoke(
                          actor, soleAdmin.getId(), adminRole.getId(), requestContext());
                      return "SUCCESS";
                    } catch (LastAdminRoleException e) {
                      return "LOCKOUT";
                    }
                  }));
    }

    executor.shutdown();
    boolean terminated = executor.awaitTermination(15, TimeUnit.SECONDS);
    assertThat(terminated).as("all 8 threads must complete within the timeout").isTrue();

    int successCount = 0;
    int lockoutCount = 0;
    for (Future<String> future : futures) {
      // future.get() rethrows for anything NOT already caught above -- any unexpected exception
      // type fails this loop loudly rather than being silently absorbed.
      String outcome = future.get();
      switch (outcome) {
        case "SUCCESS" -> successCount++;
        case "LOCKOUT" -> lockoutCount++;
        default -> throw new IllegalStateException("Unexpected outcome: " + outcome);
      }
    }

    assertThat(lockoutCount).as("every self-revoke of the tenant's last admin must be blocked")
        .isEqualTo(threadCount);
    assertThat(successCount).as("no thread may ever succeed against the tenant's last admin")
        .isZero();
    assertThat(isActive(assignment.getId()))
        .as("the tenant's only active admin assignment must remain active after the race")
        .isTrue();
    // RC-9.5 / D18: the composed timer's "lockout" outcome under real 8-way contention on the
    // SAME single-row set -- delta against baseline, count only, no duration threshold (would be
    // timing-dependent/flaky).
    assertThat(timerCount(TIMER_LOCK_HOLD, "lockout") - lockoutTimerBaseline)
        .as("D18's composed timer must record exactly one 'lockout' sample per blocked thread")
        .isEqualTo((long) lockoutCount);
  }

  // ── Harness C (US-016 T-015, RC-9.3; RES-10 closed by US-017 D7, 03-design.md §7.3/§7.4) ──

  /**
   * Seeds a fresh tenant with THREE active {@code TENANT_ADMIN} holders ({@code admin1} —
   * acting as the sole privileged actor for every non-denied thread below, {@code admin2},
   * {@code admin3}), one custom admin-defining role ({@code CUSTOM-ADMIN-DEFINING}, carrying the
   * whole permission catalogue, so it is in the set lock exactly as {@code TENANT_ADMIN} is) with
   * TWO existing holders, one non-admin {@code user:write}-only principal, and one benign,
   * permission-less role ({@code BENIGN}) with one existing holder. 11 threads fire
   * simultaneously via a {@link CyclicBarrier} split across BOTH verbs, both admin-defining
   * roles, and the admin-defining×benign case D7 newly makes relevant. <b>US-018 M3 (T-016):</b>
   * re-scoped from the name-or-dangerous-permission population to the admin-defining population
   * (ADR-0021 D6); the lock set is the tenant's admin-defining role ids plus the target, the
   * thread shapes and the expected outcomes are unchanged:
   *
   * <ol>
   *   <li>2× {@code revoke(TENANT_ADMIN)} by {@code admin1}, targeting {@code admin2} and
   *       {@code admin3} respectively — each is the only thread targeting that row, so both
   *       succeed deterministically (three admins in the set, so AC5's {@code size() <= 1}
   *       branch never fires for either).
   *   <li>1× {@code assign(TENANT_ADMIN)} by {@code admin1}, targeting a fresh, standalone user
   *       no other thread contends for — succeeds deterministically. This is RES-10's restored
   *       thread (see this method's Javadoc): it now races threads 1-2 legitimately through
   *       M11's shared union lock (D7) instead of the pre-D7 deadlock cycle.
   *   <li>2× {@code revoke(CUSTOM-ADMIN-DEFINING)} by {@code admin1}, targeting its two distinct
   *       existing holders — the role is admin-defining by its permissions alone (its name is
   *       irrelevant), so M11's lock set covers it as it covers {@code TENANT_ADMIN}; both succeed
   *       deterministically.
   *   <li>2× {@code assign(CUSTOM-ADMIN-DEFINING)} by {@code admin1}, both targeting the SAME fresh
   *       user — a duplicate-insert race (mirrors {@code ActiveAssignmentIT}'s own 8-way version
   *       of this pattern, scaled to 2): exactly one succeeds, the other gets {@link
   *       DuplicateRoleAssignmentException} (409 {@code RBAC_004}), never a raw {@code
   *       DataIntegrityViolationException} — {@code JpaUserRoleAssignmentAdapter#assign}
   *       synchronously flushes and translates it in the same try/catch.
   *   <li>1× {@code assign(CUSTOM-ADMIN-DEFINING)} by {@code admin1} against a THIRD, standalone
   *       target no other thread contends for — succeeds deterministically, adding a second
   *       independent concurrent {@code assign()} alongside the duplicate-race pair.
   *   <li>1× {@code revoke(TENANT_ADMIN)} by the non-admin {@code user:write} principal,
   *       targeting {@code admin1}'s OWN assignment (deliberately the one row no other thread
   *       ever touches, so this thread cannot race into a spurious 404) — denied with {@link
   *       InsufficientPermissionException} (403 {@code NOT_TENANT_ADMIN}). Because {@code
   *       TENANT_ADMIN} is admin-defining, this thread's transaction acquires M11's X lock over
   *       the WHOLE admin-defining role range BEFORE the administrator requirement denies it (the
   *       requirement is decided from M11's own rows, ADR-0021 D2/D5) — this is deliberately the
   *       X-lock-then-403 path T-D11 names, run concurrently with every legitimate
   *       X-lock-then-success thread above, including the restored {@code assign(TENANT_ADMIN)}
   *       thread.
   *   <li>1× {@code assign(BENIGN)} by {@code admin1}, targeting {@code dangerousHolder1} — the
   *       SAME row a {@code revoke(CUSTOM-ADMIN-DEFINING)} thread above concurrently touches.
   *       {@code BENIGN} carries no permission and is not admin-defining, so it takes no M11
   *       lock and sits outside every set lock — this is the privileged×benign
   *       case RC-20.6 requires: proving no cycle forms through {@code fk_user_roles_user} even
   *       though both transactions touch the same user row.
   *   <li>1× {@code revoke(BENIGN)} by {@code admin1}, targeting {@code admin3} — the SAME row a
   *       {@code revoke(TENANT_ADMIN)} thread above concurrently touches. Same purpose as the
   *       previous item, exercised on the revoke side.
   *   <li>US-019 T-019: 1× B8 demotion by {@code admin1} of a third admin-defining role ({@code
   *       B8-DEMOTE}, one holder): set lock, then role row (RC-46), then its current reads. {@code
   *       admin1} stays an administrator through {@code TENANT_ADMIN}, so it succeeds
   *       deterministically.
   *   <li>US-019 T-019: 1× B8 promotion by {@code admin1} of a role one permission short ({@code
   *       B8-PROMOTE}, one holder assigned by {@code admin1}): role row, then set lock. The holder's
   *       assigner is an administrator throughout, so step 11 passes and it succeeds
   *       deterministically.
   * </ol>
   *
   * <p>This is the one harness that can exercise §7.2 property 3's cross-method claim at all:
   * Harness A and B are homogeneous (single-verb) and structurally cannot. Every thread's own
   * {@code Callable} catches ONLY its own legitimate expected exception type(s) (or none, where
   * success is the only legitimate outcome) — any other exception type (a raw {@code
   * DataAccessException}, {@code CannotAcquireLockException}, {@code
   * PessimisticLockingFailureException}, or anything else) propagates through {@link
   * java.util.concurrent.Future#get()} and fails this test loudly, exactly as Harness A/B do.
   *
   * <p><b>RES-10 — closed by this story (US-017 D7), not inherited (03-design.md §7.3).</b> An
   * earlier version of this harness omitted a concurrent {@code assign(TENANT_ADMIN)} thread:
   * against real Testcontainers MySQL 8.4 it reproduced a genuine InnoDB deadlock
   * deterministically (5 of 5 runs — not a rare flake) between {@code assign(TENANT_ADMIN)} (S
   * lock on the caller's own row via M5, then an insert-intention lock in the {@code role_id =
   * adminRoleId} gap) and {@code revoke(TENANT_ADMIN)} (an X next-key range lock over that same
   * range, acquired in the opposite order) — a named, pre-existing defect (US-016 §7.2 property
   * 3, §12.3 RES-10) this harness previously hid by removing the thread rather than fixing the
   * cycle. D7 fixes the root cause instead of avoiding it: {@code assign()}'s privileged path
   * now acquires the same M11 union X lock, first, before M5b and before the INSERT — making
   * lock acquisition a total order across both verbs with respect to {@code fk_user_roles_role}.
   * The restored {@code assign(TENANT_ADMIN)} thread above now races threads 1-2 legitimately
   * through that shared lock instead of deadlocking against them, and the new benign {@code
   * assign(BENIGN)}/{@code revoke(BENIGN)} pair (RC-20.6) — targeting the SAME rows the
   * privileged threads already touch — proves the privileged×benign case that D7's
   * mutual-exclusion argument does not by itself cover: a benign transaction takes no M11 lock,
   * so it cannot cycle with a privileged one through {@code fk_user_roles_role}, but "not
   * constructible by review" is not this story's standard, hence this harness change.
   *
   * <p>This test going green is RES-10's empirical exit gate: per 04-tasks.md line 15 /
   * CLAUDE.md §4, it is verified over ≥5 consecutive runs against a real database once, in
   * Phase 8 test-validate — not on every task's {@code -DskipITs} gate. If a future change
   * reintroduces the pre-D7 cycle, expect this test to reproduce it exactly as it did before —
   * that would be a regression of D7, not of this harness.
   */
  @Test
  void should_completeWithoutDeadlock_when_mixedPrivilegedRoleChangesRaceAcrossBothVerbs()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "mixed");
    User admin1 = seedUser(tenantId, "mixed-admin1");
    User admin2 = seedUser(tenantId, "mixed-admin2");
    User admin3 = seedUser(tenantId, "mixed-admin3");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin1.getId(), admin1.getId());
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin2.getId(), admin1.getId());
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin3.getId(), admin1.getId());

    Role dangerousRole = seedRole(tenantId, "CUSTOM-ADMIN-DEFINING", "mixed");
    grantWholeCatalogue(dangerousRole.getId());
    User dangerousHolder1 = seedUser(tenantId, "mixed-dangerous-holder-1");
    User dangerousHolder2 = seedUser(tenantId, "mixed-dangerous-holder-2");
    seedActiveAssignment(
        tenantId, dangerousRole.getId(), dangerousHolder1.getId(), admin1.getId());
    seedActiveAssignment(
        tenantId, dangerousRole.getId(), dangerousHolder2.getId(), admin1.getId());

    User newDangerousCandidate = seedUser(tenantId, "mixed-new-dangerous-candidate");
    User newDangerousCandidate2 = seedUser(tenantId, "mixed-new-dangerous-candidate-2");
    User newAdminCandidate = seedUser(tenantId, "mixed-new-admin-candidate");

    User nonAdminUser = seedUserWithRole(tenantId, "mixed-nonadmin", "USER_WRITER",
        USER_WRITE_PERMISSION_ID);

    // BENIGN carries no permission at all, so it is never admin-defining regardless of who
    // holds it -- RC-20.6's privileged x benign fixture, seeded on admin3 (a row a privileged
    // revoke thread below also touches) so the benign revoke thread races that same row.
    Role benignRole = seedRole(tenantId, "BENIGN", "mixed");
    seedActiveAssignment(tenantId, benignRole.getId(), admin3.getId(), admin1.getId());

    // US-019 T-019 B8 fixtures: one admin-defining role to demote, one role to promote.
    List<UUID> catalogue = List.copyOf(permissionCatalogueRepository.findCatalogueIds());
    Role demoteRole = seedRole(tenantId, "B8-DEMOTE", "mixed");
    grantWholeCatalogue(demoteRole.getId());
    seedActiveAssignment(
        tenantId, demoteRole.getId(), seedUser(tenantId, "mixed-b8-demote-holder").getId(),
        admin1.getId());
    Set<UUID> demotedSet = new HashSet<>(catalogue.subList(1, catalogue.size()));
    String demoteVersion = RolePermissionSetVersion.of(demoteRole.getId(), catalogue);
    Role promoteRole = seedRole(tenantId, "B8-PROMOTE", "mixed");
    List<UUID> oneShort = catalogue.subList(1, catalogue.size());
    oneShort.forEach(id -> grantPermission(promoteRole.getId(), id));
    seedActiveAssignment(
        tenantId, promoteRole.getId(), seedUser(tenantId, "mixed-b8-promote-holder").getId(),
        admin1.getId());
    String promoteVersion = RolePermissionSetVersion.of(promoteRole.getId(), oneShort);

    RoleChangeActor adminActor = new RoleChangeActor(admin1.getId(), tenantId);
    RoleChangeActor nonAdminActor = new RoleChangeActor(nonAdminUser.getId(), tenantId);

    int threadCount = 13;
    CyclicBarrier barrier = new CyclicBarrier(threadCount);
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<String>> futures = new ArrayList<>();

    // 1-2: revoke(TENANT_ADMIN) on two distinct, never-otherwise-touched targets -- both
    // deterministically succeed (3 admins in the set, AC5 never triggers).
    futures.add(submitRevoke(executor, barrier, adminActor, admin2.getId(), adminRole.getId(),
        "REVOKE_ADMIN_SUCCESS"));
    futures.add(submitRevoke(executor, barrier, adminActor, admin3.getId(), adminRole.getId(),
        "REVOKE_ADMIN_SUCCESS"));

    // 3: assign(TENANT_ADMIN) against a fresh, standalone target -- RES-10's restored thread
    // (see this method's Javadoc, D7): races threads 1-2 through M11's shared union lock instead
    // of the pre-D7 deadlock cycle, and always succeeds deterministically.
    futures.add(submitAssign(executor, barrier, adminActor, newAdminCandidate.getId(),
        adminRole.getId(), "ASSIGN_ADMIN_SUCCESS", "ASSIGN_ADMIN_CONFLICT"));

    // 4-5: revoke(CUSTOM-ADMIN-DEFINING) on two distinct existing holders -- both succeed
    // deterministically; M11's set lock covers this role too (it is admin-defining, D6/D7).
    futures.add(submitRevoke(executor, barrier, adminActor, dangerousHolder1.getId(),
        dangerousRole.getId(), "REVOKE_DANGEROUS_SUCCESS"));
    futures.add(submitRevoke(executor, barrier, adminActor, dangerousHolder2.getId(),
        dangerousRole.getId(), "REVOKE_DANGEROUS_SUCCESS"));

    // 6-7: assign(CUSTOM-ADMIN-DEFINING) duplicate-insert race -- exactly one winner, one conflict.
    futures.add(submitAssign(executor, barrier, adminActor, newDangerousCandidate.getId(),
        dangerousRole.getId(), "ASSIGN_DANGEROUS_SUCCESS", "ASSIGN_DANGEROUS_CONFLICT"));
    futures.add(submitAssign(executor, barrier, adminActor, newDangerousCandidate.getId(),
        dangerousRole.getId(), "ASSIGN_DANGEROUS_SUCCESS", "ASSIGN_DANGEROUS_CONFLICT"));

    // 8: assign(CUSTOM-ADMIN-DEFINING) against a THIRD, standalone target -- no other thread contends
    // for this row, so this always succeeds; adds a second independent concurrent assign()
    // alongside the duplicate-race pair.
    futures.add(submitAssign(executor, barrier, adminActor, newDangerousCandidate2.getId(),
        dangerousRole.getId(), "ASSIGN_DANGEROUS_SUCCESS", "ASSIGN_DANGEROUS_CONFLICT"));

    // 9: denied non-admin revoke(TENANT_ADMIN) against admin1's own (never-touched-elsewhere)
    // row -- the X-lock-then-403 path (T-D11), racing against every other TENANT_ADMIN-lock-set
    // thread above via M11's shared range (D1/D7).
    futures.add(
        executor.submit(
            (Callable<String>)
                () -> {
                  barrier.await(5, TimeUnit.SECONDS);
                  try {
                    roleAssignmentService.revoke(
                        nonAdminActor, admin1.getId(), adminRole.getId(), requestContext());
                    return "UNEXPECTED_SUCCESS";
                  } catch (InsufficientPermissionException e) {
                    return "DENIED";
                  }
                }));

    // 10: assign(BENIGN) targeting dangerousHolder1 -- the SAME row thread 4 concurrently
    // revokes CUSTOM-ADMIN-DEFINING from. BENIGN carries no permission, takes no M11 lock, and
    // sits outside every set lock -- the privileged x benign case (RC-20.6, §7.3).
    futures.add(submitAssign(executor, barrier, adminActor, dangerousHolder1.getId(),
        benignRole.getId(), "ASSIGN_BENIGN_SUCCESS", "ASSIGN_BENIGN_CONFLICT"));

    // 11: revoke(BENIGN) targeting admin3 -- the SAME row thread 2 concurrently revokes
    // TENANT_ADMIN from. Same purpose as thread 10, exercised on the revoke side.
    futures.add(submitRevoke(executor, barrier, adminActor, admin3.getId(), benignRole.getId(),
        "REVOKE_BENIGN_SUCCESS"));

    // 12-13 (US-019 T-019): a B8 demotion (set lock, then role row) and a B8 promotion (role row,
    // then set lock), racing every set-lock thread above. Nothing is caught: success is the only
    // legitimate outcome, so a 412, a 403, a 409 or a 1213 fails the run.
    futures.add(submitReplace(executor, barrier, adminActor, demoteRole.getId(), demotedSet,
        demoteVersion, "B8_DEMOTE_SUCCESS"));
    futures.add(submitReplace(executor, barrier, adminActor, promoteRole.getId(),
        Set.copyOf(catalogue), promoteVersion, "B8_PROMOTE_SUCCESS"));

    executor.shutdown();
    boolean terminated = executor.awaitTermination(30, TimeUnit.SECONDS);
    assertThat(terminated).as("all 13 threads must complete within the timeout").isTrue();

    Map<String, Integer> counts = new HashMap<>();
    for (Future<String> future : futures) {
      // future.get() rethrows for anything NOT already caught in the submitting thread's own
      // try/catch -- any unexpected exception type fails this loop loudly.
      String outcome = future.get();
      counts.merge(outcome, 1, Integer::sum);
    }

    assertThat(counts.getOrDefault("REVOKE_ADMIN_SUCCESS", 0))
        .as("both distinct-target TENANT_ADMIN revokes must succeed: " + counts).isEqualTo(2);
    assertThat(counts.getOrDefault("ASSIGN_ADMIN_SUCCESS", 0))
        .as("the restored assign(TENANT_ADMIN) thread must succeed: " + counts).isEqualTo(1);
    assertThat(counts.getOrDefault("REVOKE_DANGEROUS_SUCCESS", 0))
        .as("both distinct-holder CUSTOM-ADMIN-DEFINING revokes must succeed: " + counts)
        .isEqualTo(2);
    assertThat(counts.getOrDefault("ASSIGN_DANGEROUS_SUCCESS", 0))
        .as("the duplicate-race winner plus the standalone assign must both succeed: " + counts)
        .isEqualTo(2);
    assertThat(counts.getOrDefault("ASSIGN_DANGEROUS_CONFLICT", 0))
        .as("exactly one of the two duplicate admin-defining-role assigns must conflict: " + counts)
        .isEqualTo(1);
    assertThat(counts.getOrDefault("DENIED", 0))
        .as("the non-admin's revoke(TENANT_ADMIN) attempt must be denied: " + counts).isEqualTo(1);
    assertThat(counts.getOrDefault("ASSIGN_BENIGN_SUCCESS", 0))
        .as("the benign assign against a concurrently-touched privileged row must succeed: "
            + counts).isEqualTo(1);
    assertThat(counts.getOrDefault("REVOKE_BENIGN_SUCCESS", 0))
        .as("the benign revoke against a concurrently-touched privileged row must succeed: "
            + counts).isEqualTo(1);
    assertThat(counts.getOrDefault("B8_DEMOTE_SUCCESS", 0))
        .as("the B8 demotion must succeed: " + counts).isEqualTo(1);
    assertThat(counts.getOrDefault("B8_PROMOTE_SUCCESS", 0))
        .as("the B8 promotion must succeed: " + counts).isEqualTo(1);
    assertThat(rolePermissionIds(demoteRole.getId())).isEqualTo(demotedSet);
    assertThat(rolePermissionIds(promoteRole.getId())).isEqualTo(Set.copyOf(catalogue));
    assertThat(counts.values().stream().mapToInt(Integer::intValue).sum())
        .as("every thread must resolve to one of the expected outcomes for its role: " + counts)
        .isEqualTo(threadCount);
    assertThat(countActiveAdminAssignments(tenantId, adminRole.getId()))
        .as("the tenant must retain exactly admin1 and the newly-assigned admin candidate as its"
            + " two remaining active admins after the race (admin2/admin3 both legitimately"
            + " revoked; the restored assign(TENANT_ADMIN) thread adds one -- see Javadoc, D7)")
        .isEqualTo(2);
  }

  // ── RC-57.4 (a) (US-019 T-019, RES-28, design §10.3 step 10) ─────────────────────────────

  /**
   * One administrator, whose only administrator status is two custom admin-defining roles R and
   * R2, sends two concurrent B8 demotions: PUT R - x and PUT R2 - y, each authorised at step 6
   * through the other role. Ordering is forced: a gate holds the caller's two {@code user_roles}
   * rows {@code FOR UPDATE} (the set lock's rows) until both PUTs are queued on them, so both have
   * passed their snapshot authorization. The set lock then serialises them and the second decides
   * step 10 from the current read: the other role is no longer admin-defining, so 403. Exactly one
   * succeeds and the tenant never reaches zero administrators, in every iteration.
   */
  @Test
  void should_letExactlyOneDemotionSucceed_when_oneCallerDemotesBothOfTheirAdminRolesConcurrently()
      throws Exception {
    List<UUID> catalogue = List.copyOf(permissionCatalogueRepository.findCatalogueIds());
    for (int i = 0; i < 10; i++) {
      UUID tenantId = uuidGenerator.newId();
      User caller = seedUser(tenantId, "rc574a-caller");
      Role first = seedRole(tenantId, "RC574A-R", "rc574a");
      Role second = seedRole(tenantId, "RC574A-R2", "rc574a");
      grantWholeCatalogue(first.getId());
      grantWholeCatalogue(second.getId());
      seedActiveAssignment(tenantId, first.getId(), caller.getId(), caller.getId());
      seedActiveAssignment(tenantId, second.getId(), caller.getId(), caller.getId());
      RoleChangeActor actor = new RoleChangeActor(caller.getId(), tenantId);
      String fullVersionFirst = RolePermissionSetVersion.of(first.getId(), catalogue);
      String fullVersionSecond = RolePermissionSetVersion.of(second.getId(), catalogue);
      Set<UUID> withoutFirstId = new HashSet<>(catalogue.subList(1, catalogue.size()));

      ExecutorService executor = Executors.newFixedThreadPool(2);
      Future<String> demoteFirst;
      Future<String> demoteSecond;
      try (Connection gate = lockAssignmentRows(tenantId, first.getId(), second.getId())) {
        demoteFirst =
            executor.submit(
                () -> replaceOutcome(actor, first.getId(), withoutFirstId, fullVersionFirst));
        demoteSecond =
            executor.submit(
                () -> replaceOutcome(actor, second.getId(), withoutFirstId, fullVersionSecond));
        awaitLockWaiters(2);
        gate.commit();
      }
      executor.shutdown();
      assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

      assertThat(List.of(demoteFirst.get(), demoteSecond.get()))
          .as("iteration %d: exactly one demotion succeeds", i)
          .containsExactlyInAnyOrder("OK", "DENIED_" + DenialReason.GRANT_EXCEEDS_CALLER);
      long adminDefiningLeft =
          List.of(first, second).stream()
              .filter(role -> rolePermissionIds(role.getId()).containsAll(catalogue))
              .count();
      assertThat(adminDefiningLeft)
          .as("iteration %d: the caller is still an administrator through one role", i)
          .isEqualTo(1);
    }
  }

  // ── RC-57.4 (b) (US-019 T-021, RC-57.2, T-E49, design §10.9) ─────────────────────────────

  /**
   * A B8 demotion ∥ a revoke of the last other administrator. Custom admin-defining roles R and S:
   * a user holds R, the caller holds S. The caller demotes R (an administrator through S) and, at
   * the same time, revokes their own S. Order is forced: a gate X-locks R's {@code
   * role_permissions} rows, so the demotion holds the set lock and R's row and waits at its
   * current read; the revoke, whose snapshot still calls R admin-defining, then queues on the set
   * lock. The gate commits and the demotion commits. The revoke classifies the locked roles from
   * its current read: R's holder is no administrator now, so the lockout holds (409 RBAC_002) and
   * the tenant keeps its administrator, in every iteration.
   */
  @Test
  void should_keepTheLockout_when_aRevokeOfTheLastOtherAdministratorQueuedBehindADemotion()
      throws Exception {
    List<UUID> catalogue = List.copyOf(permissionCatalogueRepository.findCatalogueIds());
    Set<UUID> withoutFirstId = new HashSet<>(catalogue.subList(1, catalogue.size()));
    for (int i = 0; i < 10; i++) {
      UUID tenantId = uuidGenerator.newId();
      Role demoted = seedRole(tenantId, "RC574B-R", "rc574b");
      Role remaining = seedRole(tenantId, "RC574B-S", "rc574b");
      grantWholeCatalogue(demoted.getId());
      grantWholeCatalogue(remaining.getId());
      User caller = seedUser(tenantId, "rc574b-caller");
      User holderOfDemoted = seedUser(tenantId, "rc574b-holder");
      seedActiveAssignment(tenantId, demoted.getId(), holderOfDemoted.getId(), caller.getId());
      seedActiveAssignment(tenantId, remaining.getId(), caller.getId(), caller.getId());
      RoleChangeActor actor = new RoleChangeActor(caller.getId(), tenantId);
      String fullVersion = RolePermissionSetVersion.of(demoted.getId(), catalogue);

      ExecutorService executor = Executors.newFixedThreadPool(2);
      Future<String> demotion;
      Future<String> revocation;
      try (Connection gate = lockRolePermissionRows(demoted.getId())) {
        demotion =
            executor.submit(
                () -> replaceOutcome(actor, demoted.getId(), withoutFirstId, fullVersion));
        awaitLockWaiters(1);
        revocation =
            executor.submit(() -> revokeOutcome(actor, caller.getId(), remaining.getId()));
        awaitLockWaiters(2);
        gate.commit();
      }
      executor.shutdown();
      assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

      assertThat(demotion.get()).as("iteration %d", i).isEqualTo("OK");
      assertThat(revocation.get()).as("iteration %d: the lockout holds", i).isEqualTo("RBAC_002");
      assertThat(rolePermissionIds(demoted.getId())).as("iteration %d", i).isEqualTo(withoutFirstId);
      assertThat(countActiveAdminAssignments(tenantId, remaining.getId()))
          .as("iteration %d: the tenant keeps its one administrator", i)
          .isEqualTo(1);
    }
  }

  /** RC-57.4 (b): "OK", or the lockout's code; anything else propagates and fails the test. */
  private String revokeOutcome(RoleChangeActor actor, UUID targetUserId, UUID roleId) {
    try {
      roleAssignmentService.revoke(actor, targetUserId, roleId, requestContext());
      return "OK";
    } catch (LastAdminRoleException e) {
      return e.code();
    }
  }

  // ── RC-56.7 (US-019 T-020, T-E48, design §10.8, §10.9): RBAC_010 holds under concurrency ──

  /**
   * Attach p ∥ attach q on a role two permissions short of the catalogue, with a holder assigned
   * by a non-administrator. Each attach's snapshot says "one short after me", so neither runs the
   * provenance rule. A gate holds R's row until both are queued on it (RC-64), so both snapshots
   * predate either insert. The first to get the row commits; the second's post-insert current read
   * sees the catalogue complete and rolls back with 409 RBAC_012 (or, had its snapshot seen the
   * first, RBAC_010). Never both, never a 1213, and R is never admin-defining.
   */
  @Test
  void should_letExactlyOneAttachSucceed_when_twoAttachesWouldTogetherCompleteARoleWithANonAdministratorAssignedHolder()
      throws Exception {
    List<UUID> catalogue = List.copyOf(permissionCatalogueRepository.findCatalogueIds());
    for (int i = 0; i < 10; i++) {
      Rc567Fixture fixture = seedRc567Fixture("rc567a", USER_WRITE_PERMISSION_ID, AUDIT_READ_ID);

      ExecutorService executor = Executors.newFixedThreadPool(2);
      Future<String> attachP;
      Future<String> attachQ;
      try (Connection gate = lockRoleRow(fixture.tenantId(), fixture.role().getId())) {
        attachP = executor.submit(() -> attachOutcome(fixture, USER_WRITE_PERMISSION_ID));
        attachQ = executor.submit(() -> attachOutcome(fixture, AUDIT_READ_ID));
        awaitLockWaiters(2);
        gate.commit();
      }
      executor.shutdown();
      assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

      List<String> outcomes = List.of(attachP.get(), attachQ.get());
      assertThat(outcomes).as("iteration %d: exactly one attach succeeds", i).containsOnlyOnce("OK");
      assertThat(outcomes).as("iteration %d", i).allMatch(Set.of("OK", "RBAC_010", "RBAC_012")::contains);
      assertThat(rolePermissionIds(fixture.role().getId()).containsAll(catalogue))
          .as("iteration %d: the role never became admin-defining", i)
          .isFalse();
    }
  }

  /**
   * B8 (+q) then a queued attach of p, on a role two short with a non-administrator-assigned
   * holder. Order is forced: a gate X-locks R's {@code role_permissions} rows, so the B8 holds R's
   * row and waits at its current read; the attach, whose snapshot still sees R two short, then
   * queues on R's row. The gate commits, the B8 commits R one short, and the attach's post-insert
   * read sees the catalogue complete: 409 RBAC_012, and R stays one short.
   */
  @Test
  void should_return409Rbac012ForTheAttach_when_itQueuedBehindAReplaceThatLeftTheRoleOneShort()
      throws Exception {
    List<UUID> catalogue = List.copyOf(permissionCatalogueRepository.findCatalogueIds());
    for (int i = 0; i < 10; i++) {
      Rc567Fixture fixture = seedRc567Fixture("rc567b", USER_WRITE_PERMISSION_ID, AUDIT_READ_ID);
      Set<UUID> twoShort = rolePermissionIds(fixture.role().getId());
      Set<UUID> oneShort = new HashSet<>(twoShort);
      oneShort.add(AUDIT_READ_ID);
      String v0 = RolePermissionSetVersion.of(fixture.role().getId(), twoShort);

      ExecutorService executor = Executors.newFixedThreadPool(2);
      Future<String> replaced;
      Future<String> attached;
      try (Connection gate = lockRolePermissionRows(fixture.role().getId())) {
        replaced =
            executor.submit(
                () -> replaceOutcome(fixture.admin(), fixture.role().getId(), oneShort, v0));
        awaitLockWaiters(1);
        attached = executor.submit(() -> attachOutcome(fixture, USER_WRITE_PERMISSION_ID));
        awaitLockWaiters(2);
        gate.commit();
      }
      executor.shutdown();
      assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

      assertThat(replaced.get()).as("iteration %d", i).isEqualTo("OK");
      assertThat(attached.get()).as("iteration %d", i).isEqualTo("RBAC_012");
      assertThat(rolePermissionIds(fixture.role().getId()))
          .as("iteration %d: the replace's set, one short of the catalogue", i)
          .isEqualTo(oneShort)
          .doesNotContainAnyElementsOf(Set.of(USER_WRITE_PERMISSION_ID));
      assertThat(oneShort.containsAll(catalogue)).isFalse();
    }
  }

  /**
   * An assign queued behind a B8 promotion. The assigner holds R's pre-promotion set (A2 passes)
   * but is no administrator; R lacks only {@code user:directory:read}, so the PII rule passes on the
   * snapshot too. A gate X-locks R's {@code role_permissions} rows, so the promotion holds R's row
   * and the set lock and waits at its current read; the assign then queues on R's row (its
   * conditional insert). The promotion commits after its RBAC_010 check over the locked holders;
   * the assign's post-insert read sees R admin-defining: 409 RBAC_012, rolled back. R never has a
   * holder assigned by a non-administrator.
   */
  @Test
  void should_return409Rbac012ForTheAssign_when_itQueuedBehindAPromotionOfTheRole()
      throws Exception {
    List<UUID> catalogue = List.copyOf(permissionCatalogueRepository.findCatalogueIds());
    UUID directoryRead = RbacSeededPermissionIds.USER_DIRECTORY_READ;
    List<UUID> allButDirectoryRead =
        catalogue.stream().filter(id -> !id.equals(directoryRead)).toList();
    for (int i = 0; i < 10; i++) {
      UUID tenantId = uuidGenerator.newId();
      Role adminRole = seedTenantAdminRole(tenantId, "rc567c");
      User admin = seedUser(tenantId, "rc567c-admin");
      seedActiveAdminAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());
      Role assignerRole = seedRole(tenantId, "RC567C-ASSIGNER-" + i, "rc567c");
      allButDirectoryRead.forEach(id -> grantPermission(assignerRole.getId(), id));
      User assigner = seedUser(tenantId, "rc567c-assigner");
      seedActiveAssignment(tenantId, assignerRole.getId(), assigner.getId(), admin.getId());
      Role role = seedRole(tenantId, "RC567C-R-" + i, "rc567c");
      allButDirectoryRead.forEach(id -> grantPermission(role.getId(), id));
      User sockPuppet = seedUser(tenantId, "rc567c-puppet");
      String v0 = RolePermissionSetVersion.of(role.getId(), allButDirectoryRead);
      RoleChangeActor adminActor = new RoleChangeActor(admin.getId(), tenantId);
      RoleChangeActor assignerActor = new RoleChangeActor(assigner.getId(), tenantId);

      ExecutorService executor = Executors.newFixedThreadPool(2);
      Future<String> promoted;
      Future<String> assigned;
      try (Connection gate = lockRolePermissionRows(role.getId())) {
        promoted =
            executor.submit(
                () -> replaceOutcome(adminActor, role.getId(), Set.copyOf(catalogue), v0));
        awaitLockWaiters(1);
        assigned = executor.submit(() -> assignOutcome(assignerActor, sockPuppet, role));
        awaitLockWaiters(2);
        gate.commit();
      }
      executor.shutdown();
      assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

      assertThat(promoted.get()).as("iteration %d", i).isEqualTo("OK");
      assertThat(assigned.get()).as("iteration %d", i).isEqualTo("RBAC_012");
      assertThat(rolePermissionIds(role.getId())).as("iteration %d", i).containsAll(catalogue);
      assertThat(countActiveAdminAssignments(tenantId, role.getId()))
          .as("iteration %d: no holder assigned by the non-administrator", i)
          .isZero();
    }
  }

  /** RC-56.7: a role two short of the catalogue (missing p and q) with one holder assigned by a
   * non-administrator, and an administrator who holds the whole catalogue. */
  private record Rc567Fixture(UUID tenantId, Role role, RoleChangeActor admin) {}

  private Rc567Fixture seedRc567Fixture(String tag, UUID p, UUID q) {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, tag);
    User admin = seedUser(tenantId, tag + "-admin");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());
    Role role = seedRole(tenantId, tag.toUpperCase(Locale.ROOT) + "-R", tag);
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions WHERE id NOT IN (UUID_TO_BIN(?), UUID_TO_BIN(?))",
        role.getId().toString(),
        p.toString(),
        q.toString());
    User nonAdministrator = seedUser(tenantId, tag + "-nonadmin");
    User holder = seedUser(tenantId, tag + "-holder");
    seedActiveAssignment(tenantId, role.getId(), holder.getId(), nonAdministrator.getId());
    return new Rc567Fixture(tenantId, role, new RoleChangeActor(admin.getId(), tenantId));
  }

  /** "OK", or the 409's code; anything else (a 1213 above all) propagates and fails the test. */
  private String attachOutcome(Rc567Fixture fixture, UUID permissionId) {
    try {
      roleManagementService.attachPermission(
          fixture.admin(), fixture.role().getId(), permissionId, requestContext());
      return "OK";
    } catch (RoleClassificationChangedException | AttachProvenanceConflictException e) {
      return e.code();
    }
  }

  /** "OK", or RBAC_012; anything else propagates and fails the test. */
  private String assignOutcome(RoleChangeActor actor, User target, Role role) {
    try {
      roleAssignmentService.assign(actor, target.getId(), role.getId(), requestContext());
      return "OK";
    } catch (RoleClassificationChangedException e) {
      return e.code();
    }
  }

  // ── Scenario 4: second, non-bootstrap tenant (R-9 regression) ──────────────────────────

  /**
   * Uses a freshly generated tenant id and a freshly created {@code TENANT_ADMIN}-named role
   * whose id is nothing like the bootstrap tenant's seeded literal. A hardcoded-bootstrap-role-
   * id implementation would fail to recognize this role as {@code TENANT_ADMIN} at all (or
   * would evaluate the guard against the wrong, unrelated tenant's admin rows), letting this
   * revoke incorrectly succeed instead of throwing — exactly the regression 04-tasks.md T-018
   * calls out scenario 1 as unable to catch on its own.
   */
  @Test
  void should_blockRevocation_when_nonBootstrapTenantHasOnlyOneActiveAdmin() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "nonbootstrap");
    User admin = seedUser(tenantId, "nonbootstrap-solo");
    UserRole assignment =
        seedActiveAdminAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    RoleChangeActor actor = new RoleChangeActor(admin.getId(), tenantId);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, admin.getId(), adminRole.getId(), requestContext()))
        .isInstanceOf(LastAdminRoleException.class)
        .extracting(e -> ((LastAdminRoleException) e).code())
        .isEqualTo("RBAC_002");

    assertThat(isActive(assignment.getId()))
        .as("a non-bootstrap tenant's own last active admin assignment must remain active"
            + " after a blocked revoke")
        .isTrue();
  }

  // ── Scenario 5: EXPLAIN pinning M11's query plan + "for update" in the emitted SQL ────

  /**
   * Pins the FK-index plan two ways: (1) an {@code EXPLAIN} of a single-role reconstruction of
   * {@code JpaUserRoleRepository#lockActiveAssignmentHoldersByRoles} (M11, US-017 D6 — supersedes
   * the removed M1 this scenario originally pinned; a one-element {@code role_id IN (:roleIds)}
   * is the same access pattern MySQL's optimizer plans identically to an equality lookup),
   * asserting {@code key = fk_user_roles_role_tenant} (the FK index name — confirmed against
   * {@code V5__rbac_schema.sql}'s {@code CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id)}
   * and the threat model's own live-MySQL verification) and {@code type = ref}, never {@code
   * ALL}; (2) a Hibernate SQL-logging capture around the REAL production call path ({@link
   * RoleAssignmentService#revoke}, with two active admins so the call succeeds without
   * throwing) asserting the actually-emitted statement contains {@code for update}.
   */
  @Test
  void should_pinQueryPlanToFkIndex_and_emitForUpdate_when_lockingTenantAdminAssignments()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "explain");
    User admin1 = seedUser(tenantId, "explain-admin1");
    User admin2 = seedUser(tenantId, "explain-admin2");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin1.getId(), admin1.getId());
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin2.getId(), admin2.getId());

    List<Map<String, Object>> plan =
        jdbc.queryForList(
            "EXPLAIN SELECT id FROM user_roles WHERE role_id = ? AND tenant_id = ? AND"
                + " revoked_at IS NULL FOR UPDATE",
            toBytes(adminRole.getId()),
            toBytes(tenantId));

    assertThat(plan).hasSize(1);
    Map<String, Object> row = plan.get(0);
    assertThat(String.valueOf(row.get("key")))
        .as("M11 must drive off the FK index on role_id, never a full table scan: " + row)
        .isEqualTo("fk_user_roles_role_tenant");
    assertThat(String.valueOf(row.get("type")))
        .as("M11's access type must be an index lookup (ref), never ALL: " + row)
        .isEqualTo("ref");

    RoleChangeActor actor = new RoleChangeActor(admin1.getId(), tenantId);
    List<String> emittedSql =
        captureHibernateSql(
            () ->
                roleAssignmentService.revoke(
                    actor, admin1.getId(), adminRole.getId(), requestContext()));

    assertThat(emittedSql)
        .as("emitted SQL captured during the revoke call: " + emittedSql)
        .anyMatch(sql -> sql.toLowerCase(Locale.ROOT).contains("for update"));
  }

  // ── Scenario 6: MC-5 — EXPLAIN the ACTUAL captured SQL for M11 ─────────────────────────

  /**
   * RC-9.1 / 03-design.md §7.2 step 1 + §11.2 MC-5. The set lock's deadlock-freedom argument is a
   * property of the chosen execution plan, not the predicates — InnoDB locks index records, not
   * logical rows. This captures the REAL Hibernate-emitted SQL for M11 from one {@code revoke()}
   * call (a revoke of an admin-defining role with two active admins) and EXPLAINs it, asserting
   * only the {@code key} column (EXPLAIN's other columns are MySQL-version-sensitive; this repo
   * pins MySQL 8.4 via Testcontainers).
   *
   * <p><b>US-018 M3 (T-016):</b> the M5/M5b caller gate and its containment assertions are
   * retired with the gate (ledger rows 1 and 2): the administrator status now comes from M11's own
   * rows, so there is no second locking read to contain. The control that replaces D8's
   * containment proof is that nothing else locks {@code user_roles} on this path, which the
   * "exactly one captured statement contains {@code for update}" lookup below asserts; the one
   * {@code for share} allowed since US-019 RC-57.2 is the current read of {@code role_permissions},
   * which locks no {@code user_roles} row.
   *
   * <p><strong>If M11's key is ever observed to NOT be {@code fk_user_roles_role_tenant}, do not relax
   * this assertion.</strong> That is a real gap in the deadlock-freedom argument requiring an
   * Architect-level escalation.
   */
  @Test
  void should_driveM11OffTheRoleIndexAndTakeNoOtherLockingRead_when_explainingCapturedLockingReads()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "mc5");
    User admin1 = seedUser(tenantId, "mc5-admin1");
    User admin2 = seedUser(tenantId, "mc5-admin2");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin1.getId(), admin1.getId());
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin2.getId(), admin2.getId());

    RoleChangeActor actor = new RoleChangeActor(admin1.getId(), tenantId);
    List<String> emittedSql =
        captureHibernateSql(
            () ->
                roleAssignmentService.revoke(
                    actor, admin1.getId(), adminRole.getId(), requestContext()));

    // M11 -- PESSIMISTIC_WRITE renders "for update"
    // (JpaUserRoleRepository#lockActiveAssignmentHoldersByRoles).
    String m11Sql = findCapturedStatement(emittedSql, "for update");
    // US-019 RC-57.2: the one other locking read is the current classification of the lock set,
    // a FOR SHARE on role_permissions only; nothing else locks user_roles on this path.
    String currentReadSql = findCapturedStatement(emittedSql, "for share");
    assertThat(currentReadSql.toLowerCase(Locale.ROOT))
        .as("the only FOR SHARE is the RC-57.2 read of role_permissions: " + currentReadSql)
        .contains("for share of rp")
        .contains("from role_permissions rp")
        .doesNotContain("user_roles");

    // M11's bind order: roleIds, tenantId (revokedAt IS NULL has no parameter).
    assertThat(explainKey(m11Sql, toBytes(adminRole.getId()), toBytes(tenantId)))
        .as("M11 must drive off the FK index on role_id: " + m11Sql)
        .isEqualTo("fk_user_roles_role_tenant");

    // US-017 T-006(b), MC-A (extended): M11 must acquire no JOIN at all (never widening the lock
    // beyond user_roles by joining roles/permissions) -- design §11.2 MC-A, port Javadoc.
    assertThat(m11Sql.toLowerCase(Locale.ROOT))
        .as("M11 must not join roles or permissions -- lock-scope discipline: " + m11Sql)
        .doesNotContain(" join ");
  }

  // ── Scenario 6b (US-018 T-016, 03-design.md §11.2 MC-A extended): M10' non-locking ───────

  /**
   * MC-A: M10' ({@code findRolePermissionIdsForTenantRoles}, hosted on {@code
   * JpaRoleRepository#findRolePermissionIdsByTenantRoles}; replaces M10) reads the tenant's
   * {@code role_permissions}. A {@code @Lock} accidentally added here would be a new acquisition
   * outside the single-statement set lock (ADR-0018 D6) and would be REJECTED IN PRODUCTION on a
   * grant-restricted table yet PASS every Testcontainers IT (every IT connects as the container
   * superuser). Identified positively by requiring BOTH {@code role_permissions} AND {@code
   * tenant_id} and excluding M14 (a {@code left join}) and M13 ({@code user_roles}), unambiguous
   * within one {@code revoke()} call of an admin-defining custom role.
   */
  @Test
  void should_neverEmitForShareOrForUpdate_when_capturingM10PrimesSql_MCA() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "mca10");
    User admin = seedUser(tenantId, "mca10-admin");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    Role customAdminRole = seedRole(tenantId, "MCA10-CUSTOM-ADMIN-DEFINING", "mca10");
    grantWholeCatalogue(customAdminRole.getId());
    User holder1 = seedUser(tenantId, "mca10-holder1");
    User holder2 = seedUser(tenantId, "mca10-holder2");
    seedActiveAssignment(tenantId, customAdminRole.getId(), holder1.getId(), admin.getId());
    seedActiveAssignment(tenantId, customAdminRole.getId(), holder2.getId(), admin.getId());

    RoleChangeActor actor = new RoleChangeActor(admin.getId(), tenantId);
    List<String> emittedSql =
        captureHibernateSql(
            () ->
                roleAssignmentService.revoke(
                    actor, holder1.getId(), customAdminRole.getId(), requestContext()));

    // "rp.role_id in (" excludes the RC-57.2 current read (US-019), scoped to the lock set's ids.
    String m10PrimeSql =
        findStatementMatching(
            emittedSql,
            List.of("role_permissions", "tenant_id"),
            List.of("user_roles", "left join", "rp.role_id in ("));
    assertNoLockingClause(m10PrimeSql, "M10' (findRolePermissionIdsForTenantRoles)");
  }

  // ── Scenario 6c (row 15, 03-design.md §11.2 MC-A extended): the indicator queries non-locking ─

  /**
   * MC-A extended: the zero-admin indicator's two support queries ({@code
   * findTenantsWithAnAdminDefiningRole}, {@code findTenantsWithActiveAdminDefiningHolders}) both
   * count {@code role_permissions} against {@code permissions}, with the same {@code SELECT}-only
   * grant concern as M10', now exercised on the health-check cadence. Invoked directly against the
   * autowired repository bean, capturing both statements from one action.
   */
  @Test
  void should_neverEmitForShareOrForUpdate_when_capturingTheIndicatorsTwoQueries_MCA()
      throws Exception {
    List<String> emittedSql =
        captureHibernateSql(
            () -> {
              userRoleRepository.findTenantsWithAnAdminDefiningRole();
              userRoleRepository.findTenantsWithActiveAdminDefiningHolders();
            });

    assertThat(emittedSql).as("the indicator's two queries, captured from one action").hasSize(2);
    assertNoLockingClause(emittedSql.get(0), "findTenantsWithAnAdminDefiningRole");
    assertNoLockingClause(emittedSql.get(1), "findTenantsWithActiveAdminDefiningHolders");
  }

  // ── Scenario 6d (US-018 T-001, 03-design.md §4.11 MC-A extended): M13/M14 non-locking ──────

  /**
   * MC-A extended: M13 ({@code findHeldRolePermissionIdsForAuthorization}) and M14 ({@code
   * findPermissionIdsByRoleAndTenantId}) are the grant-subset reads (ADR-0021 D2). A locking read on M13
   * would be a new acquisition outside the set-lock region (ADR-0018 D6), and either read would be
   * rejected in production if it ever locked a {@code SELECT}-only table, yet would pass every
   * Testcontainers IT (container superuser). Invoked directly against the repository beans,
   * capturing both statements from one action.
   */
  @Test
  void should_neverEmitForShareOrForUpdate_when_capturingM13AndM14sSql_MCA() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "mca13");
    User admin = seedUser(tenantId, "mca13-admin");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    List<String> emittedSql =
        captureHibernateSql(
            () -> {
              userRoleRepository.findHeldRolePermissionIdsForAuthorization(admin.getId(), tenantId);
              roleRepository.findPermissionIdsByRoleAndTenantId(adminRole.getId(), tenantId);
            });

    assertThat(emittedSql).as("M13 and M14, captured from one action").hasSize(2);
    assertNoLockingClause(emittedSql.get(0), "M13 (findHeldRolePermissionIdsForAuthorization)");
    assertNoLockingClause(emittedSql.get(1), "M14 (findPermissionIdsByRoleAndTenantId)");
  }

  // ── Scenario 6f (US-018 T-002, 03-design.md §4.11 MC-A extended): M15 non-locking ──────────

  /**
   * MC-A extended: M15 ({@code findCatalogueIds}, hosted on {@code JpaPermissionCatalogueRepository}) is
   * A4's catalogue read. It reads only {@code permissions}, on which {@code nexus_app} holds {@code
   * SELECT} only, so a locking form would be rejected in production yet pass every Testcontainers
   * IT (container superuser). Invoked directly against the repository bean.
   */
  @Test
  void should_neverEmitForShareOrForUpdate_when_capturingM15sSql_MCA() throws Exception {
    List<String> emittedSql = captureHibernateSql(permissionCatalogueRepository::findCatalogueIds);

    assertThat(emittedSql).as("M15, captured from one action").hasSize(1);
    assertNoLockingClause(emittedSql.get(0), "M15 (findCatalogueIds)");
  }

  // ── Scenario 6e (US-017 T-006(c), 03-design.md §11.2 MC-C, RC-20.7): plan stability ─────

  /**
   * MC-C (re-derived MC-5): the set lock's deadlock-freedom argument depends on the CHOSEN PLAN,
   * not merely the predicate -- InnoDB locks index records, and a full-scan fallback would acquire
   * in primary-key order, breaking it. A 1-element and a 40-element IN-list can be costed
   * differently by the optimizer, so this asserts {@code key = fk_user_roles_role_tenant} for M11 at
   * IN-list sizes 1, 2 and >= 20 -- plan stability across cardinalities, not one lucky fixture
   * size. (M5b, the second half of the former test, is retired with the gate, ledger row 2.)
   *
   * <p><b>If this is ever observed to select a different key at any cardinality, do not relax
   * this assertion</b> -- escalate per 03-design.md §7.2/§11.2.
   */
  @Test
  void should_pinKeyToFkUserRolesRole_acrossInListCardinalities_forM11_MCC() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "mcc");
    User admin1 = seedUser(tenantId, "mcc-admin1");
    User admin2 = seedUser(tenantId, "mcc-admin2");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin1.getId(), admin1.getId());
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin2.getId(), admin2.getId());

    for (int size : List.of(1, 2, 25)) {
      List<UUID> roleIds = new ArrayList<>();
      roleIds.add(adminRole.getId());
      for (int i = 1; i < size; i++) {
        roleIds.add(uuidGenerator.newId());
      }

      assertThat(explainM11Key(roleIds, tenantId))
          .as("M11 must drive off fk_user_roles_role_tenant at IN-list size " + size)
          .isEqualTo("fk_user_roles_role_tenant");
    }
  }

  /** MC-C helper: EXPLAINs M11's shape ({@code lockActiveAssignmentHoldersByRoles}) at the given IN-list. */
  private String explainM11Key(List<UUID> roleIds, UUID tenantId) {
    String placeholders = String.join(",", java.util.Collections.nCopies(roleIds.size(), "?"));
    List<Object> params = new ArrayList<>();
    roleIds.forEach(id -> params.add(toBytes(id)));
    params.add(toBytes(tenantId));
    // Mirrors the real M11 SQL exactly (JpaUserRoleRepository#lockActiveAssignmentHoldersByRoles)
    // -- including FORCE INDEX, added after this very test caught the JPQL/@Lock form falling
    // back to a full table scan at IN-list size 25.
    List<Map<String, Object>> plan =
        jdbc.queryForList(
            "EXPLAIN SELECT * FROM user_roles FORCE INDEX (fk_user_roles_role_tenant) WHERE role_id IN ("
                + placeholders + ") AND tenant_id = ? AND revoked_at IS NULL FOR UPDATE",
            params.toArray());
    assertThat(plan).hasSize(1);
    return String.valueOf(plan.get(0).get("key"));
  }

  // ── Scenario 7 (US-018 T-017, 03-design.md §11.2 MC-A extended): the attach reads ───────────

  /**
   * MC-A extended: every read an attach issues (A3's M13, M14 and M15, the narrow provenance
   * rule's holder and administrator reads, and the post-commit holder read with its administrator
   * user set) must be non-locking. {@code nexus_app} holds {@code SELECT} only on {@code
   * permissions}, and MySQL requires {@code SELECT} plus one of {@code DELETE}/{@code LOCK
   * TABLES}/{@code UPDATE} to execute a locking read, so a {@code @Lock} accidentally added to any
   * of them would be REJECTED IN PRODUCTION but PASS every Testcontainers IT (every IT connects as
   * the container superuser). Code review alone cannot see this failure mode; this test makes it
   * mechanical.
   *
   * <p>The attach completes the catalogue of a role that has one administrator-assigned holder, so
   * the provenance branch runs too (M14, M15, the holders, M10', the administrator users) and the
   * post-commit read repeats the holder and administrator reads. Rather than identify each
   * statement, the assertion is the stronger one: <b>no</b> captured statement contains a locking
   * clause, except the US-019 {@code lock…} statements attach takes by design (RC-64, RC-56.3,
   * and, for a catalogue-completing attach, R1-1), each identified positively: the role row {@code
   * FOR UPDATE} before the insert, R's {@code role_permissions} {@code FOR SHARE} after it, and the
   * promotion pair (the set lock and the locked roles' permissions read). All are privileged for
   * {@code nexus_app} ({@code RolesPrivilegeIT}, {@code RolePermissionsPrivilegeIT}).
   *
   * <p>This replaces the former M7/M8/M9 test (ledger rows 11 and 17): M7 and the M8 call site on
   * these paths are deleted with the name-based gates.
   */
  @Test
  void should_neverEmitForShareOrForUpdate_when_capturingEveryAttachRead_MCA() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "mc1b");
    User adminActorUser = seedUser(tenantId, "mc1b-admin");
    seedActiveAdminAssignment(
        tenantId, adminRole.getId(), adminActorUser.getId(), adminActorUser.getId());

    // A custom role carrying the whole catalogue except role:write, with one holder assigned by
    // the administrator. Attaching role:write completes the catalogue.
    Role customRole = seedRole(tenantId, "MC1-ATTACH-TARGET", "mc1b");
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions WHERE id <> UUID_TO_BIN(?)",
        customRole.getId().toString(),
        ROLE_WRITE_PERMISSION_ID.toString());
    User holder = seedUser(tenantId, "mc1b-holder");
    seedActiveAssignment(tenantId, customRole.getId(), holder.getId(), adminActorUser.getId());
    RoleChangeActor adminActor = new RoleChangeActor(adminActorUser.getId(), tenantId);

    List<String> emittedSql =
        captureHibernateSql(
            () ->
                roleManagementService.attachPermission(
                    adminActor, customRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext()));

    assertThat(emittedSql).as("the attach must emit SQL: " + emittedSql).isNotEmpty();
    String roleRowLock =
        findStatementMatching(emittedSql, List.of("from roles", "for update"), List.of());
    String currentRead =
        findStatementMatching(
            emittedSql, List.of("from role_permissions", "for share"), List.of("join"));
    // US-019 review R1-1: a catalogue-completing attach re-judges its holders under locks, as a
    // promoting replace does: the set lock (user_roles FOR UPDATE) and the current read of the
    // locked roles' permissions (role_permissions joined to roles, FOR SHARE OF rp).
    String setLock =
        findStatementMatching(emittedSql, List.of("from user_roles", "for update"), List.of());
    String lockedPermissionsRead =
        findStatementMatching(
            emittedSql, List.of("from role_permissions", "join", "for share"), List.of());
    emittedSql.stream()
        .filter(
            sql ->
                !sql.equals(roleRowLock)
                    && !sql.equals(currentRead)
                    && !sql.equals(setLock)
                    && !sql.equals(lockedPermissionsRead))
        .forEach(sql -> assertNoLockingClause(sql, "an attach read"));
    assertThat(emittedSql.stream().filter(sql -> sql.toLowerCase(Locale.ROOT).contains("user_roles")))
        .as("the holder reads (in the transaction and after commit) are captured: " + emittedSql)
        .hasSizeGreaterThanOrEqualTo(2);
  }

  // ── Scenario 8 (US-018 T-018, 03-design.md §11.2 MC-A extended): M16 non-locking ───────────

  /**
   * MC-A extended: M16 ({@code findHeldAdminDefiningRoleIds}), the independent self-assignment
   * check, must never lock: it is read inside the set-lock region and a locking read driven by
   * {@code fk_user_roles_user} would be a new acquisition outside it (ADR-0018 D6).
   */
  @Test
  void should_neverEmitForShareOrForUpdate_when_capturingM16sSql_MCA() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "mca16");
    User admin = seedUser(tenantId, "mca16-admin");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    List<String> emittedSql =
        captureHibernateSql(
            () ->
                assertThat(userRoleRepository.findHeldAdminDefiningRoleIds(admin.getId(), tenantId))
                    .containsExactly(adminRole.getId()));

    assertThat(emittedSql).as("M16, captured from one action").hasSize(1);
    assertNoLockingClause(emittedSql.get(0), "M16 (findHeldAdminDefiningRoleIds)");
  }

  // ── Scenario 9 (US-018 T-016, RC-25.1, RC-25.3): the caller's administrator status is current ─

  /**
   * RC-25.3 (harness C race case): a revoke of the caller's admin-defining role races the caller's
   * own admin-defining assign, and the assign must return 403.
   *
   * <p>Ordering is forced, not hoped for: thread A opens a transaction, revokes the caller's
   * custom admin-defining role (which takes the set lock) and holds that transaction open until
   * the assign is provably blocked on the lock ({@code performance_schema.data_lock_waits}); the
   * assign has by then created its snapshot (the tenant checks run before the lock), so M13 still
   * shows the caller as an administrator. When A commits, the assign's M11 returns the CURRENT
   * rows, in which the caller holds no admin-defining role, and A4 decides from them: 403
   * SELF_ASSIGNMENT. Decided from the snapshot the assign would have succeeded.
   */
  @Test
  void should_return403ForTheAssign_when_aRevokeOfTheCallersAdminDefiningRoleRacesTheirOwnAssign_RC253()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "rc253");
    User revoker = seedUser(tenantId, "rc253-revoker");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), revoker.getId(), revoker.getId());

    // The caller's ONLY admin status is this custom admin-defining role.
    Role callersRole = seedRole(tenantId, "RC253-CALLERS-ADMIN", "rc253");
    grantWholeCatalogue(callersRole.getId());
    User caller = seedUser(tenantId, "rc253-caller");
    seedActiveAdminAssignment(tenantId, callersRole.getId(), caller.getId(), revoker.getId());

    RoleChangeActor revokerActor = new RoleChangeActor(revoker.getId(), tenantId);
    RoleChangeActor callerActor = new RoleChangeActor(caller.getId(), tenantId);
    TransactionTemplate outer = new TransactionTemplate(transactionManager);

    java.util.concurrent.CountDownLatch revokeDone = new java.util.concurrent.CountDownLatch(1);
    ExecutorService executor = Executors.newFixedThreadPool(2);
    Future<?> revokeFuture =
        executor.submit(
            () ->
                outer.executeWithoutResult(
                    status -> {
                      roleAssignmentService.revoke(
                          revokerActor, caller.getId(), callersRole.getId(), requestContext());
                      revokeDone.countDown();
                      awaitALockWaiter();
                    }));
    Future<String> assignFuture =
        executor.submit(
            (Callable<String>)
                () -> {
                  assertThat(revokeDone.await(10, TimeUnit.SECONDS)).isTrue();
                  try {
                    roleAssignmentService.assign(
                        callerActor, caller.getId(), adminRole.getId(), requestContext());
                    return "ASSIGN_SUCCEEDED";
                  } catch (InsufficientPermissionException e) {
                    return "ASSIGN_" + e.getReason();
                  }
                });
    executor.shutdown();
    assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
    revokeFuture.get();

    assertThat(assignFuture.get())
        .as("the assign must be decided from M11's current rows, not the stale snapshot")
        .isEqualTo("ASSIGN_" + DenialReason.SELF_ASSIGNMENT);
    assertThat(
            jdbc.queryForObject(
                "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND revoked_at"
                    + " IS NULL",
                Integer.class,
                toBytes(caller.getId()),
                toBytes(adminRole.getId())))
        .as("the caller must not have become a TENANT_ADMIN")
        .isZero();
  }

  /** Waits (bounded) until some transaction is blocked on a row lock, then returns. */
  private void awaitALockWaiter() {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
    // performance_schema is not readable by nexus_app (least privilege), so the observer connects
    // as the container's root user.
    try (Connection observer =
            DriverManager.getConnection(
                mysqlContainer.getJdbcUrl(), "root", mysqlContainer.getPassword());
        Statement statement = observer.createStatement()) {
      while (System.nanoTime() < deadline) {
        try (ResultSet rs =
            statement.executeQuery("SELECT COUNT(*) FROM performance_schema.data_lock_waits")) {
          if (rs.next() && rs.getInt(1) > 0) {
            return;
          }
        }
        Thread.sleep(50);
      }
    } catch (SQLException e) {
      throw new IllegalStateException("could not observe data_lock_waits", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  // ── Shared seeding / assertion helpers ─────────────────────────────────────────────────

  private void assertBootstrapTenantAdminBaselineIsZero() {
    assertThat(countActiveAdminAssignments(BOOTSTRAP_TENANT_ID, BOOTSTRAP_TENANT_ADMIN_ROLE_ID))
        .as("bootstrap tenant must have zero active TENANT_ADMIN assignments before this test"
            + " seeds its own — a stray leftover row here (e.g. from another *IT not cleaning"
            + " up) would silently invalidate this test's 'the only active admin' premise")
        .isZero();
  }

  private User seedUser(UUID tenantId, String tag) {
    String email = "lal-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  /**
   * A tenant-scoped role literally named {@code TENANT_ADMIN} (matches {@code RbacRoleNames}).
   *
   * <p>US-018 T-001 fixture churn: the fixture {@code TENANT_ADMIN} carries the whole permission
   * catalogue, as a real one does (V5 seed plus the B7 footer from V6 on). Without it, A2's
   * grant-subset check would deny this admin every assignment of a permissioned role.
   */
  private Role seedTenantAdminRole(UUID tenantId, String tag) {
    Role role =
        roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "TENANT_ADMIN", tag, false));
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions",
        role.getId().toString());
    return role;
  }

  private UserRole seedActiveAdminAssignment(
      UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  // ── Harness C fixtures only (non-admin, permission-bearing roles) ─────────────────────

  /** A tenant-scoped role with the given literal name -- used by Harness C for the dangerous
   * custom role and the non-admin's own single-permission role (mirrors {@code
   * RoleRevocationSymmetryIT}'s identically-named helper). */
  private Role seedRole(UUID tenantId, String name, String tag) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, name, tag, false));
  }

  private void grantPermission(UUID roleId, UUID permissionId) {
    rolePermissionRepository.save(new RolePermission(roleId, permissionId));
  }

  /** Makes {@code roleId} admin-defining (ADR-0021 D3): attaches every catalogue permission. */
  private void grantWholeCatalogue(UUID roleId) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions",
        roleId.toString());
  }

  /** Generically-named alias of {@link #seedActiveAdminAssignment} for Harness C's non-admin-role
   * fixtures, so the misleading "Admin" in that method's name (retained, unrenamed, for the
   * pre-existing scenarios that already depend on it) is never used to seed a non-admin role. */
  private UserRole seedActiveAssignment(
      UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  /** Seeds a user holding exactly one permission, via a freshly created single-permission role
   * -- Harness C's non-admin {@code user:write} principal. */
  private User seedUserWithRole(UUID tenantId, String tag, String roleName, UUID permissionId) {
    User user = seedUser(tenantId, tag);
    Role role = seedRole(tenantId, roleName, tag);
    grantPermission(role.getId(), permissionId);
    seedActiveAssignment(tenantId, role.getId(), user.getId(), user.getId());
    return user;
  }

  /** Harness C: submits one revoke() thread to {@code executor}, awaiting {@code barrier} first.
   * Success is the only legitimate outcome for every call site this is used from, so nothing is
   * caught here -- any exception propagates through {@link Future#get()} and fails the test
   * loudly. */
  private Future<String> submitRevoke(
      ExecutorService executor, CyclicBarrier barrier, RoleChangeActor actor, UUID targetUserId,
      UUID roleId, String successOutcome) {
    return executor.submit(
        (Callable<String>)
            () -> {
              barrier.await(5, TimeUnit.SECONDS);
              roleAssignmentService.revoke(actor, targetUserId, roleId, requestContext());
              return successOutcome;
            });
  }

  /** Harness C: submits one assign() thread to {@code executor}, awaiting {@code barrier} first.
   * Catches ONLY {@link DuplicateRoleAssignmentException} (the legitimate duplicate-insert-race
   * outcome) -- any other exception propagates through {@link Future#get()} and fails the test
   * loudly. */
  private Future<String> submitAssign(
      ExecutorService executor, CyclicBarrier barrier, RoleChangeActor actor, UUID targetUserId,
      UUID roleId, String successOutcome, String conflictOutcome) {
    return executor.submit(
        (Callable<String>)
            () -> {
              barrier.await(5, TimeUnit.SECONDS);
              try {
                roleAssignmentService.assign(actor, targetUserId, roleId, requestContext());
                return successOutcome;
              } catch (DuplicateRoleAssignmentException e) {
                return conflictOutcome;
              }
            });
  }

  /** Harness C: submits one B8 replace thread, awaiting {@code barrier} first; nothing caught. */
  private Future<String> submitReplace(
      ExecutorService executor, CyclicBarrier barrier, RoleChangeActor actor, UUID roleId,
      Set<UUID> target, String ifMatch, String successOutcome) {
    return executor.submit(
        (Callable<String>)
            () -> {
              barrier.await(5, TimeUnit.SECONDS);
              roleManagementService.replaceRolePermissions(
                  actor, roleId, target, ifMatch, requestContext());
              return successOutcome;
            });
  }

  /** RC-57.4 (a): "OK", or the 403's reason; anything else propagates and fails the test. */
  private String replaceOutcome(
      RoleChangeActor actor, UUID roleId, Set<UUID> target, String ifMatch) {
    try {
      roleManagementService.replaceRolePermissions(
          actor, roleId, target, ifMatch, requestContext());
      return "OK";
    } catch (InsufficientPermissionException e) {
      return "DENIED_" + e.getReason();
    }
  }

  /**
   * A gate transaction holding the active {@code user_roles} rows of {@code roleIds} {@code FOR
   * UPDATE} through the index the set lock uses, so a set-lock verb queues on it.
   */
  private Connection lockAssignmentRows(UUID tenantId, UUID... roleIds) throws SQLException {
    Connection gate =
        DriverManager.getConnection(
            mysqlContainer.getJdbcUrl(), mysqlContainer.getUsername(), mysqlContainer.getPassword());
    gate.setAutoCommit(false);
    String placeholders = String.join(", ", java.util.Collections.nCopies(roleIds.length, "?"));
    try (java.sql.PreparedStatement lock =
        gate.prepareStatement(
            "SELECT id FROM user_roles FORCE INDEX (fk_user_roles_role_tenant) WHERE role_id IN ("
                + placeholders
                + ") AND tenant_id = ? AND revoked_at IS NULL FOR UPDATE")) {
      for (int i = 0; i < roleIds.length; i++) {
        lock.setBytes(i + 1, toBytes(roleIds[i]));
      }
      lock.setBytes(roleIds.length + 1, toBytes(tenantId));
      try (ResultSet rs = lock.executeQuery()) {
        assertThat(rs.next()).isTrue();
      }
    }
    return gate;
  }

  /** A gate transaction X-locking R's live role row with the statement attach and B8 use. */
  private Connection lockRoleRow(UUID tenantId, UUID roleId) throws SQLException {
    Connection gate =
        DriverManager.getConnection(
            mysqlContainer.getJdbcUrl(), mysqlContainer.getUsername(), mysqlContainer.getPassword());
    gate.setAutoCommit(false);
    try (java.sql.PreparedStatement lock =
        gate.prepareStatement(
            "SELECT id FROM roles WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL FOR UPDATE")) {
      lock.setBytes(1, toBytes(roleId));
      lock.setBytes(2, toBytes(tenantId));
      try (ResultSet rs = lock.executeQuery()) {
        assertThat(rs.next()).isTrue();
      }
    }
    return gate;
  }

  /**
   * A gate transaction X-locking R's {@code role_permissions} rows, so a B8 on R holds R's row (and
   * any set lock) and waits at its current read until the gate commits.
   */
  private Connection lockRolePermissionRows(UUID roleId) throws SQLException {
    Connection gate =
        DriverManager.getConnection(
            mysqlContainer.getJdbcUrl(), mysqlContainer.getUsername(), mysqlContainer.getPassword());
    gate.setAutoCommit(false);
    try (java.sql.PreparedStatement lock =
        gate.prepareStatement(
            "SELECT permission_id FROM role_permissions WHERE role_id = ? FOR UPDATE")) {
      lock.setBytes(1, toBytes(roleId));
      try (ResultSet rs = lock.executeQuery()) {
        assertThat(rs.next()).isTrue();
      }
    }
    return gate;
  }

  /** Waits (bounded) until at least {@code transactions} distinct transactions wait on a lock. */
  private void awaitLockWaiters(int transactions) throws SQLException, InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
    try (Connection observer =
            DriverManager.getConnection(
                mysqlContainer.getJdbcUrl(), "root", mysqlContainer.getPassword());
        Statement statement = observer.createStatement()) {
      while (System.nanoTime() < deadline) {
        try (ResultSet rs =
            statement.executeQuery(
                "SELECT COUNT(DISTINCT REQUESTING_ENGINE_TRANSACTION_ID)"
                    + " FROM performance_schema.data_lock_waits")) {
          if (rs.next() && rs.getInt(1) >= transactions) {
            return;
          }
        }
        Thread.sleep(5);
      }
    }
    throw new AssertionError("fewer than " + transactions + " transactions queued on a lock");
  }

  private Set<UUID> rolePermissionIds(UUID roleId) {
    return new HashSet<>(
        jdbc
            .queryForList(
                "SELECT permission_id FROM role_permissions WHERE role_id = ?",
                byte[].class,
                (Object) toBytes(roleId))
            .stream()
            .map(
                bytes -> {
                  ByteBuffer buf = ByteBuffer.wrap(bytes);
                  return new UUID(buf.getLong(), buf.getLong());
                })
            .toList());
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "LastAdminLockoutIT");
  }

  private int countActiveAdminAssignments(UUID tenantId, UUID roleId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE role_id = ? AND tenant_id = ? AND revoked_at"
                + " IS NULL",
            Integer.class,
            toBytes(roleId),
            toBytes(tenantId));
    return count == null ? 0 : count;
  }

  private boolean isActive(UUID userRoleId) {
    Timestamp revokedAt =
        jdbc.queryForObject(
            "SELECT revoked_at FROM user_roles WHERE id = ?", Timestamp.class, toBytes(userRoleId));
    return revokedAt == null;
  }

  /** RC-9.5 / D18: sample count recorded against {@code TIMER_LOCK_HOLD} for the given outcome. */
  private long timerCount(String timerName, String outcome) {
    var timer = meterRegistry.find(timerName).tag("outcome", outcome).timer();
    return timer == null ? 0L : timer.count();
  }

  /**
   * Test-cleanup-only bypass of the guard under test: force-revokes a row directly via JDBC so
   * bootstrap-tenant fixtures don't leak an active admin count into later tests. Never used to
   * assert production behavior.
   */
  private void forceRevokeDirectly(UUID userRoleId) {
    jdbc.update(
        "UPDATE user_roles SET revoked_at = NOW(6) WHERE id = ? AND revoked_at IS NULL",
        toBytes(userRoleId));
  }

  private List<String> captureHibernateSql(Runnable action) {
    Logger sqlLogger = (Logger) LoggerFactory.getLogger("org.hibernate.SQL");
    Level originalLevel = sqlLogger.getLevel();
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    sqlLogger.addAppender(appender);
    sqlLogger.setLevel(Level.DEBUG);
    try {
      action.run();
    } finally {
      sqlLogger.detachAppender(appender);
      sqlLogger.setLevel(originalLevel);
      appender.stop();
    }
    return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
  }

  /**
   * Locates the single captured SQL statement containing {@code marker} (case-insensitive, e.g.
   * {@code "for update"} for a PESSIMISTIC_WRITE, {@code "for share"} for a PESSIMISTIC_READ) —
   * fails loudly if zero or more than one statement matches, so a captured-SQL shape drift is
   * caught rather than silently EXPLAINing the wrong statement.
   */
  private String findCapturedStatement(List<String> emittedSql, String marker) {
    List<String> matches =
        emittedSql.stream().filter(sql -> sql.toLowerCase(Locale.ROOT).contains(marker)).toList();
    assertThat(matches)
        .as("exactly one captured statement must contain '" + marker + "': " + emittedSql)
        .hasSize(1);
    return matches.get(0);
  }

  /**
   * MC-1 (US-016 T-012): locates the single captured SQL statement matching ALL of {@code
   * requiredSubstrings} and NONE of {@code excludedSubstrings} (case-insensitive) — fails loudly
   * if zero or more than one statement matches, so ambiguous identification is caught rather than
   * silently asserting against the wrong statement. Identification is always POSITIVE (table/
   * column shape), never by lock-clause presence or absence, since none of M7/M8/M9 should ever
   * carry one — see {@link #should_neverEmitForShareOrForUpdate_when_capturingM7M8AndM9sSql()}'s
   * Javadoc for why each marker is unambiguous.
   */
  private String findStatementMatching(
      List<String> emittedSql, List<String> requiredSubstrings, List<String> excludedSubstrings) {
    List<String> matches =
        emittedSql.stream()
            .filter(
                sql -> {
                  String lower = sql.toLowerCase(Locale.ROOT);
                  return requiredSubstrings.stream().allMatch(lower::contains)
                      && excludedSubstrings.stream().noneMatch(lower::contains);
                })
            .toList();
    assertThat(matches)
        .as(
            "exactly one captured statement must match required="
                + requiredSubstrings
                + " excluded="
                + excludedSubstrings
                + ": "
                + emittedSql)
        .hasSize(1);
    return matches.get(0);
  }

  /** MC-1: asserts {@code sql} contains neither {@code for share} nor {@code for update}, case-insensitively. */
  private void assertNoLockingClause(String sql, String label) {
    String lower = sql.toLowerCase(Locale.ROOT);
    assertThat(lower)
        .as(label + " must never render a locking-read clause (MC-1, D5): " + sql)
        .doesNotContain("for share")
        .doesNotContain("for update");
  }

  /**
   * Runs {@code EXPLAIN} on a captured Hibernate SQL statement (still containing {@code ?}
   * placeholders) via {@link JdbcTemplate}, binding {@code params} positionally in the captured
   * statement's own parameter order, and returns only the {@code key} column — EXPLAIN's other
   * columns are MySQL-version-sensitive and this repo pins MySQL 8.4 via Testcontainers.
   */
  private String explainKey(String capturedSql, Object... params) {
    List<Map<String, Object>> plan = jdbc.queryForList("EXPLAIN " + capturedSql, params);
    assertThat(plan).as("EXPLAIN must return exactly one row: " + capturedSql).hasSize(1);
    return String.valueOf(plan.get(0).get("key"));
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
