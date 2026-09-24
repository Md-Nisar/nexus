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
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.RbacDangerousPermissions;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
// scheduled AuthEventRetryBuffer.drain job sharing the same pool.
@SpringBootTest(
    properties = {
      "nexus.rbac.denial-throttle.max-denials=100",
      "spring.datasource.hikari.maximum-pool-size=15"
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
  private static final UUID USER_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1803-7000-8000-000000000004");
  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private MeterRegistry meterRegistry;

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
   * {@code admin3}), one dangerous custom role ({@code CUSTOM-DANGEROUS}, carrying {@code
   * role:write} — a member of {@link com.example.nexus.rbac.domain.RbacDangerousPermissions})
   * with TWO existing holders, one non-admin {@code user:write}-only principal, and one benign,
   * permission-less role ({@code BENIGN}) with one existing holder. 11 threads fire
   * simultaneously via a {@link CyclicBarrier} split across BOTH verbs, both privileged
   * categories, and the privileged×benign case D7 newly makes relevant:
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
   *   <li>2× {@code revoke(CUSTOM-DANGEROUS)} by {@code admin1}, targeting its two distinct
   *       existing holders — name-match is false for this role, so M11's lock set is driven off
   *       {@code CUSTOM-DANGEROUS}'s own permissions, not the {@code TENANT_ADMIN} literal
   *       (§7.2); both succeed deterministically.
   *   <li>2× {@code assign(CUSTOM-DANGEROUS)} by {@code admin1}, both targeting the SAME fresh
   *       user — a duplicate-insert race (mirrors {@code ActiveAssignmentIT}'s own 8-way version
   *       of this pattern, scaled to 2): exactly one succeeds, the other gets {@link
   *       DuplicateRoleAssignmentException} (409 {@code RBAC_004}), never a raw {@code
   *       DataIntegrityViolationException} — {@code JpaUserRoleAssignmentAdapter#assign}
   *       synchronously flushes and translates it in the same try/catch.
   *   <li>1× {@code assign(CUSTOM-DANGEROUS)} by {@code admin1} against a THIRD, standalone
   *       target no other thread contends for — succeeds deterministically, adding a second
   *       independent concurrent {@code assign()} alongside the duplicate-race pair.
   *   <li>1× {@code revoke(TENANT_ADMIN)} by the non-admin {@code user:write} principal,
   *       targeting {@code admin1}'s OWN assignment (deliberately the one row no other thread
   *       ever touches, so this thread cannot race into a spurious 404) — denied with {@link
   *       InsufficientPermissionException} (403 {@code NOT_TENANT_ADMIN}). Because {@code
   *       nameMatch} is true for {@code TENANT_ADMIN}, this thread's transaction acquires M11's
   *       X lock over the WHOLE admin-equivalent role range BEFORE the gate denies it (D1/D7:
   *       lock acquisition precedes the authorization decision on both verbs, §6.3/§7.3) — this
   *       is deliberately the X-lock-then-403 path T-D11 names, run concurrently with every
   *       legitimate X-lock-then-success thread above, including the restored {@code
   *       assign(TENANT_ADMIN)} thread.
   *   <li>1× {@code assign(BENIGN)} by {@code admin1}, targeting {@code dangerousHolder1} — the
   *       SAME row a {@code revoke(CUSTOM-DANGEROUS)} thread above concurrently touches.
   *       {@code BENIGN} carries no permission and is not itself admin-equivalent, so it takes
   *       no M11 lock and sits outside every privileged lock set — this is the privileged×benign
   *       case RC-20.6 requires: proving no cycle forms through {@code fk_user_roles_user} even
   *       though both transactions touch the same user row.
   *   <li>1× {@code revoke(BENIGN)} by {@code admin1}, targeting {@code admin3} — the SAME row a
   *       {@code revoke(TENANT_ADMIN)} thread above concurrently touches. Same purpose as the
   *       previous item, exercised on the revoke side.
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

    Role dangerousRole = seedRole(tenantId, "CUSTOM-DANGEROUS", "mixed");
    grantPermission(dangerousRole.getId(), ROLE_WRITE_PERMISSION_ID);
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

    // BENIGN carries no permission at all, so it is never admin-equivalent regardless of who
    // holds it -- RC-20.6's privileged x benign fixture, seeded on admin3 (a row a privileged
    // revoke thread below also touches) so the benign revoke thread races that same row.
    Role benignRole = seedRole(tenantId, "BENIGN", "mixed");
    seedActiveAssignment(tenantId, benignRole.getId(), admin3.getId(), admin1.getId());

    RoleChangeActor adminActor = new RoleChangeActor(admin1.getId(), tenantId);
    RoleChangeActor nonAdminActor = new RoleChangeActor(nonAdminUser.getId(), tenantId);

    int threadCount = 11;
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

    // 4-5: revoke(CUSTOM-DANGEROUS) on two distinct existing holders -- both succeed
    // deterministically; M11's privileged-path lock covers this role too (D7), unlike the
    // shipped design which never locked it on this path at all.
    futures.add(submitRevoke(executor, barrier, adminActor, dangerousHolder1.getId(),
        dangerousRole.getId(), "REVOKE_DANGEROUS_SUCCESS"));
    futures.add(submitRevoke(executor, barrier, adminActor, dangerousHolder2.getId(),
        dangerousRole.getId(), "REVOKE_DANGEROUS_SUCCESS"));

    // 6-7: assign(CUSTOM-DANGEROUS) duplicate-insert race -- exactly one winner, one conflict.
    futures.add(submitAssign(executor, barrier, adminActor, newDangerousCandidate.getId(),
        dangerousRole.getId(), "ASSIGN_DANGEROUS_SUCCESS", "ASSIGN_DANGEROUS_CONFLICT"));
    futures.add(submitAssign(executor, barrier, adminActor, newDangerousCandidate.getId(),
        dangerousRole.getId(), "ASSIGN_DANGEROUS_SUCCESS", "ASSIGN_DANGEROUS_CONFLICT"));

    // 8: assign(CUSTOM-DANGEROUS) against a THIRD, standalone target -- no other thread contends
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
    // revokes CUSTOM-DANGEROUS from. BENIGN carries no permission, takes no M11 lock, and sits
    // outside every privileged lock set -- the privileged x benign case (RC-20.6, §7.3).
    futures.add(submitAssign(executor, barrier, adminActor, dangerousHolder1.getId(),
        benignRole.getId(), "ASSIGN_BENIGN_SUCCESS", "ASSIGN_BENIGN_CONFLICT"));

    // 11: revoke(BENIGN) targeting admin3 -- the SAME row thread 2 concurrently revokes
    // TENANT_ADMIN from. Same purpose as thread 10, exercised on the revoke side.
    futures.add(submitRevoke(executor, barrier, adminActor, admin3.getId(), benignRole.getId(),
        "REVOKE_BENIGN_SUCCESS"));

    executor.shutdown();
    boolean terminated = executor.awaitTermination(15, TimeUnit.SECONDS);
    assertThat(terminated).as("all 11 threads must complete within the timeout").isTrue();

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
        .as("both distinct-holder CUSTOM-DANGEROUS revokes must succeed: " + counts).isEqualTo(2);
    assertThat(counts.getOrDefault("ASSIGN_DANGEROUS_SUCCESS", 0))
        .as("the duplicate-race winner plus the standalone assign must both succeed: " + counts)
        .isEqualTo(2);
    assertThat(counts.getOrDefault("ASSIGN_DANGEROUS_CONFLICT", 0))
        .as("exactly one of the two duplicate dangerous-role assigns must conflict: " + counts)
        .isEqualTo(1);
    assertThat(counts.getOrDefault("DENIED", 0))
        .as("the non-admin's revoke(TENANT_ADMIN) attempt must be denied: " + counts).isEqualTo(1);
    assertThat(counts.getOrDefault("ASSIGN_BENIGN_SUCCESS", 0))
        .as("the benign assign against a concurrently-touched privileged row must succeed: "
            + counts).isEqualTo(1);
    assertThat(counts.getOrDefault("REVOKE_BENIGN_SUCCESS", 0))
        .as("the benign revoke against a concurrently-touched privileged row must succeed: "
            + counts).isEqualTo(1);
    assertThat(counts.values().stream().mapToInt(Integer::intValue).sum())
        .as("every thread must resolve to one of the expected outcomes for its role: " + counts)
        .isEqualTo(threadCount);
    assertThat(countActiveAdminAssignments(tenantId, adminRole.getId()))
        .as("the tenant must retain exactly admin1 and the newly-assigned admin candidate as its"
            + " two remaining active admins after the race (admin2/admin3 both legitimately"
            + " revoked; the restored assign(TENANT_ADMIN) thread adds one -- see Javadoc, D7)")
        .isEqualTo(2);
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
   * asserting {@code key = fk_user_roles_role} (the FK index name — confirmed against
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
        .isEqualTo("fk_user_roles_role");
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

  // ── Scenario 6: MC-5 — EXPLAIN the ACTUAL captured SQL for both M11 and M5 ────────────

  /**
   * RC-9.1 / 03-design.md §7.2 step 1 + §11.2 MC-5, D8. D8's containment proof ("every lock M5
   * requests is already held by M11") is a property of the chosen execution plan, not the
   * predicates — InnoDB locks index records, not logical rows. M11 drives off {@code
   * fk_user_roles_role} by its own Javadoc; M5's predicate ({@code userId AND roleId AND
   * tenantId AND revokedAt IS NULL}) could let the optimizer choose {@code fk_user_roles_role},
   * {@code fk_user_roles_user}, or {@code uq_user_role_active} — only the former satisfies
   * containment. Unlike {@link #should_pinQueryPlanToFkIndex_and_emitForUpdate_when_lockingTenantAdminAssignments()}
   * (M11 only, reconstructed native SQL), this scenario captures the REAL Hibernate-emitted SQL
   * for both M11 and M5 via {@link #captureHibernateSql} from one {@code revoke()} call — a
   * self-revocation of a {@code TENANT_ADMIN} role with two active admins, which exercises M11
   * (the lockout set lock, superseding the removed M1 this scenario originally pinned), then M8
   * (unlocked), then M5 (the gate's live-admin check) — and EXPLAINs each captured statement,
   * asserting only the {@code key} column (EXPLAIN's other columns are MySQL-version-sensitive;
   * this repo pins MySQL 8.4 via Testcontainers).
   *
   * <p><strong>If M5's key is ever observed to NOT be {@code fk_user_roles_role}, do not relax
   * this assertion.</strong> That is a real gap in D8's containment proof requiring either a
   * predicate reorder / index hint on M5, or a written non-contained-acquisition analysis in
   * design §7.2/§7.3 plus a harness C re-run — an Architect-level escalation.
   */
  @Test
  void should_driveBothM11AndM5OffTheRoleIndex_when_explainingCapturedLockingReads()
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
    // (JpaUserRoleRepository#lockActiveAssignmentHoldersByRoles; supersedes the removed M1).
    String m1Sql = findCapturedStatement(emittedSql, "for update");
    // M5 -- PESSIMISTIC_READ renders "for share" (JpaUserRoleRepository#lockActiveAdminAssignment,
    // its own Javadoc). No other query on this call path is locked (M7 is short-circuited by
    // nameMatch; M8 is a plain unlocked read), so this marker is unambiguous.
    String m5Sql = findCapturedStatement(emittedSql, "for share");

    // M11's JPQL bind order: roleIds, tenantId (revokedAt IS NULL has no parameter) -- same
    // position as the removed M1's roleId/tenantId order it superseded.
    assertThat(explainKey(m1Sql, toBytes(adminRole.getId()), toBytes(tenantId)))
        .as("M11 must drive off the FK index on role_id: " + m1Sql)
        .isEqualTo("fk_user_roles_role");

    // M5's JPQL bind order: userId, roleId, tenantId.
    assertThat(
            explainKey(
                m5Sql, toBytes(admin1.getId()), toBytes(adminRole.getId()), toBytes(tenantId)))
        .as(
            "M5 must ALSO drive off fk_user_roles_role for D2's §7.2 containment proof to hold"
                + " -- if this fails, escalate per 03-design.md §7.2 step 1, do not relax this"
                + " assertion: "
                + m5Sql)
        .isEqualTo("fk_user_roles_role");

    // US-017 T-006(b), MC-A (extended): M11 must acquire no JOIN at all (never widening the lock
    // beyond user_roles by joining roles/permissions) -- design §11.2 MC-A, port Javadoc.
    assertThat(m1Sql.toLowerCase(Locale.ROOT))
        .as("M11 must not join roles or permissions -- lock-scope discipline: " + m1Sql)
        .doesNotContain(" join ");
    // US-017 T-006(b), MC-A (extended): M5b (the widened M5) MUST keep FORCE INDEX so every
    // index record it requests is inside M11's X region (D8's containment proof).
    assertThat(m5Sql.toLowerCase(Locale.ROOT))
        .as("M5b must keep FORCE INDEX (fk_user_roles_role): " + m5Sql)
        .contains("force index");
  }

  // ── Scenario 6b (US-017 T-006(b), 03-design.md §11.2 MC-A extended): M10 non-locking ────

  /**
   * MC-A extended: M10 ({@code findPermissionNamesForTenantRoles}, hosted on {@code
   * JpaRoleRepository#findPermissionNamesByTenantRoles}) touches {@code permissions}, on which
   * {@code nexus_app} holds {@code SELECT} only (03-design.md §5.2) -- a {@code @Lock}
   * accidentally added here would be REJECTED IN PRODUCTION but PASS every Testcontainers IT
   * (every IT connects as the container superuser). Identified positively by requiring BOTH
   * {@code role_permissions} (excludes M7, which never joins on tenant) AND {@code tenant_id}
   * (excludes {@code findRole}'s plain by-id entity load, which selects the {@code tenant_id}
   * column but never predicates on it) in the same captured statement -- unambiguous within one
   * {@code revoke()} call of a dangerous, non-name-match custom role.
   */
  @Test
  void should_neverEmitForShareOrForUpdate_when_capturingM10sSql_MCA() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "mca10");
    User admin = seedUser(tenantId, "mca10-admin");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    Role dangerousRole = seedRole(tenantId, "MCA10-CUSTOM-DANGEROUS", "mca10");
    grantPermission(dangerousRole.getId(), ROLE_WRITE_PERMISSION_ID);
    User holder1 = seedUser(tenantId, "mca10-holder1");
    User holder2 = seedUser(tenantId, "mca10-holder2");
    seedActiveAssignment(tenantId, dangerousRole.getId(), holder1.getId(), admin.getId());
    seedActiveAssignment(tenantId, dangerousRole.getId(), holder2.getId(), admin.getId());

    RoleChangeActor actor = new RoleChangeActor(admin.getId(), tenantId);
    List<String> emittedSql =
        captureHibernateSql(
            () ->
                roleAssignmentService.revoke(
                    actor, holder1.getId(), dangerousRole.getId(), requestContext()));

    String m10Sql = findStatementMatching(emittedSql, List.of("role_permissions", "tenant_id"), List.of());
    assertNoLockingClause(m10Sql, "M10 (findPermissionNamesForTenantRoles)");
  }

  // ── Scenario 6c (US-017 T-006(b), 03-design.md §11.2 MC-A extended): FR-2 non-locking ───

  /**
   * MC-A extended: FR-2's two health-indicator support queries ({@code
   * findTenantsWithAFullyAdminEquivalentRole}, {@code findTenantsWithActiveFullyAdminEquivalentHolders}
   * -- renamed from the ANY-based originals post-06-code-review.md H-1, 2026-09-24) both join
   * {@code role_permissions}/{@code permissions} -- same {@code SELECT}-only grant concern as M10
   * above, now exercised on the health-check cadence rather than the privileged assign/revoke
   * path. Invoked directly against the autowired repository bean, capturing both statements from
   * one action.
   */
  @Test
  void should_neverEmitForShareOrForUpdate_when_capturingFR2sTwoQueries_MCA() throws Exception {
    long dangerousNamesCount = RbacDangerousPermissions.NAMES.size();
    List<String> emittedSql =
        captureHibernateSql(
            () -> {
              userRoleRepository.findTenantsWithAFullyAdminEquivalentRole(
                  RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, dangerousNamesCount);
              userRoleRepository.findTenantsWithActiveFullyAdminEquivalentHolders(
                  RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, dangerousNamesCount);
            });

    assertThat(emittedSql).as("FR-2's two queries, captured from one action").hasSize(2);
    assertNoLockingClause(emittedSql.get(0), "FR-2(a) findTenantsWithAFullyAdminEquivalentRole");
    assertNoLockingClause(
        emittedSql.get(1), "FR-2(b) findTenantsWithActiveFullyAdminEquivalentHolders");
  }

  // ── Scenario 6e (US-017 T-006(c), 03-design.md §11.2 MC-C, RC-20.7): plan stability ─────

  /**
   * MC-C (re-derived MC-5): D6's deadlock-freedom argument and D8's containment proof both depend
   * on the CHOSEN PLAN, not merely the predicate -- InnoDB locks index records, and a full-scan
   * fallback would acquire in primary-key order, breaking both arguments. A 1-element and a
   * 40-element IN-list can be costed differently by the optimizer, so this asserts {@code key =
   * fk_user_roles_role} for M11 and M5b at IN-list sizes 1, 2 and >= 20 -- plan stability across
   * cardinalities, not one lucky fixture size.
   *
   * <p><b>If this is ever observed to select a different key at any cardinality, do not relax
   * this assertion</b> -- escalate per 03-design.md §7.2/§11.2, exactly as the shipped MC-5
   * predecessor instructs for M5 (Risk (c)).
   */
  @Test
  void should_pinKeyToFkUserRolesRole_acrossInListCardinalities_forM11AndM5b_MCC() {
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
          .as("M11 must drive off fk_user_roles_role at IN-list size " + size)
          .isEqualTo("fk_user_roles_role");
      assertThat(explainM5bKey(admin1.getId(), roleIds, tenantId))
          .as("M5b must drive off fk_user_roles_role at IN-list size " + size)
          .isEqualTo("fk_user_roles_role");
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
            "EXPLAIN SELECT * FROM user_roles FORCE INDEX (fk_user_roles_role) WHERE role_id IN ("
                + placeholders + ") AND tenant_id = ? AND revoked_at IS NULL FOR UPDATE",
            params.toArray());
    assertThat(plan).hasSize(1);
    return String.valueOf(plan.get(0).get("key"));
  }

  /** MC-C helper: EXPLAINs M5b's shape ({@code lockActiveAssignmentOfAnyRole}) at the given IN-list. */
  private String explainM5bKey(UUID userId, List<UUID> roleIds, UUID tenantId) {
    String placeholders = String.join(",", java.util.Collections.nCopies(roleIds.size(), "?"));
    List<Object> params = new ArrayList<>();
    params.add(toBytes(userId));
    roleIds.forEach(id -> params.add(toBytes(id)));
    params.add(toBytes(tenantId));
    List<Map<String, Object>> plan =
        jdbc.queryForList(
            "EXPLAIN SELECT * FROM user_roles FORCE INDEX (fk_user_roles_role) WHERE user_id = ?"
                + " AND role_id IN (" + placeholders + ") AND tenant_id = ? AND revoked_at IS"
                + " NULL FOR SHARE",
            params.toArray());
    assertThat(plan).hasSize(1);
    return String.valueOf(plan.get(0).get("key"));
  }

  // ── Scenario 7 (US-016 T-012, 03-design.md §11.2 MC-1): M7/M8/M9 non-locking ────────────

  /**
   * US-016 T-012 / 03-design.md §11.2 MC-1, D5: mechanical proof that M7 ({@code
   * findPermissionNamesForRole}), M8 ({@code findRoleIdByName}, {@link RoleAssignmentService}'s
   * call site) and M9's new caller ({@code findActiveUserIdsForRole}, from {@link
   * RoleManagementService#attachPermission}) never render {@code for share} or {@code for
   * update}. {@code nexus_app} holds {@code SELECT} only on {@code permissions} (03-design.md
   * §5.2) — MySQL requires {@code SELECT} plus one of {@code DELETE}/{@code LOCK TABLES}/{@code
   * UPDATE} to execute a locking read, so a {@code @Lock} accidentally added to any of these three
   * would be REJECTED IN PRODUCTION but PASS every Testcontainers IT (every IT connects as the
   * container superuser). Code review alone cannot see this failure mode; this test makes it
   * mechanical.
   *
   * <p><b>Flow A</b> — {@code assign()} of a non-name-match dangerous custom role, by a non-admin
   * actor: {@code nameMatch} is false, so {@code carriesDangerousPermission} runs M7; because the
   * role is privileged, {@code requireActiveTenantAdmin} then runs M8 ({@code findRoleIdByName})
   * before denying — one call captures both. <b>Flow B</b> — {@code attachPermission()} of a
   * dangerous permission, by an actor who genuinely holds an active {@code TENANT_ADMIN}
   * assignment (so AC11's gate passes and the insert is reached): triggers M9's new call site.
   *
   * <p><b>Statements are identified positively, never via lock-clause absence</b> (a brittle
   * full-string assertion would fail on unrelated Hibernate formatting changes — MC-1's own stated
   * risk, 03-design.md §11.2): M7 by the {@code role_permissions} table, unique to that statement
   * in Flow A's capture; M8 by the single-column {@code roles} projection ({@code "id from
   * roles"}, no trailing comma after {@code id}), distinguishing it from the earlier plain {@code
   * findById(roleId)} entity load in the same flow (which selects every column, so {@code id} is
   * always followed by a comma there); M9 by the {@code user_roles} table excluding {@code FORCE
   * INDEX} (Flow B's only other {@code user_roles} statement is the pre-existing, {@code FORCE
   * INDEX}-driven {@code FOR SHARE} admin-check, which is not new and not asserted on here).
   *
   * <p><b>No new privilege-level IT is required</b> in the {@code RolePermissionsPrivilegeIT} /
   * {@code UserRolesPrivilegeIT} family (03-design.md §5.2: "Because no locking read is proposed
   * on any new path, no new privilege-level IT ... is required"). Those two classes already prove
   * {@code nexus_app}'s grant boundary directly via raw JDBC (SELECT-only on {@code permissions},
   * no UPDATE on {@code roles}/{@code role_permissions}, column-scoped grant on {@code
   * user_roles}); this test proves the ORM-emitted SQL for M7/M8/M9 never attempts to exercise a
   * locking grant in the first place. Together they close the loop — neither alone would — but no
   * <em>new</em> DB-privilege boundary is opened by M7/M8/M9, since none of them acquires a lock.
   *
   * <p><b>Mutation check performed and reverted (T-012 DoD).</b> A temporary {@code
   * @Lock(LockModeType.PESSIMISTIC_READ)} was added to {@code
   * JpaRoleRepository#findPermissionNamesByRole} (M7's query), confirmed to fail this test, then
   * reverted.
   */
  @Test
  void should_neverEmitForShareOrForUpdate_when_capturingM7M8AndM9sSql() throws Exception {
    // ── Flow A: assign() of a non-name-match dangerous custom role, denied for a non-admin ──
    UUID tenantA = uuidGenerator.newId();
    seedTenantAdminRole(tenantA, "mc1a"); // exists so M8 is non-empty; nobody holds it here
    Role dangerousRole = seedRole(tenantA, "MC1-CUSTOM-DANGEROUS", "mc1a");
    grantPermission(dangerousRole.getId(), ROLE_WRITE_PERMISSION_ID);
    User nonAdminActor = seedUser(tenantA, "mc1a-actor");
    User target = seedUser(tenantA, "mc1a-target");
    RoleChangeActor actorA = new RoleChangeActor(nonAdminActor.getId(), tenantA);

    List<String> flowASql =
        captureHibernateSql(
            () ->
                assertThatThrownBy(
                        () ->
                            roleAssignmentService.assign(
                                actorA, target.getId(), dangerousRole.getId(), requestContext()))
                    .isInstanceOf(InsufficientPermissionException.class));

    // Excludes "tenant_id": M10's new tenant-scoped bulk read (also touching role_permissions,
    // via requireActiveTenantAdmin's admin-equivalence check on this same non-admin actor) has a
    // r.tenantId predicate that M7's per-role query does not -- without this exclusion both
    // statements match and findStatementMatching's uniqueness assertion fails.
    String m7Sql =
        findStatementMatching(flowASql, List.of("role_permissions"), List.of("tenant_id"));
    String m8Sql = findStatementMatching(flowASql, List.of("id from roles"), List.of());

    assertNoLockingClause(m7Sql, "M7 (findPermissionNamesForRole)");
    assertNoLockingClause(m8Sql, "M8 (findRoleIdByName)");

    // ── Flow B: attachPermission() of a dangerous permission, by a genuine active admin ──
    UUID tenantB = uuidGenerator.newId();
    Role adminRoleB = seedTenantAdminRole(tenantB, "mc1b");
    User adminActorUser = seedUser(tenantB, "mc1b-admin");
    seedActiveAdminAssignment(
        tenantB, adminRoleB.getId(), adminActorUser.getId(), adminActorUser.getId());
    Role customRole = seedRole(tenantB, "MC1-ATTACH-TARGET", "mc1b");
    RoleChangeActor adminActor = new RoleChangeActor(adminActorUser.getId(), tenantB);

    List<String> flowBSql =
        captureHibernateSql(
            () ->
                roleManagementService.attachPermission(
                    adminActor, customRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext()));

    String m9Sql = findStatementMatching(flowBSql, List.of("user_roles"), List.of("force index"));
    assertNoLockingClause(m9Sql, "M9 (findActiveUserIdsForRole, new caller)");
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

  /** A tenant-scoped role literally named {@code TENANT_ADMIN} (matches {@code RbacRoleNames}). */
  private Role seedTenantAdminRole(UUID tenantId, String tag) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "TENANT_ADMIN", tag, false));
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
