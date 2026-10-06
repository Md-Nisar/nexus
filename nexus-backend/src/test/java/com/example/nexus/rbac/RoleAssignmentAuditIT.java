package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.identity.application.service.SecureEventService;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.audit.RbacAuthEventAdapter;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.IllegalTransactionStateException;

/**
 * US-012 T-021 (04-tasks.md; 03-design.md §6.3-§6.4; 03b-threat-model.md T-T5) / US-018 T-006
 * (04-tasks.md M4; design §6.2, TS-5): the sole automated, end-to-end proof — against real
 * Testcontainers MySQL, never H2 — that {@link RbacAuthEventAdapter}'s audit write (a) actually
 * round-trips a valid, correctly-keyed JSON {@code metadata} payload through MySQL's native {@code
 * JSON} column (T-T5), and (b) that a genuine, real-MySQL Group A (atomic) audit-write failure
 * rolls back the role-change mutation it accompanies (US-018 A6/TS-5), not merely against a mocked
 * {@link SecureEventService} — that is {@code RbacAuthEventAdapterTest}'s job and is
 * <b>deliberately not re-duplicated here</b>.
 *
 * <p><b>Scope discipline:</b> {@code RbacAuthEventAdapterTest} already exhaustively covers the
 * field-mapping table and the full adversarial {@code roleName} matrix (quote, backslash, newline,
 * control character, lone surrogate, JSON-shaped payload, and the duplicate-key {@code traceId}
 * case) against a mocked {@link SecureEventService}. This class does not repeat that matrix; it
 * picks two representative adversarial cases and proves they round-trip correctly through
 * <b>MySQL's own</b> {@code JSON_VALID()}/{@code JSON_EXTRACT()} — something a mock cannot verify,
 * because MySQL's binary JSON type normalises key order and validates JSON syntax at the storage
 * layer (03b-threat-model.md T-T1/T-T5).
 *
 * <p><b>TS-5 mechanism (US-018 A6):</b> a test-only {@code BEFORE INSERT} trigger on {@code
 * auth_events}, installed and dropped per-test, {@code SIGNAL}s only for the one RBAC success
 * {@code event_type} under test — a genuine MySQL-level rejection of the Group A audit insert,
 * surfacing exactly where {@code SecureEventService#recordEventInCurrentTransaction}'s {@code
 * saveAndFlush} runs, inside the caller's own transaction. Because {@link RbacAuditPort}'s Group A
 * methods now join that transaction and MUST THROW on failure (design §6.2), this failure
 * propagates out of {@link RoleAssignmentService#assign}/{@code revoke} itself and rolls back the
 * {@code user_roles} INSERT/UPDATE alongside the blocked audit row — never a half-atomic result.
 * This replaces the pre-A6 mechanism (a merge-at-commit collision caught by the old best-effort
 * swallow, which the old audit contract required and the new one forbids on this path).
 *
 * <p><b>Tested at the SERVICE layer for scenarios 1-4</b> (see {@link RoleAssignmentIT}'s Javadoc
 * for the rationale) — {@link RoleAssignmentService} is autowired directly, so its real,
 * Spring-wired {@link com.example.nexus.rbac.application.port.out.RbacAuditPort} (the real {@link
 * RbacAuthEventAdapter} bean) is exercised end-to-end against real MySQL, not a mock.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RoleAssignmentAuditIT {

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private SecureEventService secureEventService;

  // ── Scenario 1: successful assign writes a correctly-keyed ROLE_ASSIGNED row ──────────

  @Test
  void should_writeValidRoleAssignedEventWithCorrectFields_when_assignSucceeds() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-assign-actor", tenantId);
    grantUserRoleAssign(tenantId, actorUser.getId());
    User target = seedUser("audit-assign-target", tenantId);
    Role role = seedRole("AUDIT-ASSIGN", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    RequestContext ctx = requestContext();

    roleAssignmentService.assign(actor, target.getId(), role.getId(), ctx);

    Map<String, Object> row = findLatestAuditRow(target.getId(), "ROLE_ASSIGNED");
    assertThat(((Number) row.get("valid")).intValue())
        .as("metadata must be valid JSON per MySQL's own JSON_VALID(), never asserted via string"
            + " equality (binary JSON normalises key order)")
        .isEqualTo(1);
    // Load-bearing (US-014 T-T8 item 5): only guard, at the real-MySQL level, that a successful
    // assign still writes outcome=SUCCESS after record(...) was parameterised with an outcome
    // argument (RbacAuthEventAdapter). See also RbacAuthEventAdapterTest's mirrored assertion.
    assertThat(row.get("outcome")).isEqualTo("SUCCESS");
    assertThat(toUuid((byte[]) row.get("user_id")))
        .as("event user_id must be the TARGET user, not the actor")
        .isEqualTo(target.getId());
    assertThat(toUuid((byte[]) row.get("tenant_id"))).isEqualTo(tenantId);
    assertThat(row.get("role_id")).isEqualTo(role.getId().toString());
    assertThat(row.get("role_name")).isEqualTo(role.getName());
    assertThat(row.get("assigned_by"))
        .as("assignedBy must be the ACTOR")
        .isEqualTo(actorUser.getId().toString());
    assertThat(row.get("revoked_by")).isNull();
    assertThat(row.get("trace_id")).isEqualTo(ctx.traceId());
  }

  // ── Scenario 2: successful revoke writes revokedBy instead of assignedBy ───────────────

  @Test
  void should_writeValidRoleRevokedEventWithRevokedByField_when_revokeSucceeds() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-revoke-actor", tenantId);
    grantUserRoleAssign(tenantId, actorUser.getId());
    User target = seedUser("audit-revoke-target", tenantId);
    Role role = seedRole("AUDIT-REVOKE", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    roleAssignmentService.assign(actor, target.getId(), role.getId(), requestContext());

    roleAssignmentService.revoke(actor, target.getId(), role.getId(), requestContext());

    Map<String, Object> row = findLatestAuditRow(target.getId(), "ROLE_REVOKED");
    assertThat(((Number) row.get("valid")).intValue()).isEqualTo(1);
    // Load-bearing (US-014 T-T8 item 5) -- see the comment in
    // should_writeValidRoleAssignedEventWithCorrectFields_when_assignSucceeds above.
    assertThat(row.get("outcome")).isEqualTo("SUCCESS");
    assertThat(row.get("revoked_by"))
        .as("revokedBy must be the ACTOR")
        .isEqualTo(actorUser.getId().toString());
    assertThat(row.get("assigned_by"))
        .as("a ROLE_REVOKED event must never carry an assignedBy key")
        .isNull();
  }

  // ── Scenario 3 (T-T5): adversarial roleName round-trip against real MySQL ──────────────

  static Stream<Arguments> adversarialRoleNames() {
    return Stream.of(
        // Representative case 1: a double-quote and a backslash together — the two JSON
        // structural characters an escaper must handle correctly.
        Arguments.of("quoteAndBackslash", "TENANT\"ADMIN\\ESCAPE"),
        // Representative case 2: a duplicate-key injection attempt targeting traceId, NOT
        // assignedBy. Metadata keys are emitted traceId, roleId, roleName, assignedBy
        // (03-design.md §6.3) — a forged key injected via roleName lands AFTER the real traceId
        // but BEFORE the real assignedBy. MySQL keeps the LAST duplicate key, so a forged
        // assignedBy would always lose to the real trailing one regardless of whether escaping
        // works — that variant is not discriminating. A forged traceId would WIN if escaping
        // were broken, since it comes after the real one; only targeting traceId actually
        // proves the escaper works (per 03b-threat-model.md T-T5's own key-ordering analysis).
        Arguments.of("duplicateKeyInjection", "x\",\"traceId\":\"forged"));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("adversarialRoleNames")
  void should_roundTripAdversarialRoleNameAsLiteralStringValue_when_assigningAgainstRealMySql(
      String label, String roleName) {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-adv-actor-" + label, tenantId);
    grantUserRoleAssign(tenantId, actorUser.getId());
    User target = seedUser("audit-adv-target-" + label, tenantId);
    // roles.name is VARCHAR(64), unique per (tenant_id, name) — a fresh tenant per case means
    // no collision risk without needing to append random suffixes to the adversarial literal.
    Role role =
        roleRepository.save(new Role(uuidGenerator.newId(), tenantId, roleName, null, false));
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    RequestContext ctx = requestContext();

    roleAssignmentService.assign(actor, target.getId(), role.getId(), ctx);

    Map<String, Object> row = findLatestAuditRow(target.getId(), "ROLE_ASSIGNED");
    assertThat(((Number) row.get("valid")).intValue())
        .as("metadata must remain valid JSON even with an adversarial roleName: " + roleName)
        .isEqualTo(1);
    assertThat(row.get("role_name"))
        .as("roleName must round-trip as the LITERAL string value — never interpreted as JSON"
            + " structure")
        .isEqualTo(roleName);
    assertThat(row.get("assigned_by"))
        .as("assignedBy in the extracted JSON must remain the REAL actor id, never overridden by"
            + " an injected value embedded inside roleName")
        .isEqualTo(actorUser.getId().toString());
    assertThat(row.get("trace_id"))
        .as("traceId in the extracted JSON must remain the REAL trace id, never overridden by the"
            + " duplicateKeyInjection case's forged trailing traceId")
        .isEqualTo(ctx.traceId());
  }

  // ── Scenario 4: no audit row on a rolled-back (403/409) request ────────────────────────

  @Test
  void should_writeNoAuditRow_when_assignFailsWithCrossTenantTarget() {
    UUID actorTenantId = uuidGenerator.newId();
    UUID targetTenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-403-actor", actorTenantId);
    grantUserRoleAssign(actorTenantId, actorUser.getId());
    User target = seedUser("audit-403-target", targetTenantId);
    Role role = seedRole("AUDIT-403", actorTenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), actorTenantId);

    assertThatThrownBy(
            () ->
                roleAssignmentService.assign(
                    actor, target.getId(), role.getId(), requestContext()))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    assertThat(countAuditRows(target.getId(), "ROLE_ASSIGNED"))
        .as("a rolled-back 403 must never write a ROLE_ASSIGNED audit row — side effects are"
            + " after-commit only")
        .isZero();
  }

  @Test
  void should_writeExactlyOneAuditRow_notTwo_when_secondAssignFailsWithDuplicate() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-409-actor", tenantId);
    grantUserRoleAssign(tenantId, actorUser.getId());
    User target = seedUser("audit-409-target", tenantId);
    Role role = seedRole("AUDIT-409", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    roleAssignmentService.assign(actor, target.getId(), role.getId(), requestContext());

    assertThatThrownBy(
            () ->
                roleAssignmentService.assign(
                    actor, target.getId(), role.getId(), requestContext()))
        .isInstanceOf(DuplicateRoleAssignmentException.class);

    assertThat(countAuditRows(target.getId(), "ROLE_ASSIGNED"))
        .as("the rolled-back duplicate attempt must not add a second ROLE_ASSIGNED row")
        .isEqualTo(1);
  }

  @Test
  void should_writeNoSecondRevokedRow_when_revokingAlreadyRevokedAssignment() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-404-actor", tenantId);
    grantUserRoleAssign(tenantId, actorUser.getId());
    User target = seedUser("audit-404-target", tenantId);
    Role role = seedRole("AUDIT-404", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    roleAssignmentService.assign(actor, target.getId(), role.getId(), requestContext());
    roleAssignmentService.revoke(actor, target.getId(), role.getId(), requestContext());

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, target.getId(), role.getId(), requestContext()))
        .isInstanceOf(com.example.nexus.common.domain.ResourceNotFoundException.class);

    assertThat(countAuditRows(target.getId(), "ROLE_REVOKED"))
        .as("a rolled-back 404 (already revoked) must not add a second ROLE_REVOKED row")
        .isEqualTo(1);
  }

  // ── US-014 AC4: a ROLE_ASSIGNMENT_DENIED row survives the caller's TX1 rollback ─────────
  // ── (read AFTER assertThatThrownBy completes -- the only proof the REQUIRES_NEW write ───
  // ── actually committed; a Mockito verify would prove nothing about durability) ──────────

  @Test
  void should_writeRoleAssignmentDeniedRow_when_assignFailsWithCrossTenantTarget() {
    UUID actorTenantId = uuidGenerator.newId();
    UUID targetTenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-denied-403-actor", actorTenantId);
    grantUserRoleAssign(actorTenantId, actorUser.getId());
    User target = seedUser("audit-denied-403-target", targetTenantId);
    Role role = seedRole("AUDIT-DENIED-403", actorTenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), actorTenantId);
    RequestContext ctx = requestContext();

    assertThatThrownBy(
            () -> roleAssignmentService.assign(actor, target.getId(), role.getId(), ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    assertThat(countAuditRows(target.getId(), "ROLE_ASSIGNMENT_DENIED"))
        .as("the denial row must survive TX1's rollback")
        .isEqualTo(1);
    assertThat(countAuditRows(target.getId(), "ROLE_ASSIGNED"))
        .as("a denial must never be miscategorised as a successful assignment")
        .isZero();

    Map<String, Object> row = findLatestDenialAuditRow(target.getId());
    assertThat(row.get("outcome")).isEqualTo("DENIED");
    assertThat(toUuid((byte[]) row.get("user_id"))).isEqualTo(target.getId());
    assertThat(toUuid((byte[]) row.get("tenant_id"))).isEqualTo(actorTenantId);
    assertThat(row.get("reason")).isEqualTo("CROSS_TENANT_TARGET");
    assertThat(row.get("attempted_by")).isEqualTo(actorUser.getId().toString());
    assertThat(row.get("role_id")).isEqualTo(role.getId().toString());
    assertThat(row.get("role_name"))
        .as("T1 fires before the role is ever resolved -- roleName must be absent")
        .isNull();
    assertThat(row.get("trace_id")).isEqualTo(ctx.traceId());
    assertThat(row.get("operation"))
        .as("D17: an assign()-side denial must carry operation=\"assign\" in its metadata")
        .isEqualTo("assign");
  }

  // ── US-016 T-016 (D17): the revoke-side counterpart of the assertion above -- completes ────
  // ── the operation metadata chain for both verbs, using the same T1 cross-tenant shape ─────

  @Test
  void should_writeRoleAssignmentDeniedRow_when_revokeFailsWithCrossTenantTarget() {
    UUID actorTenantId = uuidGenerator.newId();
    UUID targetTenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-denied-revoke-actor", actorTenantId);
    grantUserRoleAssign(actorTenantId, actorUser.getId());
    User target = seedUser("audit-denied-revoke-target", targetTenantId);
    Role role = seedRole("AUDIT-DENIED-REVOKE", actorTenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), actorTenantId);
    RequestContext ctx = requestContext();

    assertThatThrownBy(
            () -> roleAssignmentService.revoke(actor, target.getId(), role.getId(), ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    assertThat(countAuditRows(target.getId(), "ROLE_ASSIGNMENT_DENIED"))
        .as("the revoke-side denial row must survive TX1's rollback")
        .isEqualTo(1);
    assertThat(countAuditRows(target.getId(), "ROLE_REVOKED"))
        .as("a denial must never be miscategorised as a successful revocation")
        .isZero();

    Map<String, Object> row = findLatestDenialAuditRow(target.getId());
    assertThat(row.get("reason")).isEqualTo("CROSS_TENANT_TARGET");
    assertThat(row.get("operation"))
        .as("D17: a revoke()-side denial must carry operation=\"revoke\" in its metadata")
        .isEqualTo("revoke");
  }

  @Test
  void should_writeRoleAssignmentDeniedRow_when_assignFailsWithNotTenantAdmin() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-denied-admin-actor", tenantId);
    grantUserRoleAssign(tenantId, actorUser.getId());
    User target = seedUser("audit-denied-admin-target", tenantId);
    // seedRole prefixes names ("RAA-" + tag + "-" + randomUUID), which can never match
    // RbacRoleNames.TENANT_ADMIN under equalsIgnoreCase (03-design.md §0.1 item 5) -- the role
    // must be built directly with the literal name for AC8's guard to fire at all.
    Role role =
        roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "TENANT_ADMIN", null, false));
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    RequestContext ctx = requestContext();
    // actorUser holds no active TENANT_ADMIN assignment, so AC8's guard denies the grant.

    assertThatThrownBy(
            () -> roleAssignmentService.assign(actor, target.getId(), role.getId(), ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    Map<String, Object> row = findLatestDenialAuditRow(target.getId());
    assertThat(row.get("outcome")).isEqualTo("DENIED");
    assertThat(row.get("reason")).isEqualTo("NOT_TENANT_ADMIN");
    assertThat(row.get("role_name"))
        .as("T3 fires only after the role is resolved in the actor's own tenant")
        .isEqualTo("TENANT_ADMIN");
    assertThat(row.get("attempted_by")).isEqualTo(actorUser.getId().toString());
  }

  // ── US-014 Phase 8 test-coverage audit: concurrent access on the REQUIRES_NEW audit write ──
  // ── (threat model T-D6 flags the nested REQUIRES_NEW transaction as a pool-pressure risk ──
  // ── under concurrent denials; no existing test proves the writes themselves stay correct ──
  // ── and independent -- not merely that ONE denial round-trips -- under real concurrency) ──

  /**
   * Eight threads, each with its OWN tenant/actor/target/role fixture (so this proves independent
   * {@code REQUIRES_NEW} transactions never cross-contaminate each other's audit row, rather than
   * modelling the {@code FOR SHARE} lock-contention shape T-D6 separately describes for a single
   * shared admin row), fire a T1 cross-tenant {@code assign} denial simultaneously via a {@link
   * CyclicBarrier} — the same deterministic, no-{@code Thread.sleep} harness {@code
   * LastAdminLockoutIT#should_allowExactlyOneWinner_when_eightConcurrentRevokesRaceAcrossTwoAdmins}
   * already establishes for this codebase. Every thread's own doomed TX1 suspends and a
   * independent TX2 commits concurrently with the other seven; asserts (a) no deadlock — all
   * eight complete within a generous bounded timeout, and (b) each of the eight target users ends
   * up with EXACTLY its own {@code ROLE_ASSIGNMENT_DENIED} row, correctly attributed to its own
   * actor/tenant — proving the concurrent {@code REQUIRES_NEW} writes never collide, duplicate, or
   * bleed fields across threads.
   */
  @Test
  void should_writeOneCorrectlyAttributedDenialRowPerThread_when_eightConcurrentCrossTenantDenialsRace()
      throws Exception {
    int threadCount = 8;
    List<User> actors = new ArrayList<>();
    List<UUID> actorTenantIds = new ArrayList<>();
    List<User> targets = new ArrayList<>();
    List<Role> roles = new ArrayList<>();

    for (int i = 0; i < threadCount; i++) {
      UUID actorTenantId = uuidGenerator.newId();
      UUID targetTenantId = uuidGenerator.newId();
      actorTenantIds.add(actorTenantId);
      actors.add(seedUser("audit-conc-actor-" + i, actorTenantId));
      targets.add(seedUser("audit-conc-target-" + i, targetTenantId));
      roles.add(seedRole("AUDIT-CONC-" + i, actorTenantId));
    }

    CyclicBarrier barrier = new CyclicBarrier(threadCount);
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<DenialReason>> futures = new ArrayList<>();

    for (int i = 0; i < threadCount; i++) {
      int idx = i;
      futures.add(
          executor.submit(
              (Callable<DenialReason>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    RoleChangeActor actor =
                        new RoleChangeActor(actors.get(idx).getId(), actorTenantIds.get(idx));
                    try {
                      roleAssignmentService.assign(
                          actor, targets.get(idx).getId(), roles.get(idx).getId(),
                          requestContext());
                      return null;
                    } catch (InsufficientPermissionException e) {
                      return e.getReason();
                    }
                  }));
    }

    executor.shutdown();
    boolean terminated = executor.awaitTermination(15, TimeUnit.SECONDS);
    assertThat(terminated)
        .as("all 8 concurrent REQUIRES_NEW denial writes must complete without deadlock")
        .isTrue();

    for (Future<DenialReason> future : futures) {
      // future.get() rethrows unwrapped for anything unexpected -- a raw DataAccessException
      // or any outcome other than the expected denial fails this loop loudly.
      assertThat(future.get())
          .as("every thread must observe its own genuine T1 cross-tenant-target denial")
          .isEqualTo(DenialReason.CROSS_TENANT_TARGET);
    }

    for (int i = 0; i < threadCount; i++) {
      Map<String, Object> row = findLatestDenialAuditRow(targets.get(i).getId());
      assertThat(row.get("outcome")).isEqualTo("DENIED");
      assertThat(row.get("attempted_by"))
          .as("thread " + i + "'s row must be attributed to ITS OWN actor, never another"
              + " concurrently-running thread's")
          .isEqualTo(actors.get(i).getId().toString());
      assertThat(countAuditRows(targets.get(i).getId(), "ROLE_ASSIGNMENT_DENIED"))
          .as("thread " + i + " must produce EXACTLY one denial row -- no duplication from the"
              + " concurrent REQUIRES_NEW commits")
          .isEqualTo(1);
    }
  }

  // ── US-014 AC3: ROLE_ASSIGNMENT_DENIED rows are append-only, same as ROLE_ASSIGNED ──────
  // ── (mirrors AuthEventsAppendOnlyIT, differing only in the event_type literal used) ─────

  @Test
  void should_rejectUpdate_when_roleAssignedAuditRowModified() {
    byte[] id = toBytes(uuidGenerator.newId());
    jdbc.update(
        "INSERT INTO auth_events (id, event_type, outcome) VALUES (?, ?, ?)",
        id, "ROLE_ASSIGNED", "SUCCESS");

    assertThatThrownBy(
            () -> jdbc.update("UPDATE auth_events SET outcome = ? WHERE id = ?", "DENIED", id))
        .isInstanceOf(org.springframework.dao.DataAccessException.class)
        .hasMessageContaining("append-only")
        .satisfies(
            ex -> {
              Throwable cause = ex;
              while (cause != null && !(cause instanceof java.sql.SQLException)) {
                cause = cause.getCause();
              }
              assertThat(cause).isInstanceOf(java.sql.SQLException.class);
              assertThat(((java.sql.SQLException) cause).getSQLState()).isEqualTo("45000");
            });
  }

  @Test
  void should_leaveRoleAssignedAuditRowUnchanged_when_updateRejected() {
    byte[] id = toBytes(uuidGenerator.newId());
    jdbc.update(
        "INSERT INTO auth_events (id, event_type, outcome) VALUES (?, ?, ?)",
        id, "ROLE_ASSIGNED", "SUCCESS");

    try {
      jdbc.update("UPDATE auth_events SET outcome = ? WHERE id = ?", "DENIED", id);
    } catch (org.springframework.dao.DataAccessException ignored) {
      // Expected to throw because the append-only trigger enforces no UPDATE.
    }

    String outcome =
        jdbc.queryForObject("SELECT outcome FROM auth_events WHERE id = ?", String.class, id);
    assertThat(outcome).isEqualTo("SUCCESS");
  }

  // ── US-014 AC5: ordered assign/revoke history for a (tenant, user) pair ─────────────────

  @Test
  void should_returnAssignThenRevokeInCreatedAtOrder_when_queryingRoleHistoryForUserInTenant() {
    UUID tenantA = uuidGenerator.newId();
    User actorA = seedUser("audit-history-a-actor", tenantA);
    grantUserRoleAssign(tenantA, actorA.getId());
    User targetA = seedUser("audit-history-a-target", tenantA);
    Role roleA = seedRole("AUDIT-HISTORY-A", tenantA);
    RoleChangeActor changeActorA = new RoleChangeActor(actorA.getId(), tenantA);

    // Decoy in an unrelated tenant B -- must never appear in tenant A's history.
    UUID tenantB = uuidGenerator.newId();
    User actorB = seedUser("audit-history-b-actor", tenantB);
    grantUserRoleAssign(tenantB, actorB.getId());
    User targetB = seedUser("audit-history-b-target", tenantB);
    Role roleB = seedRole("AUDIT-HISTORY-B", tenantB);
    roleAssignmentService.assign(
        new RoleChangeActor(actorB.getId(), tenantB), targetB.getId(), roleB.getId(),
        requestContext());

    // Two separate service calls -> two separate committed transactions -> two distinct
    // DB-generated created_at values, making a microsecond DATETIME(6) tie effectively
    // impossible without needing an artificial secondary sort key.
    roleAssignmentService.assign(changeActorA, targetA.getId(), roleA.getId(), requestContext());
    roleAssignmentService.revoke(changeActorA, targetA.getId(), roleA.getId(), requestContext());

    List<Map<String, Object>> rows =
        jdbc.queryForList(
            "SELECT event_type, created_at, user_id FROM auth_events WHERE tenant_id = ? AND "
                + "user_id = ? AND event_type IN ('ROLE_ASSIGNED','ROLE_REVOKED') ORDER BY "
                + "created_at",
            toBytes(tenantA), toBytes(targetA.getId()));

    assertThat(rows).hasSize(2);
    assertThat(rows.stream().map(r -> (String) r.get("event_type")))
        .containsExactly("ROLE_ASSIGNED", "ROLE_REVOKED");
    assertThat(rows.stream().map(r -> toUuid((byte[]) r.get("user_id"))))
        .as("the tenant-B decoy must never appear in tenant A's history")
        .containsOnly(targetA.getId());

    java.time.LocalDateTime firstCreatedAt = (java.time.LocalDateTime) rows.get(0).get("created_at");
    java.time.LocalDateTime secondCreatedAt = (java.time.LocalDateTime) rows.get(1).get("created_at");
    assertThat(secondCreatedAt)
        .as("flake control for the DATETIME(6) tie risk -- two real, separate service calls "
            + "make a tie effectively impossible")
        .isAfter(firstCreatedAt);
  }

  // ── Scenario 5 / TS-5 (US-018 A6, the most important scenario in this file): a blocked ───
  // ── Group A (atomic) audit insert rolls back the mutation it accompanies — proven with a ──
  // ── test-only BEFORE INSERT trigger on auth_events, installed and dropped by each test, ──
  // ── that signals only for the RBAC success event type under test. Unlike the pre-A6 ───────
  // ── mechanism this replaces (a merge-at-commit collision caught by the old swallow-catch), ─
  // ── RbacAuditPort's Group A methods now MUST THROW on failure (design §6.2) — a genuine ───
  // ── MySQL-level rejection must therefore propagate out of the SERVICE method, not just the ─
  // ── adapter, and the mutation's own INSERT/UPDATE must be rolled back with it. ─────────────

  @Test
  void should_rollBackAssignmentAndWriteNoAuditRow_when_roleAssignedAuditInsertIsBlocked() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("ts5-assign-actor", tenantId);
    grantUserRoleAssign(tenantId, actorUser.getId());
    User target = seedUser("ts5-assign-target", tenantId);
    Role role = seedRole("TS5-ASSIGN", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);

    installAuditBlockTrigger("ROLE_ASSIGNED");
    try {
      assertThatThrownBy(
              () ->
                  roleAssignmentService.assign(
                      actor, target.getId(), role.getId(), requestContext()))
          .as("TS-5: a blocked Group A (atomic) audit write must propagate -- never be swallowed")
          .isInstanceOf(RuntimeException.class);

      assertThat(countActiveUserRoles(target.getId(), role.getId()))
          .as("TS-5: the blocked ROLE_ASSIGNED audit insert must roll back the user_roles insert"
              + " too -- a half-atomic result (role change committed, audit lost) is exactly"
              + " what US-018 A6 closes")
          .isZero();
      assertThat(countAuditRows(target.getId(), "ROLE_ASSIGNED"))
          .as("the blocked insert itself must never actually land")
          .isZero();
    } finally {
      dropAuditBlockTrigger();
    }
  }

  @Test
  void should_rollBackRevocationAndWriteNoAuditRow_when_roleRevokedAuditInsertIsBlocked() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("ts5-revoke-actor", tenantId);
    grantUserRoleAssign(tenantId, actorUser.getId());
    User target = seedUser("ts5-revoke-target", tenantId);
    Role role = seedRole("TS5-REVOKE", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    roleAssignmentService.assign(actor, target.getId(), role.getId(), requestContext());

    installAuditBlockTrigger("ROLE_REVOKED");
    try {
      assertThatThrownBy(
              () ->
                  roleAssignmentService.revoke(
                      actor, target.getId(), role.getId(), requestContext()))
          .as("TS-5: a blocked Group A (atomic) audit write must propagate -- never be swallowed")
          .isInstanceOf(RuntimeException.class);

      assertThat(countActiveUserRoles(target.getId(), role.getId()))
          .as("TS-5: the blocked ROLE_REVOKED audit insert must roll back the revoke UPDATE too"
              + " -- the assignment must remain ACTIVE, not half-revoked")
          .isEqualTo(1);
      assertThat(countAuditRows(target.getId(), "ROLE_REVOKED")).isZero();
    } finally {
      dropAuditBlockTrigger();
    }
  }

  // ── MC-4 IT half (US-018 A6): recordEventInCurrentTransaction is MANDATORY, so calling it ──
  // ── with no active transaction is a programming error, not a condition to paper over. ──────

  @Test
  void should_throwIllegalTransactionState_when_recordEventInCurrentTransactionCalledOutsideTransaction() {
    AuthEvent event = new AuthEvent(uuidGenerator.newId(), "ROLE_ASSIGNED", "SUCCESS");

    assertThatThrownBy(() -> secureEventService.recordEventInCurrentTransaction(event))
        .as("MC-4: MANDATORY propagation must refuse to run outside an existing transaction,"
            + " rather than silently starting one")
        .isInstanceOf(IllegalTransactionStateException.class);
  }

  // ── Fixtures / helpers ───────────────────────────────────────────────────────────────────

  private User seedUser(String tag, UUID tenantId) {
    String email = "raa-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  /**
   * US-018 07-security-review.md L-1: {@code assign()}/{@code revoke()} re-check the actor's fresh
   * M13 holdings for {@code user:role:assign}, so a service-level actor must actually hold it --
   * through a fresh custom role carrying only that permission, never a dangerous one.
   */
  private void grantUserRoleAssign(UUID tenantId, UUID userId) {
    Role assignerRole = seedRole("ASSIGNER", tenantId);
    rolePermissionRepository.save(
        new RolePermission(assignerRole.getId(), RbacSeededPermissionIds.USER_ROLE_ASSIGN));
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), userId, assignerRole.getId(), tenantId, userId));
  }

  private Role seedRole(String tag, UUID tenantId) {
    // is_system_role=false: keeps RbacSchemaMigrationIT's scoped seed-role count stable
    // regardless of test execution order (see ActiveAssignmentIT's seedRole Javadoc).
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RAA-" + tag + "-" + UUID.randomUUID(), null,
            false));
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "RoleAssignmentAuditIT");
  }

  private Map<String, Object> findLatestAuditRow(UUID targetUserId, String eventType) {
    return jdbc.queryForMap(
        "SELECT JSON_VALID(metadata) AS valid, outcome, user_id, tenant_id, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.roleId')) AS role_id, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.roleName')) AS role_name, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.assignedBy')) AS assigned_by, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.revokedBy')) AS revoked_by, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.traceId')) AS trace_id "
            + "FROM auth_events WHERE user_id = ? AND event_type = ? ORDER BY created_at DESC"
            + " LIMIT 1",
        toBytes(targetUserId), eventType);
  }

  /**
   * Sibling of {@link #findLatestAuditRow}, for {@code ROLE_ASSIGNMENT_DENIED} rows: adds {@code
   * reason}/{@code attempted_by} JSON extraction in place of {@code assigned_by}/{@code
   * revoked_by} (US-014 §4.2's denial-row shape).
   */
  private Map<String, Object> findLatestDenialAuditRow(UUID targetUserId) {
    return jdbc.queryForMap(
        "SELECT outcome, user_id, tenant_id, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.roleId')) AS role_id, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.roleName')) AS role_name, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason')) AS reason, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.attemptedBy')) AS attempted_by, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.traceId')) AS trace_id, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.operation')) AS operation "
            + "FROM auth_events WHERE user_id = ? AND event_type = 'ROLE_ASSIGNMENT_DENIED' "
            + "ORDER BY created_at DESC LIMIT 1",
        toBytes(targetUserId));
  }

  private int countAuditRows(UUID targetUserId, String eventType) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM auth_events WHERE user_id = ? AND event_type = ?",
            Integer.class,
            toBytes(targetUserId),
            eventType);
    return count == null ? 0 : count;
  }

  /**
   * TS-5 (US-018 A6): a test-only {@code BEFORE INSERT} trigger on {@code auth_events} that
   * signals only for the given RBAC success {@code event_type}, simulating a genuine MySQL-level
   * rejection of the Group A (atomic) audit insert. Installed per-test and always dropped in a
   * {@code finally} block via {@link #dropAuditBlockTrigger()} -- {@code eventType} is an internal
   * literal, never request-derived, so string-building the DDL here is safe.
   */
  private void installAuditBlockTrigger(String eventType) {
    jdbc.execute(
        "CREATE TRIGGER trg_ts5_block_rbac_success BEFORE INSERT ON auth_events FOR EACH ROW "
            + "BEGIN IF NEW.event_type = '" + eventType + "' THEN "
            + "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'TS-5 test-only block'; "
            + "END IF; END");
  }

  private void dropAuditBlockTrigger() {
    jdbc.execute("DROP TRIGGER IF EXISTS trg_ts5_block_rbac_success");
  }

  private int countActiveUserRoles(UUID userId, UUID roleId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND revoked_at"
                + " IS NULL",
            Integer.class,
            toBytes(userId),
            toBytes(roleId));
    return count == null ? 0 : count;
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  private static UUID toUuid(byte[] bytes) {
    ByteBuffer buf = ByteBuffer.wrap(bytes);
    return new UUID(buf.getLong(), buf.getLong());
  }
}
