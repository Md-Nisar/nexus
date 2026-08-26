package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.identity.application.service.SecureEventService;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.audit.RbacAuthEventAdapter;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.port.out.RbacAuditEvent;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
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
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import tools.jackson.databind.ObjectMapper;

/**
 * US-012 T-021 (04-tasks.md; 03-design.md §6.3-§6.4; 03b-threat-model.md T-T5/T-R3): the sole
 * automated, end-to-end proof — against real Testcontainers MySQL, never H2 — that {@link
 * RbacAuthEventAdapter}'s audit write (a) actually round-trips a valid, correctly-keyed JSON
 * {@code metadata} payload through MySQL's native {@code JSON} column (T-T5), and (b) that the
 * T-R3 audit-write-loss handling (ERROR log + {@code nexus.rbac.audit_write_failed} counter)
 * genuinely fires on a real commit-boundary DB rejection, not merely against a mocked {@link
 * SecureEventService} — that is {@code RbacAuthEventAdapterTest}'s job (T-009) and is
 * <b>deliberately not re-duplicated here</b>.
 *
 * <p><b>Scope discipline (per T-021's own instructions):</b> {@code RbacAuthEventAdapterTest}
 * already exhaustively covers the field-mapping table and the full adversarial {@code roleName}
 * matrix (quote, backslash, newline, control character, lone surrogate, JSON-shaped payload, and
 * the duplicate-key {@code traceId} case) against a mocked {@link SecureEventService}. This class
 * does not repeat that matrix; it picks two representative adversarial cases and proves they
 * round-trip correctly through <b>MySQL's own</b> {@code JSON_VALID()}/{@code JSON_EXTRACT()} —
 * something a mock cannot verify, because MySQL's binary JSON type normalises key order and
 * validates JSON syntax at the storage layer (03b-threat-model.md T-T1/T-T5).
 *
 * <p><b>Scenario 5 (T-R3 forced-failure) mechanism, and why the obvious alternative is wrong:</b>
 * the naive approach — a {@code @MockitoSpyBean} on {@code JpaAuthEventRepository} throwing on
 * {@code save(...)} (the pattern {@code AuditStoreDownIT} uses) — does <b>not</b> reproduce the
 * T-R3 gap. A synchronous throw from {@code save()} is caught by {@code JpaAuthEventAdapter}'s own
 * {@code catch (DataAccessException)}, which enqueues the event onto the existing, already-durable
 * retry buffer — exactly the failure mode T-R3 says is <em>already handled</em>. T-R3's actual gap
 * is a failure that surfaces only when {@code SecureEventService}'s {@code REQUIRES_NEW}
 * transaction flushes/commits — <em>after</em> {@code JpaAuthEventAdapter.record()} has already
 * returned normally, so its {@code catch} never runs and {@code retryBuffer.enqueue} is never
 * called.
 *
 * <p>This class reproduces that exact commit-boundary shape with a genuine MySQL rejection, no
 * mocking of {@code SecureEventService} at all: {@link com.example.nexus.identity.domain.AuthEvent}
 * has an assigned (non-generated) {@code @Id}, so Spring Data's {@code save()} issues a {@code
 * merge()} rather than a {@code persist()}. By pre-inserting (via raw JDBC) a real, different
 * {@code auth_events} row under the exact id a stubbed {@link UuidGenerator} will hand back, {@code
 * merge()} finds that id already present, loads it, and marks it dirty — deferring the doomed
 * write to flush/commit time exactly as 03-design.md §6.4 describes. {@code auth_events}' own
 * {@code trg_auth_events_no_update} append-only trigger (V2__identity_schema.sql) then blocks that
 * {@code UPDATE} at commit, producing a genuine MySQL-level rejection that surfaces only after
 * control has returned to {@link RbacAuthEventAdapter}'s call site — structurally identical to the
 * design's own cited failure modes (a malformed-metadata {@code ERROR 3140}, a constraint
 * violation, or a transient connection loss at commit). A fresh (non-Spring-managed) {@code
 * RbacAuthEventAdapter} instance is constructed directly with the real, autowired {@code
 * SecureEventService}/{@code ObjectMapper}/{@code MeterRegistry} and only the {@code UuidGenerator}
 * swapped — mirroring the established "one broken collaborator, everything else real" technique
 * {@code RoleAssignmentCacheIT} already uses for its Redis-down case.
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
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private SecureEventService secureEventService;
  @Autowired private MeterRegistry meterRegistry;
  @Autowired private ObjectMapper objectMapper;

  // ── Scenario 1: successful assign writes a correctly-keyed ROLE_ASSIGNED row ──────────

  @Test
  void should_writeValidRoleAssignedEventWithCorrectFields_when_assignSucceeds() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-assign-actor", tenantId);
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
  }

  @Test
  void should_writeRoleAssignmentDeniedRow_when_assignFailsWithNotTenantAdmin() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("audit-denied-admin-actor", tenantId);
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
    User targetA = seedUser("audit-history-a-target", tenantA);
    Role roleA = seedRole("AUDIT-HISTORY-A", tenantA);
    RoleChangeActor changeActorA = new RoleChangeActor(actorA.getId(), tenantA);

    // Decoy in an unrelated tenant B -- must never appear in tenant A's history.
    UUID tenantB = uuidGenerator.newId();
    User actorB = seedUser("audit-history-b-actor", tenantB);
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

  // ── Scenario 5 (T-R3, the most important scenario in this file): forced real ───────────
  // ── MySQL-level audit-write failure ─────────────────────────────────────────────────────

  @Test
  void should_logErrorAndIncrementCounter_when_auditWriteFailsAtRealMySqlCommitBoundary() {
    UUID collidingId = uuidGenerator.newId();
    // Pre-existing, DIFFERENT row under the exact id the stubbed UuidGenerator below will hand
    // back. This forces Hibernate's merge() (AuthEvent has an assigned @Id) to find an existing
    // row and mark it dirty, deferring the doomed write to flush/commit time — see this class's
    // Javadoc for the full mechanism.
    jdbc.update(
        "INSERT INTO auth_events (id, event_type, outcome) VALUES (?, ?, ?)",
        toBytes(collidingId), "LOGIN_FAILURE", "FAILURE");

    UUID tenantId = uuidGenerator.newId();
    UUID targetUserId = uuidGenerator.newId();
    UUID roleId = uuidGenerator.newId();
    UUID actorUserId = uuidGenerator.newId();
    RequestContext ctx = RequestContext.of("127.0.0.1", "trace-forced-failure", "JUnit");
    RbacAuditEvent event =
        new RbacAuditEvent(tenantId, targetUserId, roleId, "TENANT_ADMIN", actorUserId, ctx);

    // Fresh, non-Spring-managed adapter instance: real (autowired) SecureEventService,
    // ObjectMapper, and MeterRegistry — only the UuidGenerator is swapped, so the actual DB
    // interaction and failure-handling code run for real against Testcontainers MySQL.
    RbacAuthEventAdapter adapterWithForcedCollision =
        new RbacAuthEventAdapter(secureEventService, () -> collidingId, objectMapper, meterRegistry);

    double counterBefore = auditWriteFailedCount("assign");
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatCode(() -> adapterWithForcedCollision.recordRoleAssigned(event))
          .as("T-R3: even a genuine commit-boundary MySQL rejection must never propagate out of"
              + " the audit adapter")
          .doesNotThrowAnyException();

      var errorEvents = appender.list.stream().filter(e -> e.getLevel() == Level.ERROR).toList();
      assertThat(errorEvents)
          .as("a genuine MySQL-level audit-write failure must log RBAC_AUDIT_WRITE_LOST at ERROR")
          .hasSize(1);
      Map<String, Object> keyValues = keyValueMap(errorEvents.get(0));
      assertThat(keyValues)
          .containsEntry("event", "RBAC_AUDIT_WRITE_LOST")
          .containsEntry("tenantId", tenantId)
          .containsEntry("targetUserId", targetUserId)
          .containsEntry("roleId", roleId)
          .containsEntry("actorUserId", actorUserId)
          .containsEntry("traceId", "trace-forced-failure");
    } finally {
      stopLogCapture(appender);
    }

    assertThat(auditWriteFailedCount("assign"))
        .as("nexus.rbac.audit_write_failed{operation=assign} must increment on the real,"
            + " commit-boundary MySQL failure")
        .isEqualTo(counterBefore + 1.0);

    Map<String, Object> untouchedRow =
        jdbc.queryForMap(
            "SELECT event_type, outcome FROM auth_events WHERE id = ?", toBytes(collidingId));
    assertThat(untouchedRow.get("event_type"))
        .as("auth_events' append-only trigger must have blocked the UPDATE outright — the"
            + " pre-existing row must be completely unchanged")
        .isEqualTo("LOGIN_FAILURE");
    assertThat(untouchedRow.get("outcome")).isEqualTo("FAILURE");
  }

  // ── Fixtures / helpers ───────────────────────────────────────────────────────────────────

  private User seedUser(String tag, UUID tenantId) {
    String email = "raa-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
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
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.traceId')) AS trace_id "
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

  private double auditWriteFailedCount(String operation) {
    var counter =
        meterRegistry.find("nexus.rbac.audit_write_failed").tag("operation", operation).counter();
    return counter != null ? counter.count() : 0.0;
  }

  private ListAppender<ILoggingEvent> startLogCapture() {
    Logger logger = (Logger) LoggerFactory.getLogger(RbacAuthEventAdapter.class);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  private void stopLogCapture(ListAppender<ILoggingEvent> listAppender) {
    Logger logger = (Logger) LoggerFactory.getLogger(RbacAuthEventAdapter.class);
    logger.detachAppender(listAppender);
    listAppender.stop();
  }

  private static Map<String, Object> keyValueMap(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    return map;
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
