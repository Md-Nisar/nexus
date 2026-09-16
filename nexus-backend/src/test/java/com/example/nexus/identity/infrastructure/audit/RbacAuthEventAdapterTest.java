package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.identity.application.service.SecureEventService;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.port.out.RbacAuditEvent;
import com.example.nexus.rbac.application.port.out.RoleAuditEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Tag("UnitTest")
class RbacAuthEventAdapterTest {

  private static final UUID GENERATED_ID = UUID.randomUUID();
  private static final UUID TENANT_ID = UUID.randomUUID();
  private static final UUID TARGET_USER_ID = UUID.randomUUID();
  private static final UUID ROLE_ID = UUID.randomUUID();
  private static final UUID ACTOR_USER_ID = UUID.randomUUID();
  private static final UUID PERMISSION_ID = UUID.randomUUID();

  private SecureEventService secureEventService;
  private UuidGenerator uuidGenerator;
  private ObjectMapper objectMapper;
  private SimpleMeterRegistry meterRegistry;
  private RbacAuthEventAdapter adapter;

  @BeforeEach
  void setUp() {
    secureEventService = mock(SecureEventService.class);
    uuidGenerator = mock(UuidGenerator.class);
    when(uuidGenerator.newId()).thenReturn(GENERATED_ID);
    objectMapper = new ObjectMapper();
    meterRegistry = new SimpleMeterRegistry();
    adapter = new RbacAuthEventAdapter(secureEventService, uuidGenerator, objectMapper, meterRegistry);
  }

  // ---------------------------------------------------------------------
  // Field-mapping assertions
  // ---------------------------------------------------------------------

  @Test
  void should_mapAllFieldsCorrectly_when_recordRoleAssignedCalled() {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-123", "test-agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    adapter.recordRoleAssigned(event);

    AuthEvent captured = captureRecordedEvent();
    assertThat(captured.getId()).isEqualTo(GENERATED_ID);
    assertThat(captured.getEventType()).isEqualTo("ROLE_ASSIGNED");
    // Load-bearing (US-014 T-T8 item 5): the only guard that the ROLE_ASSIGNED call site still
    // passes "SUCCESS" after record(...) was parameterised with an outcome argument. A
    // transposition at either success call site would silently mislabel every successful
    // assignment/revocation.
    assertThat(captured.getOutcome()).isEqualTo("SUCCESS");
    assertThat(captured.getUserId()).isEqualTo(TARGET_USER_ID); // the subject, not the actor
    assertThat(captured.getTenantId()).isEqualTo(TENANT_ID);
    assertThat(captured.getIpAddress()).isEqualTo("127.0.0.1");
    assertThat(captured.getUserAgent()).isEqualTo("test-agent");

    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("traceId").asString()).isEqualTo("trace-123");
    assertThat(metadata.get("roleId").asString()).isEqualTo(ROLE_ID.toString());
    assertThat(metadata.get("roleName").asString()).isEqualTo("TENANT_ADMIN");
    assertThat(metadata.get("assignedBy").asString()).isEqualTo(ACTOR_USER_ID.toString());
    assertThat(metadata.has("revokedBy")).isFalse();
  }

  @Test
  void should_mapAllFieldsCorrectly_when_recordRoleRevokedCalled() {
    RequestContext ctx = new RequestContext("10.0.0.5", "trace-456", "another-agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    adapter.recordRoleRevoked(event);

    AuthEvent captured = captureRecordedEvent();
    assertThat(captured.getEventType()).isEqualTo("ROLE_REVOKED");
    // Load-bearing (US-014 T-T8 item 5) -- see the comment on
    // should_mapAllFieldsCorrectly_when_recordRoleAssignedCalled above.
    assertThat(captured.getOutcome()).isEqualTo("SUCCESS");
    assertThat(captured.getUserId()).isEqualTo(TARGET_USER_ID);
    assertThat(captured.getTenantId()).isEqualTo(TENANT_ID);

    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("revokedBy").asString()).isEqualTo(ACTOR_USER_ID.toString());
    assertThat(metadata.has("assignedBy")).isFalse();
  }

  @Test
  void should_omitTraceIdKeyEntirely_when_requestContextTraceIdIsNull() {
    RequestContext ctx = new RequestContext("127.0.0.1", null, "test-agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    adapter.recordRoleAssigned(event);

    AuthEvent captured = captureRecordedEvent();
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.has("traceId")).isFalse();
    // never a JSON null either
    assertThat(metadata.toString()).doesNotContain("null");
  }

  @Test
  void should_mapAllFieldsCorrectly_when_recordRoleAssignmentDeniedCalled() {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-denied", "test-agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    adapter.recordRoleAssignmentDenied(event, DenialReason.CROSS_TENANT_TARGET, "assign");

    AuthEvent captured = captureRecordedEvent();
    assertThat(captured.getId()).isEqualTo(GENERATED_ID);
    assertThat(captured.getEventType()).isEqualTo("ROLE_ASSIGNMENT_DENIED");
    assertThat(captured.getOutcome()).isEqualTo("DENIED");
    assertThat(captured.getUserId()).isEqualTo(TARGET_USER_ID); // the subject, not the actor
    assertThat(captured.getTenantId()).isEqualTo(TENANT_ID);
    assertThat(captured.getIpAddress()).isEqualTo("127.0.0.1");
    assertThat(captured.getUserAgent()).isEqualTo("test-agent");

    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("traceId").asString()).isEqualTo("trace-denied");
    assertThat(metadata.get("roleId").asString()).isEqualTo(ROLE_ID.toString());
    assertThat(metadata.get("roleName").asString()).isEqualTo("TENANT_ADMIN");
    assertThat(metadata.get("reason").asString()).isEqualTo("CROSS_TENANT_TARGET");
    assertThat(metadata.get("operation").asString()).isEqualTo("assign");
    assertThat(metadata.get("attemptedBy").asString()).isEqualTo(ACTOR_USER_ID.toString());
    assertThat(metadata.has("assignedBy")).isFalse();
    assertThat(metadata.has("revokedBy")).isFalse();
  }

  /**
   * US-014 Phase 8 test-coverage audit: {@link RbacAuthEventAdapter#recordRoleAssignmentDenied}
   * accepts a nullable {@code DenialReason} at the port-method signature level, even though every
   * production call site in {@code RoleAssignmentService} always passes a non-null reason
   * (verified by reading the source — {@code e.getReason()} on a freshly-constructed {@code
   * InsufficientPermissionException} is never null). This proves the defensive {@code reason !=
   * null ? reason.name() : null} branch behaves like every other optional field here: the {@code
   * reason} key is omitted entirely, never emitted as a JSON {@code null} — for any future caller
   * of this port method, not only today's.
   */
  @Test
  void should_omitReasonKey_when_deniedEventReasonIsNull() {
    // traceId deliberately avoids the substring "null" -- it would otherwise trip the
    // doesNotContain("null") assertion below for a reason having nothing to do with the
    // reason key under test.
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-reason-absent", "test-agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    adapter.recordRoleAssignmentDenied(event, null, "assign");

    AuthEvent captured = captureRecordedEvent();
    assertThat(captured.getEventType()).isEqualTo("ROLE_ASSIGNMENT_DENIED");
    assertThat(captured.getOutcome()).isEqualTo("DENIED");
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.has("reason")).isFalse();
    // never a JSON null either
    assertThat(metadata.toString()).doesNotContain("null");
    assertThat(metadata.get("attemptedBy").asString()).isEqualTo(ACTOR_USER_ID.toString());
  }

  @Test
  void should_omitRoleNameKey_when_deniedEventHasNullRoleName() {
    // The T1/T2 row shape (03-design.md §0.1 item 2): the tenant checks throw before the role
    // is ever resolved, so a denial row for those reasons carries no roleName at all.
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-no-role-name", "test-agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, null, ACTOR_USER_ID, ctx);

    adapter.recordRoleAssignmentDenied(event, DenialReason.CROSS_TENANT_TARGET, "assign");

    AuthEvent captured = captureRecordedEvent();
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.has("roleName")).isFalse();
    // never a JSON null either
    assertThat(metadata.toString()).doesNotContain("null");
    assertThat(metadata.get("reason").asString()).isEqualTo("CROSS_TENANT_TARGET");
  }

  /**
   * Characterisation test for the metadata key-ordering property (03-design.md §4.2): {@code
   * reason} is emitted after {@code roleName}, so MySQL's last-duplicate-key-wins semantics mean
   * a forged {@code reason} smuggled in through {@code roleName} loses to the real, trailing one.
   *
   * <p><b>This is not an escaper-failure detector</b> — it passes under both a working and a
   * broken escaper. The actual escaper-failure detector is the pre-existing {@code
   * duplicateKeyInjection} case targeting {@code traceId} in {@link #adversarialRoleNames()},
   * which is NOT made redundant by this test (T-T8 item 3) and must not be retired.
   */
  @Test
  void should_keepRealReason_when_roleNameAttemptsDuplicateKeyInjectionOfReason() {
    String forgedRoleName = "x\",\"reason\":\"PERMISSION_ABSENT";
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-reason-inject", "test-agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, forgedRoleName, ACTOR_USER_ID, ctx);

    adapter.recordRoleAssignmentDenied(event, DenialReason.CROSS_TENANT_TARGET, "assign");

    AuthEvent captured = captureRecordedEvent();
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("roleName").isString()).isTrue();
    assertThat(metadata.get("roleName").asString()).isEqualTo(forgedRoleName);
    assertThat(metadata.get("reason").asString())
        .as("the real reason must win over a forged one smuggled in through roleName")
        .isEqualTo("CROSS_TENANT_TARGET");
  }

  // ---------------------------------------------------------------------
  // Adversarial roleName set (T-T5)
  // ---------------------------------------------------------------------

  static Stream<Arguments> adversarialRoleNames() {
    return Stream.of(
        Arguments.of("quote", "TENANT_\"ADMIN\""),
        Arguments.of("backslash", "TENANT\\ADMIN"),
        Arguments.of("newline", "TENANT\nADMIN"),
        Arguments.of("controlChar", "TENANT" + (char) 0 + "ADMIN"),
        Arguments.of("jsonShaped", "{\"a\":1}"),
        // Duplicate-key injection targeting traceId, not assignedBy (03-design.md §6.3's own
        // key-ordering analysis): metadata keys are emitted traceId, roleId, roleName,
        // assignedBy -- a forged key injected via roleName lands AFTER the real traceId but
        // BEFORE the real assignedBy. MySQL keeps the LAST duplicate key, so a forged
        // assignedBy would always lose to the real trailing one regardless of whether escaping
        // works -- assignedBy is not a discriminating case. A forged traceId, by contrast,
        // would WIN if escaping were broken, since it comes after the real one. Only targeting
        // traceId actually proves the escaper works.
        //
        // Load-bearing (US-014 T-T8 item 3): this is the ONLY escaper-failure detector in this
        // file -- it fails if Jackson-3 escaping regresses. The newer
        // should_keepRealReason_when_roleNameAttemptsDuplicateKeyInjectionOfReason test does NOT
        // make this redundant: that test is a characterisation test for key ordering only (it
        // passes under both a working and a broken escaper). Do not retire this case.
        Arguments.of("duplicateKeyInjection", "x\",\"traceId\":\"forged"));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("adversarialRoleNames")
  void should_escapeAdversarialRoleName_when_metadataSerialised(String label, String roleName) {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-adv", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, roleName, ACTOR_USER_ID, ctx);

    adapter.recordRoleAssigned(event);

    AuthEvent captured = captureRecordedEvent();
    // Must round-trip as valid JSON with the role name preserved as a plain string value —
    // never interpreted as JSON structure.
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("roleName").isString()).isTrue();
    assertThat(metadata.get("roleName").asString()).isEqualTo(roleName);
    // The real traceId must survive untouched regardless of what roleName tries to inject.
    assertThat(metadata.get("traceId").asString()).isEqualTo("trace-adv");
  }

  /**
   * A lone (unpaired) UTF-16 high surrogate is the one residual T-T5 case 03-design.md §6.3
   * itself flags: whether it serializes cleanly or the write fails is implementation-specific,
   * but either way {@code recordRoleAssigned} must never throw -- a failure here must go through
   * the same T-R3 never-throws/ERROR-log/counter path as any other audit-write failure, not
   * propagate to the caller.
   */
  @Test
  void should_neverThrow_when_roleNameContainsLoneHighSurrogate() {
    String roleName = "TENANT" + '\uD800' + "ADMIN";
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-surrogate", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, roleName, ACTOR_USER_ID, ctx);

    assertThatCode(() -> adapter.recordRoleAssigned(event)).doesNotThrowAnyException();
  }

  // ---------------------------------------------------------------------
  // T-R3: never-throws + ERROR log + counter on audit-write failure
  // ---------------------------------------------------------------------

  @Test
  void should_notPropagateException_when_secureEventServiceThrowsOnAssign() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    assertThatCode(() -> adapter.recordRoleAssigned(event)).doesNotThrowAnyException();
  }

  @Test
  void should_logErrorWithLostAuditMarker_when_secureEventServiceThrowsOnAssign() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      adapter.recordRoleAssigned(event);

      var errorEvents =
          appender.list.stream().filter(e -> e.getLevel() == Level.ERROR).toList();
      assertThat(errorEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(errorEvents.get(0));
      assertThat(keyValues)
          .containsEntry("event", "RBAC_AUDIT_WRITE_LOST")
          .containsEntry("tenantId", TENANT_ID)
          .containsEntry("targetUserId", TARGET_USER_ID)
          .containsEntry("roleId", ROLE_ID)
          .containsEntry("actorUserId", ACTOR_USER_ID)
          .containsEntry("traceId", "trace-fail");
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_incrementAuditWriteFailedCounterWithAssignTag_when_recordRoleAssignedFails() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    adapter.recordRoleAssigned(event);

    double count =
        meterRegistry.get("nexus.rbac.audit_write_failed").tag("operation", "assign").counter().count();
    assertThat(count).isEqualTo(1.0);
  }

  @Test
  void should_incrementAuditWriteFailedCounterWithRevokeTag_when_recordRoleRevokedFails() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    adapter.recordRoleRevoked(event);

    double count =
        meterRegistry.get("nexus.rbac.audit_write_failed").tag("operation", "revoke").counter().count();
    assertThat(count).isEqualTo(1.0);
  }

  @Test
  void should_notPropagateException_when_secureEventServiceThrowsOnRevoke() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    assertThatCode(() -> adapter.recordRoleRevoked(event)).doesNotThrowAnyException();
  }

  @Test
  void should_notPropagateException_when_secureEventServiceThrowsOnDenied() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    assertThatCode(
            () -> adapter.recordRoleAssignmentDenied(event, DenialReason.CROSS_TENANT_TARGET, "assign"))
        .doesNotThrowAnyException();
  }

  /**
   * Proves the metric tag stays fixed at {@code "deny"} regardless of which verb was denied
   * (03-design.md §12.2 item 11) — the metric tag and the {@code operation} metadata field are
   * deliberately different axes and must not be unified.
   */
  @ParameterizedTest
  @ValueSource(strings = {"assign", "revoke"})
  void should_incrementAuditWriteFailedCounterWithDenyTag_when_recordRoleAssignmentDeniedFails(
      String operation) {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    adapter.recordRoleAssignmentDenied(event, DenialReason.CROSS_TENANT_TARGET, operation);

    double count =
        meterRegistry.get("nexus.rbac.audit_write_failed").tag("operation", "deny").counter().count();
    assertThat(count).isEqualTo(1.0);
  }

  /**
   * D17/RC-13 (03-design.md §4.9): {@code operation} is persisted in the denial's metadata,
   * positioned after {@code reason} (key-ordering matters for the same last-duplicate-key-wins
   * reasoning as {@link #should_keepRealReason_when_roleNameAttemptsDuplicateKeyInjectionOfReason}).
   */
  @ParameterizedTest
  @ValueSource(strings = {"assign", "revoke"})
  void should_includeOperationAfterReason_when_operationPresent(String operation) {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-op", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    adapter.recordRoleAssignmentDenied(event, DenialReason.CROSS_TENANT_TARGET, operation);

    AuthEvent captured = captureRecordedEvent();
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("operation").asString()).isEqualTo(operation);
    String raw = captured.getMetadata();
    assertThat(raw.indexOf("\"reason\"")).isLessThan(raw.indexOf("\"operation\""));
  }

  /**
   * US-016 T-004/T-007: the port parameter is a plain, nullable {@code String}, so this omit-path
   * is exercised defensively here even though no current or planned call site in {@code
   * RoleAssignmentService} passes {@code null} for {@code operation} (every T-008 call site
   * passes a literal {@code "assign"} or {@code "revoke"}) — the same convention as {@link
   * #should_omitReasonKey_when_deniedEventReasonIsNull}.
   */
  @Test
  void should_omitOperationKey_when_deniedEventOperationIsNull() {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-op-absent", "agent");
    RbacAuditEvent event =
        new RbacAuditEvent(TENANT_ID, TARGET_USER_ID, ROLE_ID, "TENANT_ADMIN", ACTOR_USER_ID, ctx);

    adapter.recordRoleAssignmentDenied(event, DenialReason.CROSS_TENANT_TARGET, null);

    AuthEvent captured = captureRecordedEvent();
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.has("operation")).isFalse();
    // never a JSON null either
    assertThat(metadata.toString()).doesNotContain("null");
    assertThat(metadata.get("attemptedBy").asString()).isEqualTo(ACTOR_USER_ID.toString());
  }

  // ---------------------------------------------------------------------
  // US-015 AC12: RoleAuditEvent overload (recordRoleCreated / recordRolePermissionGranted /
  // recordRolePermissionRevoked)
  // ---------------------------------------------------------------------

  @Test
  void should_mapAllFieldsCorrectly_when_recordRoleCreatedCalled() {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-create", "test-agent");
    RoleAuditEvent event =
        new RoleAuditEvent(TENANT_ID, ROLE_ID, "Billing Manager", null, null, ACTOR_USER_ID, ctx, null);

    adapter.recordRoleCreated(event);

    AuthEvent captured = captureRecordedEvent();
    assertThat(captured.getId()).isEqualTo(GENERATED_ID);
    assertThat(captured.getEventType()).isEqualTo("ROLE_CREATED");
    assertThat(captured.getOutcome()).isEqualTo("SUCCESS");
    // Load-bearing (design §6.1/§6.3): these events have no subject user, so user_id stays NULL
    // rather than being set to the actor — never "for consistency" with the assign/revoke events.
    assertThat(captured.getUserId()).isNull();
    assertThat(captured.getTenantId()).isEqualTo(TENANT_ID);
    assertThat(captured.getIpAddress()).isEqualTo("127.0.0.1");
    assertThat(captured.getUserAgent()).isEqualTo("test-agent");

    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("traceId").asString()).isEqualTo("trace-create");
    assertThat(metadata.get("roleId").asString()).isEqualTo(ROLE_ID.toString());
    assertThat(metadata.get("roleName").asString()).isEqualTo("Billing Manager");
    assertThat(metadata.get("createdBy").asString()).isEqualTo(ACTOR_USER_ID.toString());
  }

  @Test
  void should_omitPermissionFieldKeys_when_roleCreatedEventHasNullPermissionFields() {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-create-omit", "test-agent");
    RoleAuditEvent event =
        new RoleAuditEvent(TENANT_ID, ROLE_ID, "Billing Manager", null, null, ACTOR_USER_ID, ctx, null);

    adapter.recordRoleCreated(event);

    AuthEvent captured = captureRecordedEvent();
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.has("permissionId")).isFalse();
    assertThat(metadata.has("permissionName")).isFalse();
    // never a JSON null either
    assertThat(metadata.toString()).doesNotContain("null");
  }

  @Test
  void should_mapAllFieldsCorrectly_when_recordRolePermissionGrantedCalled() {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-grant", "test-agent");
    RoleAuditEvent event =
        new RoleAuditEvent(
            TENANT_ID,
            ROLE_ID,
            "Billing Manager",
            PERMISSION_ID,
            "user:read",
            ACTOR_USER_ID,
            ctx,
            null);

    adapter.recordRolePermissionGranted(event);

    AuthEvent captured = captureRecordedEvent();
    assertThat(captured.getEventType()).isEqualTo("ROLE_PERMISSION_GRANTED");
    assertThat(captured.getOutcome()).isEqualTo("SUCCESS");
    assertThat(captured.getUserId()).isNull();
    assertThat(captured.getTenantId()).isEqualTo(TENANT_ID);

    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("traceId").asString()).isEqualTo("trace-grant");
    assertThat(metadata.get("roleId").asString()).isEqualTo(ROLE_ID.toString());
    assertThat(metadata.get("roleName").asString()).isEqualTo("Billing Manager");
    assertThat(metadata.get("permissionId").asString()).isEqualTo(PERMISSION_ID.toString());
    assertThat(metadata.get("permissionName").asString()).isEqualTo("user:read");
    assertThat(metadata.get("grantedBy").asString()).isEqualTo(ACTOR_USER_ID.toString());
    assertThat(metadata.has("revokedBy")).isFalse();
    assertThat(metadata.has("createdBy")).isFalse();
  }

  /**
   * D13 (03-design.md §4.7): {@code holderCount} is populated only on the dangerous-attach path
   * and is persisted after {@code permissionName} in the metadata key order.
   */
  @Test
  void should_includeHolderCountAfterPermissionName_when_dangerousAttachHasHolders() {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-holder-count", "test-agent");
    RoleAuditEvent event =
        new RoleAuditEvent(
            TENANT_ID, ROLE_ID, "Billing Manager", PERMISSION_ID, "user:write", ACTOR_USER_ID, ctx, 3);

    adapter.recordRolePermissionGranted(event);

    AuthEvent captured = captureRecordedEvent();
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("holderCount").asInt()).isEqualTo(3);
    String raw = captured.getMetadata();
    assertThat(raw.indexOf("\"permissionName\"")).isLessThan(raw.indexOf("\"holderCount\""));
  }

  @Test
  void should_omitHolderCountKey_when_roleAuditEventHolderCountIsNull() {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-holder-count-absent", "test-agent");
    RoleAuditEvent event =
        new RoleAuditEvent(
            TENANT_ID, ROLE_ID, "Billing Manager", PERMISSION_ID, "user:write", ACTOR_USER_ID, ctx, null);

    adapter.recordRolePermissionGranted(event);

    AuthEvent captured = captureRecordedEvent();
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.has("holderCount")).isFalse();
    // never a JSON null either
    assertThat(metadata.toString()).doesNotContain("null");
    assertThat(metadata.get("grantedBy").asString()).isEqualTo(ACTOR_USER_ID.toString());
  }

  @Test
  void should_mapAllFieldsCorrectly_when_recordRolePermissionRevokedCalled() {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-revoke", "test-agent");
    RoleAuditEvent event =
        new RoleAuditEvent(
            TENANT_ID,
            ROLE_ID,
            "Billing Manager",
            PERMISSION_ID,
            "user:read",
            ACTOR_USER_ID,
            ctx,
            null);

    adapter.recordRolePermissionRevoked(event);

    AuthEvent captured = captureRecordedEvent();
    assertThat(captured.getEventType()).isEqualTo("ROLE_PERMISSION_REVOKED");
    assertThat(captured.getOutcome()).isEqualTo("SUCCESS");
    assertThat(captured.getUserId()).isNull();

    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("permissionId").asString()).isEqualTo(PERMISSION_ID.toString());
    assertThat(metadata.get("permissionName").asString()).isEqualTo("user:read");
    assertThat(metadata.get("revokedBy").asString()).isEqualTo(ACTOR_USER_ID.toString());
    assertThat(metadata.has("grantedBy")).isFalse();
  }

  /**
   * Adversarial corpus for the tenant-controlled {@code roleName}/{@code permissionName} pair
   * (threat model T-T8): quotes, backslashes, control characters, and the two Unicode line
   * terminators U+2028/U+2029 that {@code \p{Cntrl}} does not cover.
   */
  static Stream<Arguments> adversarialRoleAndPermissionNames() {
    return Stream.of(
        Arguments.of("quote", "Billing\"Manager"),
        Arguments.of("backslash", "Billing\\Manager"),
        Arguments.of("controlChar", "Billing" + (char) 0 + "Manager"),
        Arguments.of("lineSeparatorU2028", "Billing Manager"),
        Arguments.of("paragraphSeparatorU2029", "Billing Manager"));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("adversarialRoleAndPermissionNames")
  void should_escapeAdversarialRoleAndPermissionName_when_metadataSerialised(
      String label, String value) {
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-adv-role", "agent");
    RoleAuditEvent event =
        new RoleAuditEvent(
            TENANT_ID, ROLE_ID, value, PERMISSION_ID, value, ACTOR_USER_ID, ctx, null);

    adapter.recordRolePermissionGranted(event);

    AuthEvent captured = captureRecordedEvent();
    // Must round-trip as valid JSON with both fields preserved as plain string values — never
    // interpreted as JSON structure.
    JsonNode metadata = objectMapper.readTree(captured.getMetadata());
    assertThat(metadata.get("roleName").isString()).isTrue();
    assertThat(metadata.get("roleName").asString()).isEqualTo(value);
    assertThat(metadata.get("permissionName").isString()).isTrue();
    assertThat(metadata.get("permissionName").asString()).isEqualTo(value);
    // The real traceId must survive untouched regardless of what roleName/permissionName try to
    // inject.
    assertThat(metadata.get("traceId").asString()).isEqualTo("trace-adv-role");
  }

  @Test
  void should_notPropagateException_when_secureEventServiceThrowsOnCreateRole() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RoleAuditEvent event =
        new RoleAuditEvent(TENANT_ID, ROLE_ID, "Billing Manager", null, null, ACTOR_USER_ID, ctx, null);

    assertThatCode(() -> adapter.recordRoleCreated(event)).doesNotThrowAnyException();
  }

  @Test
  void should_incrementAuditWriteFailedCounterWithCreateRoleTag_when_recordRoleCreatedFails() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RoleAuditEvent event =
        new RoleAuditEvent(TENANT_ID, ROLE_ID, "Billing Manager", null, null, ACTOR_USER_ID, ctx, null);

    adapter.recordRoleCreated(event);

    double count =
        meterRegistry
            .get("nexus.rbac.audit_write_failed")
            .tag("operation", "createRole")
            .counter()
            .count();
    assertThat(count).isEqualTo(1.0);
  }

  @Test
  void should_notPropagateException_when_secureEventServiceThrowsOnGrantPermission() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RoleAuditEvent event =
        new RoleAuditEvent(
            TENANT_ID,
            ROLE_ID,
            "Billing Manager",
            PERMISSION_ID,
            "user:read",
            ACTOR_USER_ID,
            ctx,
            null);

    assertThatCode(() -> adapter.recordRolePermissionGranted(event)).doesNotThrowAnyException();
  }

  @Test
  void should_incrementAuditWriteFailedCounterWithGrantPermissionTag_when_recordRolePermissionGrantedFails() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RoleAuditEvent event =
        new RoleAuditEvent(
            TENANT_ID,
            ROLE_ID,
            "Billing Manager",
            PERMISSION_ID,
            "user:read",
            ACTOR_USER_ID,
            ctx,
            null);

    adapter.recordRolePermissionGranted(event);

    double count =
        meterRegistry
            .get("nexus.rbac.audit_write_failed")
            .tag("operation", "grantPermission")
            .counter()
            .count();
    assertThat(count).isEqualTo(1.0);
  }

  @Test
  void should_logErrorWithLostAuditMarker_when_secureEventServiceThrowsOnGrantPermission() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RoleAuditEvent event =
        new RoleAuditEvent(
            TENANT_ID,
            ROLE_ID,
            "Billing Manager",
            PERMISSION_ID,
            "user:read",
            ACTOR_USER_ID,
            ctx,
            null);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      adapter.recordRolePermissionGranted(event);

      var errorEvents =
          appender.list.stream().filter(e -> e.getLevel() == Level.ERROR).toList();
      assertThat(errorEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(errorEvents.get(0));
      assertThat(keyValues)
          .containsEntry("event", "RBAC_AUDIT_WRITE_LOST")
          .containsEntry("tenantId", TENANT_ID)
          .containsEntry("roleId", ROLE_ID)
          .containsEntry("actorUserId", ACTOR_USER_ID)
          .containsEntry("traceId", "trace-fail");
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_notPropagateException_when_secureEventServiceThrowsOnRevokePermission() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RoleAuditEvent event =
        new RoleAuditEvent(
            TENANT_ID,
            ROLE_ID,
            "Billing Manager",
            PERMISSION_ID,
            "user:read",
            ACTOR_USER_ID,
            ctx,
            null);

    assertThatCode(() -> adapter.recordRolePermissionRevoked(event)).doesNotThrowAnyException();
  }

  @Test
  void should_incrementAuditWriteFailedCounterWithRevokePermissionTag_when_recordRolePermissionRevokedFails() {
    doThrow(new RuntimeException("db down")).when(secureEventService).recordEvent(any());
    RequestContext ctx = new RequestContext("127.0.0.1", "trace-fail", "agent");
    RoleAuditEvent event =
        new RoleAuditEvent(
            TENANT_ID,
            ROLE_ID,
            "Billing Manager",
            PERMISSION_ID,
            "user:read",
            ACTOR_USER_ID,
            ctx,
            null);

    adapter.recordRolePermissionRevoked(event);

    double count =
        meterRegistry
            .get("nexus.rbac.audit_write_failed")
            .tag("operation", "revokePermission")
            .counter()
            .count();
    assertThat(count).isEqualTo(1.0);
  }

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  private AuthEvent captureRecordedEvent() {
    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(captor.capture());
    return captor.getValue();
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
}
