package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.DuplicateRoleNameException;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.domain.SystemRoleImmutableException;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-015 T-010 (AC12; Test Scenarios 11-14): proves {@code ROLE_CREATED}/{@code
 * ROLE_PERMISSION_GRANTED}/{@code ROLE_PERMISSION_REVOKED} audit rows round-trip through real
 * MySQL with the AC12 minimum field set, and that denied attempts (403/409) write no success row.
 *
 * <p>Structural mirror of {@code RoleAssignmentAuditIT}'s JSON-extraction-via-{@code JdbcTemplate}
 * pattern, adapted for the fact these three event types carry NO {@code user_id} ({@link
 * com.example.nexus.rbac.application.port.out.RoleAuditEvent} has no target user; {@code
 * auth_events.user_id} stays {@code NULL} by design, 03-design.md §6.1/§6.3). Row lookup is
 * therefore by {@code tenant_id} + {@code event_type} rather than {@code user_id} -- each test uses
 * a fresh {@code uuidGenerator.newId()} tenant, so this is unambiguous.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleManagementAuditIT {

  // role:read for the plain grant/revoke success-path scenarios (12/13) -- role:write is one of
  // AC11's 3 dangerous permissions and requires an active TENANT_ADMIN caller, which these tests
  // don't set up. DANGEROUS_PERMISSION_ID (role:write) is used deliberately, and only, by the
  // AC11-denial negative test below.
  private static final UUID SAFE_PERMISSION_ID =
      UUID.fromString("019f6839-1804-7000-8000-000000000005");
  private static final UUID DANGEROUS_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");

  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  // ── Scenario 11: create role -> ROLE_CREATED ────────────────────────────────────────────

  @Test
  void should_writeRoleCreatedEventWithCorrectFields_when_createRoleSucceeds() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    RequestContext ctx = requestContext();

    RoleView created = roleManagementService.createRole(actor, "AUDIT-CREATE-" + UUID.randomUUID(), null, ctx);

    Map<String, Object> row = findLatestAuditRow(tenantId, "ROLE_CREATED");
    assertThat(((Number) row.get("valid")).intValue()).isEqualTo(1);
    assertThat(row.get("outcome")).isEqualTo("SUCCESS");
    assertThat(toUuid((byte[]) row.get("tenant_id"))).isEqualTo(tenantId);
    assertThat(row.get("user_id")).as("ROLE_CREATED has no subject user").isNull();
    assertThat(row.get("role_id")).isEqualTo(created.id().toString());
    assertThat(row.get("role_name")).isEqualTo(created.name());
    assertThat(row.get("created_by")).isEqualTo(actor.userId().toString());
    assertThat(row.get("permission_id")).isNull();
    assertThat(row.get("permission_name")).isNull();
    assertThat(row.get("trace_id")).isEqualTo(ctx.traceId());
  }

  @Test
  void should_writeExactlyOneRoleCreatedRow_notTwo_when_secondCreateFailsWithDuplicateName() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    String name = "AUDIT-DUP-" + UUID.randomUUID();
    roleManagementService.createRole(actor, name, null, requestContext());

    assertThatThrownBy(() -> roleManagementService.createRole(actor, name, null, requestContext()))
        .isInstanceOf(DuplicateRoleNameException.class);

    assertThat(countAuditRows(tenantId, "ROLE_CREATED"))
        .as("the rolled-back duplicate attempt must not add a second ROLE_CREATED row")
        .isEqualTo(1);
  }

  // ── Scenario 12: grant permission -> ROLE_PERMISSION_GRANTED ────────────────────────────

  @Test
  void should_writeRolePermissionGrantedEventWithCorrectFields_when_attachPermissionSucceeds() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    Role role = seedRole("GRANT", tenantId);
    RequestContext ctx = requestContext();

    roleManagementService.attachPermission(actor, role.getId(), SAFE_PERMISSION_ID, ctx);

    Map<String, Object> row = findLatestAuditRow(tenantId, "ROLE_PERMISSION_GRANTED");
    assertThat(((Number) row.get("valid")).intValue()).isEqualTo(1);
    assertThat(row.get("outcome")).isEqualTo("SUCCESS");
    assertThat(row.get("role_id")).isEqualTo(role.getId().toString());
    assertThat(row.get("role_name")).isEqualTo(role.getName());
    assertThat(row.get("permission_id")).isEqualTo(SAFE_PERMISSION_ID.toString());
    assertThat(row.get("permission_name")).isEqualTo("role:read");
    assertThat(row.get("granted_by")).isEqualTo(actor.userId().toString());
    assertThat(row.get("trace_id")).isEqualTo(ctx.traceId());
  }

  // ── Scenario 13: revoke permission -> ROLE_PERMISSION_REVOKED ───────────────────────────

  @Test
  void should_writeRolePermissionRevokedEventWithRevokedByField_when_detachPermissionSucceeds() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    Role role = seedRole("REVOKE", tenantId);
    roleManagementService.attachPermission(actor, role.getId(), SAFE_PERMISSION_ID, requestContext());
    RequestContext ctx = requestContext();

    roleManagementService.detachPermission(actor, role.getId(), SAFE_PERMISSION_ID, ctx);

    Map<String, Object> row = findLatestAuditRow(tenantId, "ROLE_PERMISSION_REVOKED");
    assertThat(((Number) row.get("valid")).intValue()).isEqualTo(1);
    assertThat(row.get("outcome")).isEqualTo("SUCCESS");
    assertThat(row.get("permission_id")).isEqualTo(SAFE_PERMISSION_ID.toString());
    assertThat(row.get("permission_name")).isEqualTo("role:read");
    assertThat(row.get("revoked_by")).isEqualTo(actor.userId().toString());
    assertThat(row.get("granted_by"))
        .as("a ROLE_PERMISSION_REVOKED event must never carry a grantedBy key")
        .isNull();
  }

  // ── Scenario 14: denied attempts write no success event ────────────────────────────────

  /**
   * Uses the REAL migration-seeded bootstrap {@code TENANT_ADMIN} role (by its known literal id),
   * never a freshly created {@code is_system_role=TRUE} fixture row: {@code
   * RbacSchemaMigrationIT#should_seedExactly2SystemRoles_when_migrationApplied} asserts an
   * UNSCOPED {@code COUNT(*) WHERE is_system_role=TRUE} across this run's whole shared schema
   * (must stay exactly 2), so inserting even one more system-role row here -- regardless of
   * whether the subsequent write against it correctly fails -- would corrupt that count.
   */
  @Test
  void should_writeNoRolePermissionGrantedRow_when_attachFailsWithSystemRoleImmutable() {
    UUID bootstrapTenantId = UUID.fromString("00000000-0000-7000-8000-000000000001");
    UUID seededTenantAdminRoleId = UUID.fromString("019f6839-1810-7000-8000-00000000000a");
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), bootstrapTenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.attachPermission(
                    actor, seededTenantAdminRoleId, DANGEROUS_PERMISSION_ID, requestContext()))
        .isInstanceOf(SystemRoleImmutableException.class);

    assertThat(countAuditRows(bootstrapTenantId, "ROLE_PERMISSION_GRANTED"))
        .as("a 409 RBAC_003 denial must never write a ROLE_PERMISSION_GRANTED row")
        .isZero();
  }

  @Test
  void should_writeNoRolePermissionGrantedRow_when_attachFailsWithNotTenantAdmin() {
    UUID tenantId = uuidGenerator.newId();
    // Caller has role:write (implicit at the service layer -- no @RequiresPermission gate here)
    // but no active TENANT_ADMIN assignment.
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    Role customRole = seedRole("DENIED-ADMIN-GATE", tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.attachPermission(
                    actor, customRole.getId(), DANGEROUS_PERMISSION_ID, requestContext()))
        .isInstanceOf(InsufficientPermissionException.class);

    assertThat(countAuditRows(tenantId, "ROLE_PERMISSION_GRANTED"))
        .as("a 403 NOT_TENANT_ADMIN denial must never write a ROLE_PERMISSION_GRANTED row")
        .isZero();
  }

  // ── Fixtures / helpers ───────────────────────────────────────────────────────────────────

  private Role seedRole(String tag, UUID tenantId) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RMA-" + tag + "-" + UUID.randomUUID(), null,
            false));
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "RoleManagementAuditIT");
  }

  private Map<String, Object> findLatestAuditRow(UUID tenantId, String eventType) {
    return jdbc.queryForMap(
        "SELECT JSON_VALID(metadata) AS valid, outcome, user_id, tenant_id, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.roleId')) AS role_id, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.roleName')) AS role_name, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.permissionId')) AS permission_id, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.permissionName')) AS permission_name, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.createdBy')) AS created_by, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.grantedBy')) AS granted_by, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.revokedBy')) AS revoked_by, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.traceId')) AS trace_id "
            + "FROM auth_events WHERE tenant_id = ? AND event_type = ? ORDER BY created_at DESC"
            + " LIMIT 1",
        toBytes(tenantId), eventType);
  }

  private int countAuditRows(UUID tenantId, String eventType) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM auth_events WHERE tenant_id = ? AND event_type = ?",
            Integer.class,
            toBytes(tenantId),
            eventType);
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
