package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.EffectivePermission;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionHolder;
import com.example.nexus.rbac.domain.PermissionViaRole;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleHolder;
import com.example.nexus.rbac.domain.RolePermissionRef;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

/** Unit tests for {@link AccessReviewService} (US-018 T-029, C3): tenant scoping, redaction, signals. */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class AccessReviewServiceTest {

  private static final UUID P1 = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID P2 = UUID.fromString("00000000-0000-7000-8000-000000000002");
  private static final Set<UUID> CATALOGUE = Set.of(P1, P2);

  @Mock private UserRoleAssignmentPort assignmentPort;
  @Mock private UserRoleQueryPort queryPort;
  @Mock private UserDirectoryPort directoryPort;

  private SimpleMeterRegistry meterRegistry;
  private AccessReviewService service;
  private RoleChangeActor actor;
  private UUID tenantId;
  private UUID otherTenantId;
  private UUID roleId;
  private ListAppender<ILoggingEvent> appender;
  private Logger serviceLogger;

  @BeforeEach
  void setUp() {
    meterRegistry = new SimpleMeterRegistry();
    service = new AccessReviewService(assignmentPort, queryPort, directoryPort, meterRegistry);
    tenantId = UUID.randomUUID();
    otherTenantId = UUID.randomUUID();
    roleId = UUID.randomUUID();
    actor = new RoleChangeActor(UUID.randomUUID(), tenantId);
    serviceLogger = (Logger) LoggerFactory.getLogger(AccessReviewService.class);
    appender = new ListAppender<>();
    appender.start();
    serviceLogger.addAppender(appender);
  }

  @AfterEach
  void tearDown() {
    serviceLogger.detachAppender(appender);
    appender.stop();
  }

  private Role role(UUID tenant) {
    return new Role(roleId, tenant, "Reviewers", null, false);
  }

  private void callerIsAdministrator(boolean administrator) {
    UUID heldRole = UUID.randomUUID();
    List<RolePermissionRef> held =
        administrator
            ? List.of(new RolePermissionRef(heldRole, P1), new RolePermissionRef(heldRole, P2))
            : List.of(new RolePermissionRef(heldRole, P1));
    when(assignmentPort.findHeldRolePermissionIdsForAuthorization(actor.userId(), tenantId))
        .thenReturn(held);
    when(assignmentPort.findCatalogueIds()).thenReturn(CATALOGUE);
  }

  private static PageResult<RoleHolder> holders(UUID assignedBy) {
    return new PageResult<>(
        List.of(new RoleHolder(UUID.randomUUID(), UUID.randomUUID(), Instant.now(), assignedBy)),
        1,
        0,
        20);
  }

  // ── role holders ───────────────────────────────────────────────────────────────────────

  @Test
  void should_keepAssignedBy_when_theCallerIsAnAdministrator() {
    UUID assigner = UUID.randomUUID();
    when(assignmentPort.findRole(roleId)).thenReturn(Optional.of(role(tenantId)));
    when(assignmentPort.findActiveRoleHolders(roleId, tenantId, 0, 20)).thenReturn(holders(assigner));
    callerIsAdministrator(true);

    PageResult<RoleHolder> result = service.listRoleHolders(actor, roleId, 0, 20);

    assertThat(result.items()).extracting(RoleHolder::assignedBy).containsExactly(assigner);
  }

  /** T-I17 / R1-4: a non-administrator audit:read holder must not read who assigned whom. */
  @Test
  void should_redactAssignedBy_when_theCallerIsNotAnAdministrator() {
    when(assignmentPort.findRole(roleId)).thenReturn(Optional.of(role(tenantId)));
    when(assignmentPort.findActiveRoleHolders(roleId, tenantId, 0, 20))
        .thenReturn(holders(UUID.randomUUID()));
    callerIsAdministrator(false);

    PageResult<RoleHolder> result = service.listRoleHolders(actor, roleId, 0, 20);

    assertThat(result.items()).extracting(RoleHolder::assignedBy).containsOnlyNulls();
    assertThat(result.items()).extracting(RoleHolder::userId).doesNotContainNull();
  }

  @Test
  void should_redactAssignedBy_when_aUnionHolderIsNoAdministrator() {
    UUID a = UUID.randomUUID();
    UUID b = UUID.randomUUID();
    when(assignmentPort.findRole(roleId)).thenReturn(Optional.of(role(tenantId)));
    when(assignmentPort.findActiveRoleHolders(roleId, tenantId, 0, 20))
        .thenReturn(holders(UUID.randomUUID()));
    when(assignmentPort.findHeldRolePermissionIdsForAuthorization(actor.userId(), tenantId))
        .thenReturn(List.of(new RolePermissionRef(a, P1), new RolePermissionRef(b, P2)));
    when(assignmentPort.findCatalogueIds()).thenReturn(CATALOGUE);

    assertThat(service.listRoleHolders(actor, roleId, 0, 20).items())
        .extracting(RoleHolder::assignedBy)
        .containsOnlyNulls();
  }

  @Test
  void should_throwRoleNotFound_when_theRoleIsMissingOrDeleted() {
    when(assignmentPort.findRole(roleId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.listRoleHolders(actor, roleId, 0, 20))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verify(assignmentPort, never()).findActiveRoleHolders(any(), any(), org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.anyInt());
  }

  @Test
  void should_throwTheSameNotFoundWithWarnAndCounter_when_theRoleBelongsToAnotherTenant() {
    when(assignmentPort.findRole(roleId)).thenReturn(Optional.of(role(otherTenantId)));

    assertThatThrownBy(() -> service.listRoleHolders(actor, roleId, 0, 20))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND")
        .hasMessage("No such role");

    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_denied")
                .tag("permission", "audit:read")
                .tag("reason", "CROSS_TENANT_TARGET")
                .counter()
                .count())
        .isEqualTo(1.0);
    assertThat(appender.list)
        .anySatisfy(
            e -> {
              assertThat(e.getLevel()).isEqualTo(Level.WARN);
              assertThat(e.getKeyValuePairs()).anyMatch(kv -> "RBAC_CROSS_TENANT_TARGET".equals(kv.value));
              assertThat(e.getKeyValuePairs())
                  .noneMatch(kv -> String.valueOf(kv.value).contains(otherTenantId.toString()));
            });
    verify(assignmentPort, never()).findActiveRoleHolders(any(), any(), org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.anyInt());
  }

  @Test
  void should_scopeTheHolderReadToTheActorsTenant_andEmitTheQuerySignal() {
    when(assignmentPort.findRole(roleId)).thenReturn(Optional.of(role(tenantId)));
    when(assignmentPort.findActiveRoleHolders(roleId, tenantId, 2, 5)).thenReturn(holders(null));
    callerIsAdministrator(true);

    service.listRoleHolders(actor, roleId, 2, 5);

    verify(assignmentPort).findActiveRoleHolders(roleId, tenantId, 2, 5);
    assertThat(meterRegistry.get("nexus.rbac.access_review_query").tag("endpoint", "role_holders").counter().count())
        .isEqualTo(1.0);
    assertThat(appender.list)
        .anySatisfy(
            e -> {
              assertThat(e.getLevel()).isEqualTo(Level.INFO);
              assertThat(e.getKeyValuePairs())
                  .anyMatch(kv -> "RBAC_ACCESS_REVIEW_QUERY".equals(kv.value));
              assertThat(e.getKeyValuePairs())
                  .anyMatch(kv -> "subjectId".equals(kv.key) && roleId.equals(kv.value));
              assertThat(e.getKeyValuePairs())
                  .anyMatch(kv -> "actorUserId".equals(kv.key) && actor.userId().equals(kv.value));
            });
  }

  @Test
  void should_notEmitTheQuerySignal_when_theTargetIsNotFound() {
    when(assignmentPort.findRole(roleId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.listRoleHolders(actor, roleId, 0, 20))
        .isInstanceOf(ResourceNotFoundException.class);

    assertThat(meterRegistry.find("nexus.rbac.access_review_query").counter()).isNull();
  }

  // ── permission holders ─────────────────────────────────────────────────────────────────

  @Test
  void should_returnThePermissionHoldersOfTheActorsTenant_when_thePermissionExists() {
    UUID user = UUID.randomUUID();
    PageResult<PermissionHolder> page =
        new PageResult<>(List.of(new PermissionHolder(user, List.of(roleId))), 1, 0, 20);
    when(assignmentPort.findCatalogueIds()).thenReturn(CATALOGUE);
    when(assignmentPort.findPermissionHolders(P1, tenantId, 0, 20)).thenReturn(page);

    PageResult<PermissionHolder> result = service.listPermissionHolders(actor, P1, 0, 20);

    assertThat(result).isSameAs(page);
    assertThat(
            meterRegistry
                .get("nexus.rbac.access_review_query")
                .tag("endpoint", "permission_holders")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void should_throwPermissionNotFound_when_thePermissionIsNotInTheCatalogue() {
    when(assignmentPort.findCatalogueIds()).thenReturn(CATALOGUE);

    assertThatThrownBy(() -> service.listPermissionHolders(actor, UUID.randomUUID(), 0, 20))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "PERMISSION_NOT_FOUND");

    verify(assignmentPort, never()).findPermissionHolders(any(), any(), org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.anyInt());
  }

  // ── effective permissions ──────────────────────────────────────────────────────────────

  @Test
  void should_groupRolesPerPermissionName_when_aUserHoldsAPermissionThroughTwoRoles() {
    UUID user = UUID.randomUUID();
    UUID roleA = UUID.randomUUID();
    UUID roleB = UUID.randomUUID();
    when(directoryPort.findTenantId(user)).thenReturn(Optional.of(tenantId));
    when(queryPort.findActivePermissionsViaRoles(user, tenantId))
        .thenReturn(
            List.of(
                new PermissionViaRole("audit:read", roleA),
                new PermissionViaRole("audit:read", roleB),
                new PermissionViaRole("user:read", roleA)));

    List<EffectivePermission> result = service.getEffectivePermissions(actor, user);

    assertThat(result)
        .containsExactly(
            new EffectivePermission("audit:read", List.of(roleA, roleB)),
            new EffectivePermission("user:read", List.of(roleA)));
  }

  @Test
  void should_returnAnEmptyList_when_theUserHoldsNothing() {
    UUID user = UUID.randomUUID();
    when(directoryPort.findTenantId(user)).thenReturn(Optional.of(tenantId));
    when(queryPort.findActivePermissionsViaRoles(user, tenantId)).thenReturn(List.of());

    assertThat(service.getEffectivePermissions(actor, user)).isEmpty();
  }

  @Test
  void should_throwUserNotFound_when_theUserDoesNotExist() {
    UUID user = UUID.randomUUID();
    when(directoryPort.findTenantId(user)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.getEffectivePermissions(actor, user))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND");
  }

  @Test
  void should_throwTheSameUserNotFoundAndReadNothing_when_theUserIsInAnotherTenant() {
    UUID user = UUID.randomUUID();
    when(directoryPort.findTenantId(user)).thenReturn(Optional.of(otherTenantId));

    assertThatThrownBy(() -> service.getEffectivePermissions(actor, user))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND")
        .hasMessage("No such user");

    verify(queryPort, never()).findActivePermissionsViaRoles(any(), any());
    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_denied")
                .tag("permission", "audit:read")
                .tag("reason", "CROSS_TENANT_TARGET")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void should_document_repeatable_read_snapshot_behavior() {
    when(assignmentPort.findRole(roleId)).thenReturn(Optional.of(role(tenantId)));
    when(assignmentPort.findActiveRoleHolders(roleId, tenantId, 0, 20))
        .thenReturn(holders(UUID.randomUUID()));
    callerIsAdministrator(true);

    PageResult<RoleHolder> result = service.listRoleHolders(actor, roleId, 0, 20);
    assertThat(result.items()).hasSize(1);
  }
}
