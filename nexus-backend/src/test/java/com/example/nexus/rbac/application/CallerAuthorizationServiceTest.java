package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.application.CallerAuthorizationService.CallerAuthorization;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.rbac.application.port.out.DirectoryUser;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.RoleRef;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import com.example.nexus.common.domain.TenantSuspendedException;

/**
 * US-019 T-008 (design §6.2, T-S13): the caller's live authorization profile. The administrator
 * answer comes from the one predicate (M13 + M15), never the cache or a copy of the rule.
 */
@Tag("UnitTest")
class CallerAuthorizationServiceTest {

  private static final UUID USER = UUID.fromString("0190a000-0000-7000-8000-000000000001");
  private static final UUID TENANT = UUID.fromString("0190a000-0000-7000-8000-000000000002");
  private static final UUID ROLE_A = UUID.fromString("0190a000-0000-7000-8000-00000000000a");
  private static final UUID ROLE_B = UUID.fromString("0190a000-0000-7000-8000-00000000000b");
  private static final UUID P1 = UUID.fromString("0190a000-0000-7000-8000-0000000000f1");
  private static final UUID P2 = UUID.fromString("0190a000-0000-7000-8000-0000000000f2");
  private static final RoleChangeActor ACTOR = new RoleChangeActor(USER, TENANT);

  private UserRoleQueryPort userRoleQueryPort;
  private UserRoleAssignmentPort userRoleAssignmentPort;
  private SimpleMeterRegistry registry;
  private UserDirectoryPort userDirectoryPort;
  private CallerAuthorizationService service;

  @BeforeEach
  void setUp() {
    userRoleQueryPort = mock(UserRoleQueryPort.class);
    userRoleAssignmentPort = mock(UserRoleAssignmentPort.class);
    userDirectoryPort = mock(UserDirectoryPort.class);
    when(userDirectoryPort.findUser(USER)).thenReturn(Optional.of(new DirectoryUser(TENANT, true)));
    registry = new SimpleMeterRegistry();
    service =
        new CallerAuthorizationService(
            userRoleQueryPort, userRoleAssignmentPort, registry, userDirectoryPort);
  }

  @Test
  void should_throwAccessDeniedException_when_callerTenantIsSuspended() {
    when(userDirectoryPort.findUser(USER)).thenReturn(Optional.of(new DirectoryUser(TENANT, false)));

    org.assertj.core.api.Assertions.assertThatThrownBy(() -> service.read(ACTOR))
        .isInstanceOf(TenantSuspendedException.class)
        .hasMessage("Tenant suspended or disabled");
  }

  @Test
  void should_throwResourceNotFoundException_when_callerTenantMismatch() {
    UUID otherTenant = UUID.randomUUID();
    when(userDirectoryPort.findUser(USER))
        .thenReturn(Optional.of(new DirectoryUser(otherTenant, true)));

    org.assertj.core.api.Assertions.assertThatThrownBy(() -> service.read(ACTOR))
        .isInstanceOf(ResourceNotFoundException.class);
  }

  @Test
  void should_askTheOnePredicateWithM13AndM15_when_readingTheCallersProfile() {
    service.read(ACTOR);

    verify(userRoleAssignmentPort).findHeldRolePermissionIdsForAuthorization(USER, TENANT);
    verify(userRoleAssignmentPort).findCatalogueIds();
  }

  @Test
  void should_answerAdministrator_when_oneHeldRoleCarriesTheWholeCatalogue() {
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(USER, TENANT))
        .thenReturn(List.of(new RolePermissionRef(ROLE_A, P1), new RolePermissionRef(ROLE_A, P2)));
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(Set.of(P1, P2));

    assertThat(service.read(ACTOR).isAdministrator()).isTrue();
  }

  @Test
  void should_answerNotAdministrator_when_onlyTheUnionOfTwoRolesCoversTheCatalogue() {
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(USER, TENANT))
        .thenReturn(List.of(new RolePermissionRef(ROLE_A, P1), new RolePermissionRef(ROLE_B, P2)));
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(Set.of(P1, P2));

    assertThat(service.read(ACTOR).isAdministrator()).isFalse();
  }

  @Test
  void should_returnRolesAsReadAndPermissionsSortedAndDistinct_when_theCallerHoldsRoles() {
    List<RoleRef> roles = List.of(new RoleRef(ROLE_A, "Auditor"), new RoleRef(ROLE_B, "Editor"));
    when(userRoleQueryPort.findActiveRoles(USER, TENANT)).thenReturn(roles);
    when(userRoleQueryPort.findActivePermissionNames(USER, TENANT))
        .thenReturn(List.of("role:read", "audit:read", "role:read"));

    CallerAuthorization result = service.read(ACTOR);

    assertThat(result.roles()).isEqualTo(roles);
    assertThat(result.permissions()).containsExactly("audit:read", "role:read");
  }

  @Test
  void should_returnTheEmptyShape_when_theCallerHoldsNoRole() {
    assertThat(service.read(ACTOR))
        .isEqualTo(new CallerAuthorization(List.of(), List.of(), false));
  }

  @Test
  void should_countTheReadTaggedByAdministratorStatus_when_readingTheCallersProfile() {
    service.read(ACTOR);

    assertThat(
            registry
                .get("nexus.rbac.caller_authorization.reads")
                .tag("isAdministrator", "false")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void should_haveNoCacheOrResolutionCollaborator_when_constructed() {
    Constructor<?>[] constructors = CallerAuthorizationService.class.getConstructors();

    assertThat(constructors)
        .singleElement()
        .satisfies(
            constructor ->
                assertThat(Arrays.asList(constructor.getParameterTypes()))
                    .doesNotContain(PermissionCachePort.class, RoleResolutionService.class));
  }
}
