package com.example.nexus.identity.infrastructure.seed;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;

import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.interfaces.cli.BreakGlassAdminRunner;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

/**
 * Unit tests for {@link DevDataInitializer} and its two seeders. The ports are backed by small
 * in-memory maps so a re-run can be observed as "creates nothing".
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class DevDataInitializerTest {

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID ADMIN_ROLE_ID = UUID.fromString("019f6839-1810-7000-8000-00000000000a");
  private static final UUID MEMBER_ROLE_ID = UUID.fromString("019f6839-1810-7000-8000-00000000000b");
  private static final List<String> PERMISSION_NAMES =
      List.of(
          "role:read",
          "role:write",
          "user:directory:read",
          "user:read",
          "user:role:assign",
          "audit:read");

  @Mock private UserRegistrationPort userRegistrationPort;
  @Mock private PasswordHasherPort passwordHasherPort;
  @Mock private UuidGenerator uuidGenerator;
  @Mock private UserRoleAssignmentPort userRoleAssignmentPort;
  @Mock private RoleManagementPort roleManagementPort;
  @Mock private Environment environment;

  private final Map<String, User> usersByKey = new HashMap<>();
  private final Map<String, UUID> rolesByKey = new HashMap<>();
  private final Map<UUID, Set<UUID>> permissionsByRole = new HashMap<>();
  private final Map<String, UUID> assignedByByAssignment = new HashMap<>();
  private final Map<UUID, PermissionView> catalogue = new HashMap<>();
  private final AtomicInteger writes = new AtomicInteger();

  private EmailBlindIndexService emailBlindIndexService;
  private DevDataInitializer initializer;

  @BeforeEach
  void setUp() {
    emailBlindIndexService =
        new EmailBlindIndexService("dev-not-a-secret-hmac-key-min-32-bytes-long".getBytes());
    PERMISSION_NAMES.forEach(
        name -> {
          UUID id = UUID.randomUUID();
          catalogue.put(id, new PermissionView(id, name, name));
        });
    rolesByKey.put(key(TENANT_ID, RbacRoleNames.TENANT_ADMIN), ADMIN_ROLE_ID);
    rolesByKey.put(key(TENANT_ID, RbacRoleNames.MEMBER), MEMBER_ROLE_ID);
    wirePorts();
    lenient().when(environment.getActiveProfiles()).thenReturn(new String[] {"dev"});

    DevUserSeeder userSeeder =
        new DevUserSeeder(
            userRegistrationPort, emailBlindIndexService, passwordHasherPort, uuidGenerator);
    DevRbacSeeder rbacSeeder = new DevRbacSeeder(roleManagementPort, userRoleAssignmentPort);
    initializer = new DevDataInitializer(userSeeder, rbacSeeder, environment, TENANT_ID);
  }

  @Test
  void should_createNothing_when_runAgainOnSeededDatabase() {
    initializer.run(null);
    int writesAfterFirstRun = writes.get();
    int usersAfterFirstRun = usersByKey.size();

    initializer.run(null);

    assertThat(writes.get()).isEqualTo(writesAfterFirstRun);
    assertThat(usersByKey).hasSize(usersAfterFirstRun);
  }

  @Test
  void should_assignEachPersonaItsRoles_when_seeding() {
    initializer.run(null);

    assertThat(rolesHeldBy(DevUserSeeder.E2E_EMAIL)).containsExactly(RbacRoleNames.TENANT_ADMIN);
    assertThat(rolesHeldBy(DevUserSeeder.SECOND_ADMIN_EMAIL))
        .containsExactly(RbacRoleNames.TENANT_ADMIN);
    assertThat(rolesHeldBy(DevUserSeeder.MEMBER_EMAIL)).containsExactly(RbacRoleNames.MEMBER);
    assertThat(rolesHeldBy(DevUserSeeder.ROLE_MANAGER_EMAIL))
        .containsExactly(DevDataInitializer.ROLE_MANAGER_ROLE);
    assertThat(rolesHeldBy(DevUserSeeder.USER_MANAGER_EMAIL))
        .containsExactly(DevDataInitializer.USER_MANAGER_ROLE);
    assertThat(rolesHeldBy(DevUserSeeder.LOCKED_EMAIL)).containsExactly(RbacRoleNames.MEMBER);
    assertThat(rolesHeldBy(DevUserSeeder.PENDING_EMAIL)).isEmpty();
  }

  @Test
  void should_attachTheDocumentedPermissions_when_seedingCustomRoles() {
    initializer.run(null);

    assertThat(permissionNamesOf(TENANT_ID, DevDataInitializer.ROLE_MANAGER_ROLE))
        .containsExactlyInAnyOrder("role:read", "role:write");
    assertThat(permissionNamesOf(TENANT_ID, DevDataInitializer.USER_MANAGER_ROLE))
        .containsExactlyInAnyOrder("user:read", "user:role:assign", "user:directory:read");
  }

  @Test
  void should_buildSecondTenantAdminRoleFromFindAllPermissions_when_seeding() {
    initializer.run(null);

    UUID roleId = rolesByKey.get(key(DevUserSeeder.SECOND_TENANT_ID, DevDataInitializer.DEV_ADMIN_ROLE));
    assertThat(permissionsByRole.get(roleId)).isEqualTo(catalogue.keySet());
  }

  @Test
  void should_holdSecondTenantAdminRoleOnFixedUser_when_seeding() {
    initializer.run(null);

    User user = userByEmail(DevUserSeeder.SECOND_TENANT_ADMIN_EMAIL, DevUserSeeder.SECOND_TENANT_ID);
    assertThat(user.getId()).isEqualTo(DevUserSeeder.SECOND_TENANT_ADMIN_ID);
    assertThat(user.getTenantId()).isEqualTo(DevUserSeeder.SECOND_TENANT_ID);
    assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
  }

  @Test
  void should_neverAssignAPersonaToItself_when_seeding() {
    initializer.run(null);
    UUID admin = userByEmail(DevUserSeeder.E2E_EMAIL, TENANT_ID).getId();

    List<String> personaEmails =
        List.of(
            DevUserSeeder.SECOND_ADMIN_EMAIL,
            DevUserSeeder.MEMBER_EMAIL,
            DevUserSeeder.ROLE_MANAGER_EMAIL,
            DevUserSeeder.USER_MANAGER_EMAIL,
            DevUserSeeder.LOCKED_EMAIL);
    for (String email : personaEmails) {
      UUID personaId = userByEmail(email, TENANT_ID).getId();
      List<UUID> assigners =
          assignedByByAssignment.entrySet().stream()
              .filter(e -> e.getKey().startsWith(personaId.toString()))
              .map(Map.Entry::getValue)
              .toList();
      assertThat(assigners).as(email).isNotEmpty().containsOnly(admin);
    }
  }

  @Test
  void should_keepRootAdministratorSelfAssigned_when_seeding() {
    initializer.run(null);
    UUID admin = userByEmail(DevUserSeeder.E2E_EMAIL, TENANT_ID).getId();

    assertThat(assignedByByAssignment).containsEntry(admin + "/" + ADMIN_ROLE_ID, admin);
  }

  @Test
  void should_lockFarIntoTheFuture_when_seedingTheLockedUser() {
    initializer.run(null);

    User locked = userByEmail(DevUserSeeder.LOCKED_EMAIL, TENANT_ID);
    assertThat(locked.getStatus()).isEqualTo(UserStatus.LOCKED);
    assertThat(locked.getLockedUntil()).isAfter(Instant.now().plus(Duration.ofDays(3650)));
  }

  @Test
  void should_leavePendingUserUnverified_when_seeding() {
    initializer.run(null);

    User pending = userByEmail(DevUserSeeder.PENDING_EMAIL, TENANT_ID);
    assertThat(pending.getStatus()).isEqualTo(UserStatus.PENDING);
  }

  @Test
  void should_failTheWholeSeed_when_aNamedPermissionIsMissingFromTheCatalogue() {
    catalogue.values().removeIf(p -> p.name().equals("role:write"));

    assertThatThrownBy(() -> initializer.run(null)).isInstanceOf(IllegalStateException.class);
  }

  // US-018 T-008 / US-019 T-023 (RC-63(g)): the dev seed grants TENANT_ADMIN without any check, so
  // it must never run in a break-glass or prod process.

  @ParameterizedTest
  @ValueSource(strings = {"break-glass", "dev,break-glass", "dev,prod", "prod"})
  void should_notActivate_when_breakGlassOrProdProfileActive(String activeProfiles) {
    Set<String> active = Set.of(activeProfiles.split(","));

    for (Class<?> bean : seedBeans()) {
      assertThat(isActive(bean, active)).as(bean.getSimpleName()).isFalse();
    }
    assertThat(isActive(BreakGlassAdminRunner.class, active))
        .isEqualTo(active.contains("break-glass"));
  }

  @Test
  void should_activateOnlyTheDevSeed_when_onlyDevProfileActive() {
    Set<String> active = Set.of("dev");

    for (Class<?> bean : seedBeans()) {
      assertThat(isActive(bean, active)).as(bean.getSimpleName()).isTrue();
    }
    assertThat(isActive(BreakGlassAdminRunner.class, active)).isFalse();
  }

  private static List<Class<?>> seedBeans() {
    return List.of(DevDataInitializer.class, DevUserSeeder.class, DevRbacSeeder.class);
  }

  private static boolean isActive(Class<?> bean, Set<String> activeProfiles) {
    Profile profile = bean.getAnnotation(Profile.class);
    assertThat(profile).as("%s must be profile-gated", bean.getSimpleName()).isNotNull();
    return Profiles.of(profile.value()).matches(activeProfiles::contains);
  }

  private User userByEmail(String email, UUID tenantId) {
    return usersByKey.get(key(tenantId, emailBlindIndexService.blindIndex(email)));
  }

  private List<String> rolesHeldBy(String email) {
    UUID userId = userByEmail(email, TENANT_ID).getId();
    Map<UUID, String> roleNames =
        rolesByKey.entrySet().stream()
            .collect(Collectors.toMap(Map.Entry::getValue, e -> e.getKey().split("/", 2)[1]));
    List<String> held = new ArrayList<>();
    assignedByByAssignment
        .keySet()
        .forEach(
            k -> {
              String[] parts = k.split("/");
              if (parts[0].equals(userId.toString())) {
                held.add(roleNames.get(UUID.fromString(parts[1])));
              }
            });
    return held;
  }

  private Set<String> permissionNamesOf(UUID tenantId, String roleName) {
    return permissionsByRole.get(rolesByKey.get(key(tenantId, roleName))).stream()
        .map(id -> catalogue.get(id).name())
        .collect(Collectors.toSet());
  }

  private static String key(UUID tenantId, String second) {
    return tenantId + "/" + second;
  }

  private void wirePorts() {
    lenient()
        .when(userRegistrationPort.findByTenantAndEmailHmac(any(), anyString()))
        .thenAnswer(
            inv ->
                java.util.Optional.ofNullable(
                    usersByKey.get(key(inv.getArgument(0), inv.getArgument(1)))));
    lenient()
        .when(userRegistrationPort.save(any(User.class)))
        .thenAnswer(
            inv -> {
              User user = inv.getArgument(0);
              if (usersByKey.values().stream().noneMatch(u -> u == user)) {
                writes.incrementAndGet();
              }
              usersByKey.put(key(user.getTenantId(), user.getEmailHmac()), user);
              return user;
            });
    lenient().when(uuidGenerator.newId()).thenAnswer(inv -> UUID.randomUUID());
    lenient().when(passwordHasherPort.hash(anyString())).thenReturn("hashed-password");

    lenient()
        .when(roleManagementPort.findAllPermissions(anyInt(), anyInt()))
        .thenAnswer(
            inv -> {
              List<PermissionView> all = new ArrayList<>(catalogue.values());
              return new PageResult<>(all, all.size(), inv.getArgument(0), inv.getArgument(1));
            });
    lenient()
        .when(roleManagementPort.createRole(any(), anyString(), anyString()))
        .thenAnswer(
            inv -> {
              UUID id = UUID.randomUUID();
              rolesByKey.put(key(inv.getArgument(0), inv.getArgument(1)), id);
              permissionsByRole.put(id, new HashSet<>());
              writes.incrementAndGet();
              return id;
            });
    lenient()
        .when(roleManagementPort.hasPermission(any(), any()))
        .thenAnswer(
            inv ->
                permissionsByRole
                    .getOrDefault(inv.<UUID>getArgument(0), Set.of())
                    .contains(inv.<UUID>getArgument(1)));
    lenient()
        .doAnswer(
            inv -> {
              permissionsByRole
                  .computeIfAbsent(inv.getArgument(0), k -> new HashSet<>())
                  .add(inv.getArgument(1));
              writes.incrementAndGet();
              return null;
            })
        .when(roleManagementPort)
        .attachPermission(any(), any());

    lenient()
        .when(userRoleAssignmentPort.findRoleIdByName(any(), anyString()))
        .thenAnswer(
            inv ->
                java.util.Optional.ofNullable(
                    rolesByKey.get(key(inv.getArgument(0), inv.getArgument(1)))));
    lenient()
        .when(userRoleAssignmentPort.hasActiveAssignment(any(), any()))
        .thenAnswer(
            inv ->
                assignedByByAssignment.containsKey(
                    inv.<UUID>getArgument(0) + "/" + inv.<UUID>getArgument(1)));
    lenient()
        .when(userRoleAssignmentPort.assign(any(), any(), any(), any()))
        .thenAnswer(
            inv -> {
              assignedByByAssignment.put(
                  inv.<UUID>getArgument(0) + "/" + inv.<UUID>getArgument(1),
                  inv.getArgument(3));
              writes.incrementAndGet();
              return UUID.randomUUID();
            });
  }
}
