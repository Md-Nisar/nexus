package com.example.nexus.identity.infrastructure.seed;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionView;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * US-019 T-023 (RC-63(g), R17, T-E52): in a context whose active profiles include {@code prod} or
 * {@code break-glass}, no dev seed bean is registered, so known-password administrators can never
 * be created there. Each case is a real Spring context evaluating the {@code @Profile}
 * expressions; the seeders' collaborators are deliberately absent, because a bean that is wrongly
 * registered would fail context startup as well as be found.
 *
 * <p>US-020 T-014 (RC-77, T-E58): the {@code dev,prod} context is extended to the rows themselves.
 * With recording ports present and every registered {@link ApplicationRunner} executed, a {@code
 * dev,prod} context writes none of the new personas or assignment targets, while a {@code dev}-only
 * context writes all of them (the harness's positive control).
 */
@Tag("UnitTest")
class DevSeedProfileGuardTest {

  private static final String HMAC_KEY = "dev-not-a-secret-hmac-key-min-32-bytes-long";
  private static final List<String> NEW_PERSONA_EMAILS =
      List.of(
          DevUserSeeder.ROLE_READER_USER_MANAGER_EMAIL,
          DevUserSeeder.AUDITOR_EMAIL,
          DevUserSeeder.TARGET_A_EMAIL,
          DevUserSeeder.TARGET_B_EMAIL,
          DevUserSeeder.HIDDEN_CHARACTER_TARGET_EMAIL);
  private static final List<String> CATALOGUE_NAMES =
      List.of(
          "role:read",
          "role:write",
          "user:directory:read",
          "user:read",
          "user:role:assign",
          "audit:read");

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withUserConfiguration(DevDataInitializer.class, DevUserSeeder.class, DevRbacSeeder.class);

  private final EmailBlindIndexService blindIndex =
      new EmailBlindIndexService(HMAC_KEY.getBytes());

  @ParameterizedTest
  @ValueSource(strings = {"prod", "dev,break-glass", "dev,prod", "break-glass"})
  void should_registerNoSeederBean_when_prodOrBreakGlassProfileActive(String profiles) {
    runner
        .withPropertyValues("spring.profiles.active=" + profiles)
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context).doesNotHaveBean(DevDataInitializer.class);
              assertThat(context).doesNotHaveBean(DevUserSeeder.class);
              assertThat(context).doesNotHaveBean(DevRbacSeeder.class);
            });
  }

  @Test
  void should_writeNoNewPersonaOrTarget_when_devAndProdProfilesActive() {
    Set<String> written = seededBlindIndexes("dev,prod");

    for (String email : NEW_PERSONA_EMAILS) {
      assertThat(written).doesNotContain(blindIndex.blindIndex(email));
    }
  }

  @Test
  void should_writeEveryNewPersonaAndTarget_when_onlyDevProfileActive() {
    Set<String> written = seededBlindIndexes("dev");

    assertThat(written)
        .containsAll(NEW_PERSONA_EMAILS.stream().map(blindIndex::blindIndex).toList());
  }

  /**
   * Starts a context under {@code profiles} with recording ports, runs every registered {@link
   * ApplicationRunner} as Spring Boot would at startup, and returns the blind index of every user
   * row the seed wrote. Users are compared by blind index so no address is ever printed.
   */
  private Set<String> seededBlindIndexes(String profiles) {
    List<User> saved = new ArrayList<>();
    UserRegistrationPort users = mock(UserRegistrationPort.class);
    when(users.findByTenantAndEmailHmac(any(), anyString())).thenReturn(Optional.empty());
    when(users.save(any(User.class)))
        .thenAnswer(
            inv -> {
              saved.add(inv.getArgument(0));
              return inv.getArgument(0);
            });
    UuidGenerator ids = mock(UuidGenerator.class);
    when(ids.newId()).thenAnswer(inv -> UUID.randomUUID());
    PasswordHasherPort hasher = mock(PasswordHasherPort.class);
    when(hasher.hash(anyString())).thenReturn("hashed-password");
    RoleManagementPort roles = mock(RoleManagementPort.class);
    List<PermissionView> catalogue =
        CATALOGUE_NAMES.stream().map(n -> new PermissionView(UUID.randomUUID(), n, n)).toList();
    when(roles.findAllPermissions(anyInt(), anyInt()))
        .thenReturn(new PageResult<>(catalogue, catalogue.size(), 0, catalogue.size()));
    when(roles.createRole(any(), anyString(), anyString())).thenAnswer(inv -> UUID.randomUUID());
    UserRoleAssignmentPort assignments = mock(UserRoleAssignmentPort.class);
    when(assignments.findRoleIdByName(any(), anyString()))
        .thenAnswer(inv -> Optional.of(UUID.randomUUID()));

    runner
        .withPropertyValues(
            "spring.profiles.active=" + profiles,
            "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001")
        .withBean(UserRegistrationPort.class, () -> users)
        .withBean(EmailBlindIndexService.class, () -> blindIndex)
        .withBean(PasswordHasherPort.class, () -> hasher)
        .withBean(UuidGenerator.class, () -> ids)
        .withBean(RoleManagementPort.class, () -> roles)
        .withBean(UserRoleAssignmentPort.class, () -> assignments)
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              for (ApplicationRunner seed :
                  context.getBeansOfType(ApplicationRunner.class).values()) {
                seed.run(null);
              }
            });
    return saved.stream().map(User::getEmailHmac).collect(Collectors.toSet());
  }
}
