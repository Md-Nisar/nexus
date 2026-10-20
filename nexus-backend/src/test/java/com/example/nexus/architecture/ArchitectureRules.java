package com.example.nexus.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.example.nexus.common.Profiles;
import com.example.nexus.common.security.Permissions;
import com.example.nexus.identity.infrastructure.persistence.BreakGlassGrantLookupAdapter;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import com.example.nexus.rbac.interfaces.rest.PermissionController;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaFieldAccess;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * ArchUnit rules shared between {@link HexagonalArchitectureTest}, which applies them to the
 * production classes, and the fixture tests that prove each one fires. Public so a fixture test
 * in another package (its failing fixture must reside in the package the rule refuses) can reach
 * them without {@link HexagonalArchitectureTest} itself being public.
 */
public final class ArchitectureRules {

  /** US-018 A7 (EC2): the one package allowed to reach the break-glass grant. */
  public static final String BREAK_GLASS_CLI_PACKAGE = "com.example.nexus.rbac.interfaces.cli..";

  /**
   * US-018 T-007 (03-design.md §7.2, EC2): the break-glass grant has no caller to authorize, so
   * REST must never reach it.
   */
  public static final ArchRule BOOTSTRAP_ADMIN_SERVICE_IS_REACHABLE_ONLY_FROM_THE_CLI =
      noClasses()
          .that()
          .resideOutsideOfPackage(BREAK_GLASS_CLI_PACKAGE)
          .and()
          .doNotBelongToAnyOf(BootstrapAdminService.class)
          .should()
          .dependOnClassesThat()
          .belongToAnyOf(BootstrapAdminService.class)
          .because(
              "US-018 A7/EC2: BootstrapAdminService grants TENANT_ADMIN without an authorized"
                  + " caller; only the break-glass CLI in rbac.interfaces.cli may reach it, never a"
                  + " REST controller or another service.")
          .allowEmptyShould(true);

  /**
   * US-018 T-007 (EC2): neither the break-glass service nor the CLI may route through the
   * request-path grant, whose caller gate, grant-subset check and post-commit side effects assume
   * an authenticated actor.
   */
  public static final ArchRule BREAK_GLASS_NEVER_CALLS_ROLE_ASSIGNMENT_ASSIGN_OR_REVOKE =
      noClasses()
          .that()
          .belongToAnyOf(BootstrapAdminService.class)
          .or()
          .resideInAPackage(BREAK_GLASS_CLI_PACKAGE)
          .should()
          .callMethodWhere(
              DescribedPredicate.describe(
                  "target is RoleAssignmentService.assign or RoleAssignmentService.revoke",
                  (JavaMethodCall call) ->
                      call.getTargetOwner().isEquivalentTo(RoleAssignmentService.class)
                          && Set.of("assign", "revoke").contains(call.getName())))
          .because(
              "US-018 A7/EC2: the break-glass grant reuses only the M10/M11 lock helpers, never"
                  + " RoleAssignmentService.assign()/revoke().");

  /**
   * US-018 T-008 (03-design.md §7.2 Containment, ADR-0025 item 3): every Spring bean in {@code
   * rbac.interfaces.cli} carries {@code @Profile("break-glass")} and nothing else, so no CLI bean
   * loads in a serving pod or alongside {@code dev}. Must not pass vacuously: the runner is such a
   * bean.
   */
  public static final ArchRule CLI_BEANS_ARE_BREAK_GLASS_PROFILE_ONLY =
      classes()
          .that()
          .resideInAPackage(BREAK_GLASS_CLI_PACKAGE)
          .and()
          .areMetaAnnotatedWith(Component.class)
          .should(carryExactlyTheBreakGlassProfile())
          .because(
              "US-018 A7: a break-glass CLI bean outside the break-glass profile would run in a"
                  + " serving pod or alongside the dev seed.")
          .allowEmptyShould(false);

  /**
   * US-018 M5 security review L-3 (sign-off 1): the replay lookup is deliberately NOT tenant-scoped
   * (RC-37.2, RC-47, T-S11) and is allowlisted in {@code TenantIsolationArchitectureTest}. That
   * sign-off holds only while the port has no consumer but the break-glass service, so no class
   * other than {@link BootstrapAdminService} and {@link BreakGlassGrantLookupAdapter} (and the port
   * itself) may depend on {@link BreakGlassGrantLookupPort}. Tests are outside the production import.
   */
  public static final ArchRule BREAK_GLASS_GRANT_LOOKUP_PORT_IS_CONTAINED =
      noClasses()
          .that()
          .doNotBelongToAnyOf(
              BootstrapAdminService.class,
              BreakGlassGrantLookupAdapter.class,
              BreakGlassGrantLookupPort.class)
          .should()
          .dependOnClassesThat()
          .belongToAnyOf(BreakGlassGrantLookupPort.class)
          .because(
              "US-018 M5 L-3: the global (cross-tenant) change-reference lookup is a cross-tenant"
                  + " existence oracle for any other consumer; only the break-glass service may"
                  + " ask it.")
          .allowEmptyShould(true);

  /**
   * US-018 M5 security review L-3: the global repository query behind the port. Only {@link
   * BreakGlassGrantLookupAdapter} may call it, so reaching it by injecting the repository directly
   * (bypassing the port rule above) is refused too.
   */
  public static final ArchRule GLOBAL_BREAK_GLASS_REPLAY_QUERY_IS_CALLED_ONLY_BY_ITS_ADAPTER =
      noClasses()
          .that()
          .doNotBelongToAnyOf(BreakGlassGrantLookupAdapter.class)
          .should()
          .callMethodWhere(
              DescribedPredicate.describe(
                  "target is JpaAuthEventRepository.existsSuccessfulBreakGlassGrantWithChangeRef",
                  (JavaMethodCall call) ->
                      call.getTargetOwner().isEquivalentTo(JpaAuthEventRepository.class)
                          && "existsSuccessfulBreakGlassGrantWithChangeRef"
                              .equals(call.getName())))
          .because(
              "US-018 M5 L-3: the query is unscoped by tenant by design; a second caller would"
                  + " turn it into a cross-tenant existence oracle.")
          .allowEmptyShould(true);

  /**
   * US-019 RC-63(k): {@code isSensitive} is UX only. Only the response mapper may read the
   * sensitivity sets, so no server-side authorization decision can ever depend on them.
   */
  public static final ArchRule SENSITIVITY_SETS_ARE_READ_ONLY_BY_THE_RESPONSE_MAPPER =
      noClasses()
          .that()
          .doNotBelongToAnyOf(PermissionController.class, Permissions.class)
          .should()
          .accessFieldWhere(
              DescribedPredicate.describe(
                  "target is Permissions.SENSITIVE or Permissions.NON_SENSITIVE",
                  (JavaFieldAccess access) ->
                      access.getTargetOwner().isEquivalentTo(Permissions.class)
                          && Set.of("SENSITIVE", "NON_SENSITIVE").contains(access.getName())))
          .because(
              "US-019 RC-63(k): isSensitive is a display hint; a server rule that read it would"
                  + " turn a UX classification into an authorization decision.")
          .allowEmptyShould(true);

  private static ArchCondition<JavaClass> carryExactlyTheBreakGlassProfile() {
    return new ArchCondition<>("be annotated @Profile(\"" + Profiles.BREAK_GLASS + "\") only") {
      @Override
      public void check(JavaClass javaClass, ConditionEvents events) {
        List<String> profiles =
            javaClass
                .tryGetAnnotationOfType(Profile.class)
                .map(profile -> Arrays.asList(profile.value()))
                .orElse(List.of());
        boolean satisfied = profiles.equals(List.of(Profiles.BREAK_GLASS));
        events.add(
            new SimpleConditionEvent(
                javaClass,
                satisfied,
                javaClass.getName() + " has @Profile " + profiles + " (expected exactly ["
                    + Profiles.BREAK_GLASS + "])"));
      }
    };
  }

  private ArchitectureRules() {}
}
