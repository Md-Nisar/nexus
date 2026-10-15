package com.example.nexus.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.example.nexus.common.Profiles;
import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
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
