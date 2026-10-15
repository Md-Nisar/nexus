package com.example.nexus.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.lang.ArchRule;
import java.util.Set;

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

  private ArchitectureRules() {}
}
