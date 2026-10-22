package com.example.nexus.rbac.interfaces.cli;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.architecture.ArchitectureRules;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Proves {@link ArchitectureRules#BREAK_GLASS_NEVER_CALLS_ROLE_ASSIGNMENT_ASSIGN_OR_REVOKE} fires
 * (US-018 T-007, EC2; 06-code-review-M5-T007.md finding 8). The rule covers {@code
 * BootstrapAdminService} and every class in {@code rbac.interfaces.cli}, so the failing fixtures
 * live in this package as nested classes: outside every {@code @SpringBootTest} component scan
 * and outside the production ArchUnit import ({@code DoNotIncludeTests}).
 */
@Tag("UnitTest")
class BreakGlassNoAssignOrRevokeRuleTest {

  @Test
  void should_failRule_when_cliClassCallsRoleAssignmentServiceAssign() {
    JavaClasses fixture = new ClassFileImporter().importClasses(AssigningCliFixture.class);

    assertThatThrownBy(
            () ->
                ArchitectureRules.BREAK_GLASS_NEVER_CALLS_ROLE_ASSIGNMENT_ASSIGN_OR_REVOKE.check(
                    fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(AssigningCliFixture.class.getName())
        .hasMessageContaining("assign");
  }

  @Test
  void should_failRule_when_cliClassCallsRoleAssignmentServiceRevoke() {
    JavaClasses fixture = new ClassFileImporter().importClasses(RevokingCliFixture.class);

    assertThatThrownBy(
            () ->
                ArchitectureRules.BREAK_GLASS_NEVER_CALLS_ROLE_ASSIGNMENT_ASSIGN_OR_REVOKE.check(
                    fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(RevokingCliFixture.class.getName())
        .hasMessageContaining("revoke");
  }

  @Test
  void should_passRule_when_cliClassCallsOnlyBootstrapAdminService() {
    JavaClasses fixture = new ClassFileImporter().importClasses(BootstrapAdminCliFixture.class);

    assertThatCode(
            () ->
                ArchitectureRules.BREAK_GLASS_NEVER_CALLS_ROLE_ASSIGNMENT_ASSIGN_OR_REVOKE.check(
                    fixture))
        .doesNotThrowAnyException();
  }

  /** A CLI-package class routing break-glass through the request-path grant. */
  static class AssigningCliFixture {

    private final RoleAssignmentService roleAssignmentService;

    AssigningCliFixture(RoleAssignmentService roleAssignmentService) {
      this.roleAssignmentService = roleAssignmentService;
    }

    void grant(UUID tenantId, UUID targetUserId, UUID roleId) {
      roleAssignmentService.assign(
          new RoleChangeActor(targetUserId, tenantId), targetUserId, roleId, null);
    }
  }

  /** A CLI-package class revoking through the request path. */
  static class RevokingCliFixture {

    private final RoleAssignmentService roleAssignmentService;

    RevokingCliFixture(RoleAssignmentService roleAssignmentService) {
      this.roleAssignmentService = roleAssignmentService;
    }

    void revoke(UUID tenantId, UUID targetUserId, UUID roleId) {
      roleAssignmentService.revoke(
          new RoleChangeActor(targetUserId, tenantId), targetUserId, roleId, null);
    }
  }
}
