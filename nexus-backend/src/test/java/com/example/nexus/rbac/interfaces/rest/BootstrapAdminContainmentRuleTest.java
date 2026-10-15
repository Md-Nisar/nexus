package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.architecture.HexagonalArchitectureTest;
import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.BreakGlassOutcome;
import com.example.nexus.rbac.interfaces.cli.BootstrapAdminCliFixture;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Proves {@link HexagonalArchitectureTest#bootstrap_admin_service_is_reachable_only_from_the_cli}
 * fires (US-018 T-007, EC2). Lives in {@code rbac.interfaces.rest} because the failing fixture
 * must reside there; a nested class of a test class is outside every {@code @SpringBootTest}
 * component scan and outside the production ArchUnit import ({@code DoNotIncludeTests}).
 */
@Tag("UnitTest")
class BootstrapAdminContainmentRuleTest {

  @Test
  void should_failContainmentRule_when_restPackageClassCallsBootstrapAdminService() {
    JavaClasses fixture = new ClassFileImporter().importClasses(RestCallerFixture.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.bootstrap_admin_service_is_reachable_only_from_the_cli
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(RestCallerFixture.class.getName());
  }

  @Test
  void should_passContainmentRule_when_cliPackageClassCallsBootstrapAdminService() {
    JavaClasses fixture = new ClassFileImporter().importClasses(BootstrapAdminCliFixture.class);

    assertThatCode(
            () -> HexagonalArchitectureTest.bootstrap_admin_service_is_reachable_only_from_the_cli
                .check(fixture))
        .doesNotThrowAnyException();
  }

  /** A REST-package class reaching the privileged path: exactly what the rule must refuse. */
  static class RestCallerFixture {

    private final BootstrapAdminService bootstrapAdminService;

    RestCallerFixture(BootstrapAdminService bootstrapAdminService) {
      this.bootstrapAdminService = bootstrapAdminService;
    }

    BreakGlassOutcome grant(UUID targetUserId) {
      return bootstrapAdminService.grantFirstAdmin(targetUserId, "OPS-1");
    }
  }
}
