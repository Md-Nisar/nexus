package com.example.nexus.architecture;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.rbac.application.BootstrapAdminService;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Proves the US-018 A7 containment rule in {@link HexagonalArchitectureTest} fires (T-007): a
 * REST-style fixture (outside {@code rbac.interfaces.cli}) that calls {@link BootstrapAdminService} must fail it.
 *
 * <p>The fixtures are static nested classes of this test class, for the reason given on {@code
 * AccessMarkerRuleFixturesTest}: the production ArchUnit scan skips test classes, and Spring Boot
 * leaves nested test classes out of the component scan.
 */
@Tag("UnitTest")
class BreakGlassContainmentRuleFixturesTest {

  @Test
  void should_failContainmentRule_when_restClassCallsBootstrapAdminService() {
    JavaClasses fixture = new ClassFileImporter().importClasses(RestCallerFixture.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.bootstrap_admin_service_is_callable_only_from_the_cli
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(RestCallerFixture.class.getName());
  }

  @Test
  void should_failContainmentRule_when_classOnlyHoldsBootstrapAdminServiceAsAField() {
    JavaClasses fixture = new ClassFileImporter().importClasses(FieldOnlyFixture.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.bootstrap_admin_service_is_callable_only_from_the_cli
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(FieldOnlyFixture.class.getName());
  }

  @Test
  void should_passContainmentRule_when_classDoesNotReferenceBootstrapAdminService() {
    JavaClasses fixture = new ClassFileImporter().importClasses(UnrelatedFixture.class);

    assertThatCode(
            () -> HexagonalArchitectureTest.bootstrap_admin_service_is_callable_only_from_the_cli
                .check(fixture))
        .doesNotThrowAnyException();
  }

  static class RestCallerFixture {
    private final BootstrapAdminService service;

    RestCallerFixture(BootstrapAdminService service) {
      this.service = service;
    }

    void handle(UUID target) {
      service.grantFirstAdmin(target, "OPS-1");
    }
  }

  static class FieldOnlyFixture {
    private BootstrapAdminService service;
  }

  static class UnrelatedFixture {
    void handle(UUID target) {
      target.toString();
    }
  }
}
