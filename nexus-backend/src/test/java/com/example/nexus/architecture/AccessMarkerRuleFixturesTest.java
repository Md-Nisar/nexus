package com.example.nexus.architecture;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.common.security.AuthenticatedEndpoint;
import com.example.nexus.common.security.PublicEndpoint;
import com.example.nexus.common.security.RequiresPermission;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Proves that each US-018 A8 rule in {@link HexagonalArchitectureTest} fires (design §3.4): every
 * rule is run against a fixture that breaks it and must fail, naming the fixture.
 *
 * <p>The fixtures are static nested classes of this test class on purpose. {@code
 * HexagonalArchitectureTest} imports production classes only ({@code DoNotIncludeTests}), so they
 * never fail the production scan; and Spring Boot's {@code TestTypeExcludeFilter} leaves classes
 * nested in a test class out of the component scan of every {@code @SpringBootTest} context, so
 * the fixture controllers are never registered as handlers.
 */
@Tag("UnitTest")
class AccessMarkerRuleFixturesTest {

  // ── rest_handlers_must_carry_exactly_one_access_marker ─────────────────────

  @Test
  void should_fail_marker_rule_when_handler_has_no_marker() {
    JavaClasses fixture = new ClassFileImporter().importClasses(UnmarkedController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.rest_handlers_must_carry_exactly_one_access_marker
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UnmarkedController.class.getName() + ".handler()")
        .hasMessageContaining("no access marker");
  }

  @Test
  void should_fail_marker_rule_when_handler_has_two_markers() {
    JavaClasses fixture = new ClassFileImporter().importClasses(DoublyMarkedController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.rest_handlers_must_carry_exactly_one_access_marker
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(DoublyMarkedController.class.getName() + ".handler()")
        .hasMessageContaining("more than one access marker");
  }

  // ── no_self_invocation_of_requires_permission_methods ──────────────────────

  @Test
  void should_fail_self_invocation_rule_when_class_calls_own_requires_permission_method() {
    JavaClasses fixture = new ClassFileImporter().importClasses(SelfCallingService.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.no_self_invocation_of_requires_permission_methods
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(SelfCallingService.class.getName() + ".caller()");
  }

  @Test
  void should_fail_self_invocation_rule_when_class_references_own_requires_permission_method() {
    JavaClasses fixture = new ClassFileImporter().importClasses(SelfReferencingService.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.no_self_invocation_of_requires_permission_methods
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(SelfReferencingService.class.getName() + ".caller()");
  }

  @Test
  void should_fail_self_invocation_rule_when_inner_class_calls_outer_requires_permission_method() {
    JavaClasses fixture =
        new ClassFileImporter()
            .importClasses(OuterGuardedService.class, OuterGuardedService.Helper.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.no_self_invocation_of_requires_permission_methods
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(OuterGuardedService.Helper.class.getName() + ".call()");
  }

  @Test
  void should_fail_self_invocation_rule_when_subclass_calls_inherited_requires_permission_method() {
    JavaClasses fixture = new ClassFileImporter().importClasses(SuperCallingService.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.no_self_invocation_of_requires_permission_methods
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(SuperCallingService.class.getName() + ".caller()");
  }

  @Test
  void should_pass_self_invocation_rule_when_another_bean_calls_requires_permission_method() {
    JavaClasses fixture = new ClassFileImporter().importClasses(OtherBeanCaller.class);

    assertThatCode(
            () -> HexagonalArchitectureTest.no_self_invocation_of_requires_permission_methods
                .check(fixture))
        .doesNotThrowAnyException();
  }

  // ── authenticated_endpoints_take_no_uuid_identifier (Option B) ─────────────

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_uuid_path_variable() {
    JavaClasses fixture = new ClassFileImporter().importClasses(UuidPathVariableController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UuidPathVariableController.class.getName() + ".handler(")
        .hasMessageContaining("@PathVariable");
  }

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_string_path_variable() {
    JavaClasses fixture =
        new ClassFileImporter().importClasses(StringPathVariableController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(StringPathVariableController.class.getName() + ".handler(")
        .hasMessageContaining("@PathVariable");
  }

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_uuid_request_param() {
    JavaClasses fixture = new ClassFileImporter().importClasses(UuidRequestParamController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UuidRequestParamController.class.getName() + ".handler(")
        .hasMessageContaining("@RequestParam");
  }

  // ── Fixtures ───────────────────────────────────────────────────────────────

  @RestController
  static class UnmarkedController {
    @GetMapping("/fixture/unmarked")
    public void handler() {
      // fixture: a handler with no access marker
    }
  }

  @RestController
  static class DoublyMarkedController {
    @GetMapping("/fixture/doubly-marked")
    @PublicEndpoint
    @AuthenticatedEndpoint
    public void handler() {
      // fixture: a handler with two access markers
    }
  }

  static class SelfCallingService {
    @RequiresPermission("fixture:read")
    public void guarded() {
      // fixture: target of the self-invocation
    }

    public void caller() {
      guarded();
    }
  }

  static class SelfReferencingService {
    @RequiresPermission("fixture:read")
    public void guarded() {
      // fixture: target of the method reference
    }

    public void caller() {
      Runnable task = this::guarded;
      task.run();
    }
  }

  static class OuterGuardedService {
    @RequiresPermission("fixture:read")
    public void guarded() {
      // fixture: target of the call from the inner class
    }

    class Helper {
      void call() {
        guarded();
      }
    }
  }

  static class GuardedBaseService {
    @RequiresPermission("fixture:read")
    public void guarded() {
      // fixture: inherited target of the super call
    }
  }

  static class SuperCallingService extends GuardedBaseService {
    public void caller() {
      super.guarded();
    }
  }

  static class OtherBeanCaller {
    private final GuardedBaseService service;

    OtherBeanCaller(GuardedBaseService service) {
      this.service = service;
    }

    void call() {
      service.guarded();
    }
  }

  @RestController
  static class UuidPathVariableController {
    @GetMapping("/fixture/uuid-path/{id}")
    @AuthenticatedEndpoint
    public void handler(@PathVariable UUID id) {
      // fixture: an authenticated-only handler addressing a resource by UUID path variable
    }
  }

  @RestController
  static class StringPathVariableController {
    @GetMapping("/fixture/string-path/{id}")
    @AuthenticatedEndpoint
    public void handler(@PathVariable String id) {
      // fixture: same as above, in the house style (D15: String path variables)
    }
  }

  @RestController
  static class UuidRequestParamController {
    @GetMapping("/fixture/uuid-param")
    @AuthenticatedEndpoint
    public void handler(@RequestParam UUID id) {
      // fixture: an authenticated-only handler addressing a resource by UUID request param
    }
  }
}
