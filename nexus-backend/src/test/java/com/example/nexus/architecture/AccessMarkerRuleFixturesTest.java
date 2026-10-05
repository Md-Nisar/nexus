package com.example.nexus.architecture;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.common.security.AuthenticatedEndpoint;
import com.example.nexus.common.security.PublicEndpoint;
import com.example.nexus.common.security.RequiresPermission;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.MatrixVariable;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
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

  @Test
  void should_fail_marker_rule_when_unmarked_handler_mapping_is_declared_on_interface() {
    JavaClasses fixture =
        new ClassFileImporter().importClasses(InterfaceMappedController.class, MappedApi.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.rest_handlers_must_carry_exactly_one_access_marker
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(InterfaceMappedController.class.getName() + ".handler()")
        .hasMessageContaining("no access marker");
  }

  @Test
  void should_fail_marker_rule_when_unmarked_handler_mapping_is_inherited_from_abstract_base() {
    JavaClasses fixture =
        new ClassFileImporter().importClasses(InheritingController.class, MappedBase.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.rest_handlers_must_carry_exactly_one_access_marker
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(InheritingController.class.getName())
        .hasMessageContaining(MappedBase.class.getName() + ".handler()")
        .hasMessageContaining("no access marker");
  }

  @Test
  void should_fail_marker_rule_when_unmarked_handler_is_in_controller_with_response_body() {
    JavaClasses fixture = new ClassFileImporter().importClasses(ResponseBodyController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.rest_handlers_must_carry_exactly_one_access_marker
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(ResponseBodyController.class.getName() + ".handler()")
        .hasMessageContaining("no access marker");
  }

  @Test
  void should_pass_marker_rule_when_interface_declares_mapping_and_marker() {
    JavaClasses fixture =
        new ClassFileImporter().importClasses(MarkedInterfaceController.class, MarkedApi.class);

    assertThatCode(
            () -> HexagonalArchitectureTest.rest_handlers_must_carry_exactly_one_access_marker
                .check(fixture))
        .doesNotThrowAnyException();
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
  void should_fail_self_invocation_rule_when_override_of_interface_guarded_method_is_self_called() {
    JavaClasses fixture =
        new ClassFileImporter().importClasses(InterfaceGuardedService.class, GuardedApi.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.no_self_invocation_of_requires_permission_methods
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(InterfaceGuardedService.class.getName() + ".caller()");
  }

  @Test
  void should_pass_self_invocation_rule_when_another_bean_calls_requires_permission_method() {
    JavaClasses fixture = new ClassFileImporter().importClasses(OtherBeanCaller.class);

    assertThatCode(
            () -> HexagonalArchitectureTest.no_self_invocation_of_requires_permission_methods
                .check(fixture))
        .doesNotThrowAnyException();
  }

  // ── authenticated_endpoints_take_no_uuid_identifier (Option B, extended: D-8) ──

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

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_unannotated_uuid() {
    JavaClasses fixture = new ClassFileImporter().importClasses(UnannotatedUuidController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UnannotatedUuidController.class.getName() + ".handler(")
        .hasMessageContaining("UUID parameter");
  }

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_string_request_param() {
    JavaClasses fixture =
        new ClassFileImporter().importClasses(StringRequestParamController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(StringRequestParamController.class.getName() + ".handler(")
        .hasMessageContaining("@RequestParam");
  }

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_model_attribute() {
    JavaClasses fixture = new ClassFileImporter().importClasses(ModelAttributeController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(ModelAttributeController.class.getName() + ".handler(")
        .hasMessageContaining("@ModelAttribute");
  }

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_unannotated_string() {
    JavaClasses fixture =
        new ClassFileImporter().importClasses(UnannotatedStringController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UnannotatedStringController.class.getName() + ".handler(")
        .hasMessageContaining("unannotated parameter");
  }

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_unannotated_record() {
    JavaClasses fixture =
        new ClassFileImporter().importClasses(UnannotatedRecordController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UnannotatedRecordController.class.getName() + ".handler(")
        .hasMessageContaining("unannotated parameter");
  }

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_matrix_variable() {
    JavaClasses fixture = new ClassFileImporter().importClasses(MatrixVariableController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(MatrixVariableController.class.getName() + ".handler(")
        .hasMessageContaining("@MatrixVariable");
  }

  @Test
  void should_pass_uuid_rule_when_authenticated_endpoint_takes_only_principal_and_framework_types() {
    JavaClasses fixture = new ClassFileImporter().importClasses(PrincipalOnlyController.class);

    assertThatCode(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .doesNotThrowAnyException();
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

  interface MappedApi {
    @GetMapping("/fixture/interface-mapped")
    void handler();
  }

  @RestController
  static class InterfaceMappedController implements MappedApi {
    @Override
    public void handler() {
      // fixture: MVC registers the interface's mapping for this unmarked implementation
    }
  }

  abstract static class MappedBase {
    @GetMapping("/fixture/base-mapped")
    public void handler() {
      // fixture: MVC registers this inherited mapping for every concrete subclass
    }
  }

  @RestController
  static class InheritingController extends MappedBase {}

  @Controller
  static class ResponseBodyController {
    @GetMapping("/fixture/response-body")
    @ResponseBody
    public String handler() {
      return "fixture: a @Controller + @ResponseBody handler with no access marker";
    }
  }

  interface MarkedApi {
    @GetMapping("/fixture/marked-api")
    @AuthenticatedEndpoint
    void handler();
  }

  @RestController
  static class MarkedInterfaceController implements MarkedApi {
    @Override
    public void handler() {
      // fixture: mapping and marker both come from the interface, as MVC and Spring see them
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

  interface GuardedApi {
    @RequiresPermission("fixture:read")
    void guarded();
  }

  static class InterfaceGuardedService implements GuardedApi {
    @Override
    public void guarded() {
      // fixture: Spring Security finds @RequiresPermission through the interface on proxied calls
    }

    public void caller() {
      guarded();
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

  @RestController
  static class UnannotatedUuidController {
    @GetMapping("/fixture/unannotated-uuid")
    @AuthenticatedEndpoint
    public void handler(Authentication authentication, UUID userId) {
      // fixture: MVC binds the unannotated UUID as an implicit @RequestParam (?userId=...)
    }
  }

  @RestController
  static class StringRequestParamController {
    @GetMapping("/fixture/string-param")
    @AuthenticatedEndpoint
    public void handler(@RequestParam String userId) {
      // fixture: a String identifier taken from the query string
    }
  }

  record IdentifierQuery(UUID userId) {}

  @RestController
  static class ModelAttributeController {
    @GetMapping("/fixture/model-attribute")
    @AuthenticatedEndpoint
    public void handler(@ModelAttribute IdentifierQuery query) {
      // fixture: an identifier bound from request parameters into a model attribute
    }
  }

  @RestController
  static class UnannotatedStringController {
    @GetMapping("/fixture/unannotated-string")
    @AuthenticatedEndpoint
    public void handler(String userId) {
      // fixture: MVC binds the unannotated String as an implicit @RequestParam
    }
  }

  @RestController
  static class UnannotatedRecordController {
    @GetMapping("/fixture/unannotated-record")
    @AuthenticatedEndpoint
    public void handler(IdentifierQuery query) {
      // fixture: MVC binds the unannotated record as an implicit @ModelAttribute
    }
  }

  @RestController
  static class MatrixVariableController {
    @GetMapping("/fixture/matrix/{segment}")
    @AuthenticatedEndpoint
    public void handler(@MatrixVariable String userId) {
      // fixture: an identifier taken from a matrix variable (;userId=...)
    }
  }

  record FixtureBody(String note) {}

  @RestController
  static class PrincipalOnlyController {
    @PostMapping("/fixture/principal-only")
    @AuthenticatedEndpoint
    public void handler(
        Authentication authentication,
        Principal principal,
        HttpServletRequest request,
        HttpServletResponse response,
        @AuthenticationPrincipal Object user,
        @RequestBody FixtureBody body) {
      // fixture: only the principal and framework types; identifiers in a body are out of scope
    }
  }
}
