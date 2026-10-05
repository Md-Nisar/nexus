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
import org.springframework.web.HttpRequestHandler;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.MatrixVariable;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

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
  void should_fail_marker_rule_when_static_handler_carries_requires_permission() {
    JavaClasses fixture = new ClassFileImporter().importClasses(StaticGuardedController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.rest_handlers_must_carry_exactly_one_access_marker
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(StaticGuardedController.class.getName() + ".handler()")
        .hasMessageContaining("static handler method");
  }

  @Test
  void should_fail_marker_rule_when_static_handler_has_no_marker() {
    JavaClasses fixture = new ClassFileImporter().importClasses(StaticUnmarkedController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.rest_handlers_must_carry_exactly_one_access_marker
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(StaticUnmarkedController.class.getName() + ".handler()")
        .hasMessageContaining("static handler method");
  }

  @Test
  void should_fail_marker_rule_when_http_exchange_handler_has_no_marker() {
    JavaClasses fixture = new ClassFileImporter().importClasses(HttpExchangeController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.rest_handlers_must_carry_exactly_one_access_marker
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(HttpExchangeController.class.getName() + ".handler()")
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

  // ── requires_permission_methods_must_be_public_and_non_final ───────────────

  @Test
  void should_fail_public_non_final_rule_when_requires_permission_method_is_static() {
    JavaClasses fixture = new ClassFileImporter().importClasses(StaticGuardedController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.requires_permission_methods_must_be_public_and_non_final
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(StaticGuardedController.class.getName() + ".handler()")
        .hasMessageContaining("STATIC");
  }

  // ── requires_permission_overrides_must_be_proxyable ────────────────────────

  @Test
  void should_fail_override_rule_when_implementation_of_guarded_interface_method_is_final() {
    JavaClasses fixture =
        new ClassFileImporter()
            .importClasses(FinalOverrideController.class, GuardedHandlerApi.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.requires_permission_overrides_must_be_proxyable
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(FinalOverrideController.class.getName() + ".handler()")
        .hasMessageContaining("is final");
  }

  @Test
  void should_fail_override_rule_when_class_implementing_guarded_interface_method_is_final() {
    JavaClasses fixture =
        new ClassFileImporter()
            .importClasses(FinalClassOverrideController.class, GuardedHandlerApi.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.requires_permission_overrides_must_be_proxyable
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(FinalClassOverrideController.class.getName() + ".handler()")
        .hasMessageContaining("final class");
  }

  @Test
  void should_pass_override_rule_when_implementation_of_guarded_interface_method_is_proxyable() {
    JavaClasses fixture =
        new ClassFileImporter()
            .importClasses(ProxyableOverrideController.class, GuardedHandlerApi.class);

    assertThatCode(
            () -> HexagonalArchitectureTest.requires_permission_overrides_must_be_proxyable
                .check(fixture))
        .doesNotThrowAnyException();
  }

  // ── no_handlers_outside_annotated_controllers ──────────────────────────────

  @Test
  void should_fail_handler_type_rule_when_class_declares_router_function() {
    JavaClasses fixture = new ClassFileImporter().importClasses(RouterFunctionConfig.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.no_handlers_outside_annotated_controllers
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(RouterFunctionConfig.class.getName())
        .hasMessageContaining(RouterFunction.class.getName());
  }

  @Test
  void should_fail_handler_type_rule_when_class_implements_http_request_handler() {
    JavaClasses fixture = new ClassFileImporter().importClasses(BeanNameRequestHandler.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.no_handlers_outside_annotated_controllers
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(BeanNameRequestHandler.class.getName())
        .hasMessageContaining(HttpRequestHandler.class.getName());
  }

  @Test
  void should_fail_handler_type_rule_when_class_implements_mvc_controller() {
    JavaClasses fixture = new ClassFileImporter().importClasses(LegacyMvcController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.no_handlers_outside_annotated_controllers
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(LegacyMvcController.class.getName())
        .hasMessageContaining(org.springframework.web.servlet.mvc.Controller.class.getName());
  }

  @Test
  void should_pass_handler_type_rule_when_class_is_annotated_controller() {
    JavaClasses fixture = new ClassFileImporter().importClasses(MarkedInterfaceController.class);

    assertThatCode(
            () -> HexagonalArchitectureTest.no_handlers_outside_annotated_controllers
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
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_request_header() {
    JavaClasses fixture = new ClassFileImporter().importClasses(RequestHeaderController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(RequestHeaderController.class.getName() + ".handler(")
        .hasMessageContaining("@RequestHeader");
  }

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_cookie_value() {
    JavaClasses fixture = new ClassFileImporter().importClasses(CookieValueController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(CookieValueController.class.getName() + ".handler(")
        .hasMessageContaining("@CookieValue");
  }

  @Test
  void should_fail_uuid_rule_when_authenticated_endpoint_takes_servlet_request() {
    JavaClasses fixture = new ClassFileImporter().importClasses(ServletRequestController.class);

    assertThatThrownBy(
            () -> HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier
                .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(ServletRequestController.class.getName() + ".handler(")
        .hasMessageContaining("ServletRequest");
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

  @RestController
  static class StaticGuardedController {
    @GetMapping("/fixture/static-guarded")
    @RequiresPermission("fixture:read")
    public static String handler() {
      return "fixture: MVC registers a static handler, but method security never intercepts it";
    }
  }

  @RestController
  static class StaticUnmarkedController {
    @GetMapping("/fixture/static-unmarked")
    public static void handler() {
      // fixture: a static handler with no access marker
    }
  }

  @RestController
  static class HttpExchangeController {
    @GetExchange("/fixture/get-exchange")
    public void handler() {
      // fixture: MVC registers an @HttpExchange (here @GetExchange) mapping on a controller
    }
  }

  interface GuardedHandlerApi {
    @GetMapping("/fixture/guarded-api")
    @RequiresPermission("fixture:read")
    String handler();
  }

  @RestController
  static class FinalOverrideController implements GuardedHandlerApi {
    @Override
    public final String handler() {
      return "fixture: the CGLIB proxy cannot override a final method, so the guard never runs";
    }
  }

  @RestController
  static final class FinalClassOverrideController implements GuardedHandlerApi {
    @Override
    public String handler() {
      return "fixture: CGLIB cannot subclass a final class";
    }
  }

  @RestController
  static class ProxyableOverrideController implements GuardedHandlerApi {
    @Override
    public String handler() {
      return "fixture: public, non-final, non-static, in a non-final class";
    }
  }

  static class RouterFunctionConfig {
    RouterFunction<ServerResponse> route() {
      return RouterFunctions.route()
          .GET("/fixture/router", request -> ServerResponse.ok().build())
          .build();
    }
  }

  static class BeanNameRequestHandler implements HttpRequestHandler {
    @Override
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) {
      // fixture: BeanNameUrlHandlerMapping serves an HttpRequestHandler bean named "/..."
    }
  }

  static class LegacyMvcController implements org.springframework.web.servlet.mvc.Controller {
    @Override
    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) {
      return null;
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

  @RestController
  static class RequestHeaderController {
    @GetMapping("/fixture/request-header")
    @AuthenticatedEndpoint
    public void handler(@RequestHeader("X-Fixture-Subject") String subjectId) {
      // fixture: an identifier taken from a request header chosen by the caller
    }
  }

  @RestController
  static class CookieValueController {
    @GetMapping("/fixture/cookie-value")
    @AuthenticatedEndpoint
    public void handler(@CookieValue("fixture-subject") String subjectId) {
      // fixture: an identifier taken from a cookie chosen by the caller
    }
  }

  @RestController
  static class ServletRequestController {
    @GetMapping("/fixture/servlet-request")
    @AuthenticatedEndpoint
    public void handler(HttpServletRequest request) {
      // fixture: the raw request exposes every header, cookie and parameter (getParameter(...))
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
        HttpServletResponse response,
        @AuthenticationPrincipal Object user,
        @RequestBody FixtureBody body) {
      // fixture: only the principal and framework types; identifiers in a body are out of scope
    }
  }
}
