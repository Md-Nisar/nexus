package com.example.nexus.config;

import static java.util.stream.Collectors.toUnmodifiableSet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;

import com.example.nexus.common.security.AuthenticatedEndpoint;
import com.example.nexus.common.security.AuthenticationDetailKeys;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.common.security.PublicEndpoint;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.identity.application.service.LogoutUseCase;
import com.example.nexus.identity.infrastructure.web.PublicEndpointRequestMatcher;
import com.jayway.jsonpath.JsonPath;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.annotation.Annotation;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.http.server.PathContainer;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.function.support.RouterFunctionMapping;
import org.springframework.web.servlet.handler.AbstractHandlerMethodMapping;
import org.springframework.web.servlet.handler.AbstractUrlHandlerMapping;
import org.springframework.web.servlet.handler.BeanNameUrlHandlerMapping;
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.UriTemplate;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * Runtime drift guard between the access markers and {@link SecurityConfig} (US-018 A8, design
 * §3.1, RC-40.2, RC-44.3, TS-7).
 *
 * <p>Full security chain on MockMvc, H2 (no Docker), {@code test} profile so every feature flag is
 * on and the flag-gated RBAC controllers are registered; {@link
 * #should_register_every_production_rest_controller_when_all_flags_enabled} fails if a flag is
 * ever left off.
 *
 * <p>The anonymous sweep sends one request per production handler, path variables filled with
 * random UUIDs and POST/PUT/PATCH bodies set to {@code {}} so a public handler stops at bean
 * validation instead of running its use case ({@link LogoutUseCase}, which takes no body, is
 * mocked). It asserts on the authentication entry point's own response, {@code AUTH_003} written
 * by {@code jwtAuthenticationEntryPoint} with no {@code instance} member, and not on the status
 * alone: a public handler may legitimately answer 401 itself (refresh without a cookie answers
 * {@code AUTH_004}, and {@code GlobalExceptionHandler}'s problem details always carry {@code
 * instance}).
 *
 * <p>The sweeps are limited to production handlers, those whose bean type is a main-source class
 * (any class, not only {@code @RestController}s). Every other handler type must be named in
 * {@link #NON_PRODUCTION_HANDLER_ALLOWLIST} with a reason (springdoc, Spring Boot, the test-only
 * fixtures); an unlisted one fails the sweeps (security review F-1). The completeness sweep
 * asserts that every production handler carries exactly one access marker as Spring resolves it;
 * the anonymous sweep checks the public ones against {@link SecurityConfig} and against the
 * ordered handler mappings {@code DispatcherServlet} consults. {@link #HANDLER_MAPPING_TYPES} pins
 * the handler mappings themselves, so a handler that {@code requestMappingHandlerMapping} does not
 * serve (a functional endpoint, a bean-name handler) cannot escape the sweeps.
 *
 * <p>Since US-018 T-009, {@code SecurityConfig} grants anonymous access to {@code @PublicEndpoint}
 * handlers through {@link PublicEndpointRequestMatcher} (HTTP method and pattern), plus a short
 * literal list of non-MVC infrastructure paths that the matcher cannot see. The {@code permitAll}
 * sweep (security review F-5) sends every HTTP method to each path of {@link
 * #PERMIT_ALL_PATTERNS}, the test-side mirror of that literal list, because a literal matches on
 * path only. A drift guard keeps the mirror and the matcher in step with the configured chain, and
 * {@link PermitAllOverlapProbe} proves that a non-public pattern overlapping a public literal is no
 * longer reachable anonymously.
 *
 * <p>Two sweeps cover a signed-in caller holding no permission: every {@code
 * @AuthenticatedEndpoint} handler passes the chain (neither 401 nor 403), and every {@code
 * @RequiresPermission} handler, invoked on its method-security proxy, is denied with {@code
 * PERMISSION_ABSENT} for the permission it declares.
 *
 * <p>The matcher sweep checks {@link PublicEndpointRequestMatcher} against every mapping. The
 * fixture {@link SamePathOtherMethodController} maps {@code GET} on the public refresh pattern;
 * it proves the matcher, and therefore {@code permitAll}, does not exempt it. Every {@code
 * @PublicEndpoint} pattern must be a literal path, so a public exemption can never widen through
 * a path variable or wildcard.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.MOCK,
    properties = {
        "spring.datasource.url=jdbc:h2:mem:nexus-endpoint-classification-test;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.flyway.enabled=false",
        "spring.mail.host=127.0.0.1",
        "spring.mail.properties.mail.smtp.connectiontimeout=200",
        "spring.mail.properties.mail.smtp.timeout=200",
        "nexus.mail.from-address=test@nexus.test",
        "nexus.frontend.base-url=http://localhost:2000",
        "management.health.mail.enabled=false"
    })
@ActiveProfiles("test")
@Import(EndpointClassificationWebTest.SamePathOtherMethodFixtureConfig.class)
@Tag("WebSliceTest")
class EndpointClassificationWebTest {

  private static final String ENTRY_POINT_CODE = "AUTH_003";
  private static final String ACCESS_DENIED_CODE = "ACCESS_DENIED";
  private static final String PUBLIC_REFRESH_PATH = "/api/v1/auth/refresh";
  private static final Set<RequestMethod> METHODS_WITH_BODY =
      Set.of(RequestMethod.POST, RequestMethod.PUT, RequestMethod.PATCH);
  private static final List<Class<? extends Annotation>> ACCESS_MARKERS =
      List.of(RequiresPermission.class, AuthenticatedEndpoint.class, PublicEndpoint.class);

  /** The HTTP methods swept on each {@code permitAll} path (Tomcat rejects TRACE by default). */
  private static final List<RequestMethod> ALL_METHODS =
      List.of(RequestMethod.GET, RequestMethod.HEAD, RequestMethod.POST, RequestMethod.PUT,
          RequestMethod.PATCH, RequestMethod.DELETE, RequestMethod.OPTIONS);

  /** Fills path variables and wildcards of probe paths; fixed, so test names are stable. */
  private static final String PROBE_SEGMENT = "5f0c2d1e-9a7b-4c3d-8e6f-0a1b2c3d4e5f";

  private static final Authentication ANONYMOUS =
      new AnonymousAuthenticationToken(
          "endpoint-classification", "anonymousUser",
          AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

  /** Fixed subject and tenant of the signed-in caller without permissions; synthetic values. */
  private static final String NO_PERMISSION_SUBJECT = "0b6f3c1a-2d4e-4f5a-8b9c-1d2e3f4a5b6c";

  private static final String NO_PERMISSION_TENANT = "7c1e2d3f-4a5b-4c6d-9e8f-0a1b2c3d4e5f";

  /**
   * Test-side mirror of the literal {@code permitAll} list in {@code SecurityConfig.apiSecurity}
   * (security review F-5), in the same order: the non-MVC infrastructure paths only, because the
   * {@code @PublicEndpoint} handlers are granted through {@link PublicEndpointRequestMatcher}. Spring Security exposes the configured matchers through no
   * public API (they sit in private fields of {@code RequestMatcherDelegatingAuthorizationManager},
   * behind {@code ObservationAuthorizationManager}), so the list is copied rather than read by
   * reflection, and {@link #should_permit_anonymous_request_only_when_path_is_on_permit_all_list}
   * fails as soon as the copy and the configured chain disagree in either direction. Change both
   * together; a pattern with a wildcard other than a trailing {@code /**} fails {@link
   * #samplePaths} until that method can sample it.
   */
  private static final List<String> PERMIT_ALL_PATTERNS =
      List.of(
          "/actuator/health/**", "/actuator/info",
          "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html");

  /**
   * {@code HandlerMapping} bean types this context may hold (security review F-1), each with what
   * it may serve. Only {@code requestMappingHandlerMapping} may hold main-source handlers, and
   * every sweep reads it; {@link #should_hold_only_reviewed_handlers_when_handler_mapping_is_registered}
   * checks that the others stay empty or framework-only. A new mapping type fails {@link
   * #should_register_only_reviewed_handler_mapping_types_when_context_starts} until it is
   * reviewed and listed here with a reason.
   */
  private static final Set<String> HANDLER_MAPPING_TYPES =
      Set.of(
          // Annotated controllers: the only mapping allowed to hold main-source handlers.
          RequestMappingHandlerMapping.class.getName(),
          // Actuator operations under /actuator (exposure: management.endpoints.web.exposure,
          // outside A8, security review P-2) and health groups on additional paths (none here).
          "org.springframework.boot.webmvc.actuate.endpoint.web.WebMvcEndpointHandlerMapping",
          "org.springframework.boot.webmvc.actuate.endpoint.web"
              + ".AdditionalHealthEndpointPathsWebMvcHandlerMapping",
          // Actuator @ControllerEndpoint beans: may hold no main-source handler (none today).
          "org.springframework.boot.webmvc.actuate.endpoint.web.ControllerEndpointHandlerMapping",
          // Functional endpoints: must have no RouterFunction; HexagonalArchitectureTest
          // .no_handlers_outside_annotated_controllers bans one in production code.
          RouterFunctionMapping.class.getName(),
          // HttpRequestHandler / mvc.Controller beans named "/...": must stay empty (same rule).
          BeanNameUrlHandlerMapping.class.getName(),
          // Static resources (spring.web.resources, springdoc's swagger-ui assets) only.
          SimpleUrlHandlerMapping.class.getName(),
          // Welcome page (index.html or an index template): there is none, so both stay empty.
          "org.springframework.boot.webmvc.autoconfigure.WelcomePageHandlerMapping",
          "org.springframework.boot.webmvc.autoconfigure.WelcomePageNotAcceptableHandlerMapping");

  /**
   * Handler types that are not main-source classes and may be registered: the sweeps leave them
   * out on purpose, for the reason given. Any other non-production handler type fails the sweeps
   * (security review F-1). Never add a main-source class; add an entry only with a reason and
   * security-reviewer sign-off.
   */
  private static final Set<String> NON_PRODUCTION_HANDLER_ALLOWLIST =
      Set.of(
          // springdoc: the OpenAPI document (JSON, YAML) and the UI's config; permitAll in
          // SecurityConfig, and springdoc.api-docs.enabled=false in the prod profile.
          "org.springdoc.webmvc.api.OpenApiWebMvcResource",
          "org.springdoc.webmvc.ui.SwaggerConfigResource",
          // springdoc: /swagger-ui.html, a redirect to the UI's static resources.
          "org.springdoc.webmvc.ui.SwaggerWelcomeWebMvc",
          // Spring Boot: /error renders the failed request's error attributes; not an API handler.
          "org.springframework.boot.webmvc.autoconfigure.error.BasicErrorController",
          // Spring Boot actuator: endpoint operations and the /actuator links page (exposure is
          // management.endpoints.web.exposure, outside A8: security review P-2).
          "org.springframework.boot.webmvc.actuate.endpoint.web"
              + ".AbstractWebMvcEndpointHandlerMapping$OperationHandler",
          "org.springframework.boot.webmvc.actuate.endpoint.web"
              + ".WebMvcEndpointHandlerMapping$WebMvcLinksHandler",
          // Spring MVC: static classpath resources (/**, /webjars/**, swagger-ui assets); runs no
          // application code.
          ResourceHttpRequestHandler.class.getName(),
          // Spring MVC: answers a plain OPTIONS with the Allow header of the matching mappings;
          // invokes no controller.
          "org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping"
              + "$HttpOptionsHandler",
          // Test sources: component-scanned into every @SpringBootTest context (security review
          // I-1), never packaged; its handlers prove @RequiresPermission enforcement.
          "com.example.nexus.support.web.GuardedTestController",
          // This class's matcher fixture, imported only here: GET on the public refresh path, which
          // neither the matcher nor permitAll exempts (see the class Javadoc).
          SamePathOtherMethodController.class.getName());

  /**
   * Every main-source class under {@code com.example.nexus}: the same import scope as the ArchUnit
   * rules. A handler is production when its bean type is in this set, whatever annotation makes
   * MVC register it.
   */
  private static final JavaClasses PRODUCTION_CLASSES =
      new ClassFileImporter()
          .withImportOption(new ImportOption.DoNotIncludeTests())
          .importPackages("com.example.nexus");

  private static final Set<String> PRODUCTION_CLASS_NAMES =
      PRODUCTION_CLASSES.stream().map(JavaClass::getName).collect(toUnmodifiableSet());

  /**
   * Production classes MVC treats as handlers: concrete, and {@code @Controller} found the way
   * {@code RequestMappingHandlerMapping.isHandler} finds it (through meta-annotations,
   * superclasses and interfaces), so {@code @Controller} + {@code @ResponseBody} counts too.
   */
  private static final Set<String> PRODUCTION_CONTROLLERS =
      PRODUCTION_CLASSES.stream()
          .filter(javaClass -> !javaClass.isInterface()
              && !javaClass.getModifiers().contains(JavaModifier.ABSTRACT))
          .filter(javaClass -> AnnotatedElementUtils.hasAnnotation(
              javaClass.reflect(), Controller.class))
          .map(JavaClass::getName)
          .collect(toUnmodifiableSet());

  @Autowired private WebApplicationContext context;

  @Autowired
  @Qualifier("requestMappingHandlerMapping")
  private RequestMappingHandlerMapping handlerMapping;

  @Autowired private PublicEndpointRequestMatcher matcher;

  @MockitoBean LogoutUseCase logoutUseCase;

  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  @Test
  void should_register_every_production_rest_controller_when_all_flags_enabled() {
    Set<String> registered =
        handlerMapping.getHandlerMethods().values().stream()
            .map(handler -> handler.getBeanType().getName())
            .collect(toUnmodifiableSet());

    assertThat(PRODUCTION_CONTROLLERS)
        .as("production @Controller classes registered as handlers (a feature flag is off?)")
        .isNotEmpty()
        .allMatch(registered::contains);
  }

  /**
   * Confirms that the component scan leaves nested test fixtures out: the static nested fixture
   * controllers of {@code AccessMarkerRuleFixturesTest} (and of any other test class) are never
   * registered, because {@code TestTypeExcludeFilter} excludes classes nested in a test class. The
   * only nested test handler is this class's explicitly imported fixture.
   */
  @Test
  void should_register_no_nested_test_fixture_handler_except_explicit_one_when_context_starts() {
    Set<String> nestedTestHandlerTypes =
        handlerMapping.getHandlerMethods().values().stream()
            .map(HandlerMethod::getBeanType)
            .filter(type -> type.getName().startsWith("com.example.nexus.")
                && type.getEnclosingClass() != null
                && !PRODUCTION_CLASS_NAMES.contains(type.getName()))
            .map(Class::getName)
            .collect(toUnmodifiableSet());

    assertThat(nestedTestHandlerTypes)
        .as("nested test-source handler bean types registered in the context")
        .containsExactly(SamePathOtherMethodController.class.getName());
  }

  /**
   * Completeness sweep (code review M-1): every production handler MVC registered, however it got
   * its mapping (own method, inherited from a base class, declared on an interface, {@code
   * @Controller} + {@code @ResponseBody}), carries exactly one access marker as Spring resolves
   * it ({@link AnnotatedElementUtils#hasAnnotation}, through the method hierarchy).
   */
  @TestFactory
  Stream<DynamicTest> should_carry_exactly_one_access_marker_when_handler_is_production() {
    List<HandlerMethod> productionHandlers =
        handlerMapping.getHandlerMethods().values().stream()
            .filter(EndpointClassificationWebTest::isProductionHandler)
            .toList();
    assertThat(productionHandlers).as("production handlers").isNotEmpty();
    return productionHandlers.stream()
        .map(handler -> DynamicTest.dynamicTest(
            handler.getBeanType().getSimpleName() + "." + handler.getMethod().getName(),
            () -> assertThat(ACCESS_MARKERS)
                .as("access markers on %s", handler)
                .filteredOn(marker -> AnnotatedElementUtils.hasAnnotation(
                    handler.getMethod(), marker))
                .hasSize(1)));
  }

  @TestFactory
  Stream<DynamicTest> should_not_return_entry_point_401_when_anonymous_calls_public_endpoint() {
    return dynamicTests(
        publicProductionEndpoints(),
        endpoint -> {
          MockHttpServletResponse response = performAnonymously(endpoint);
          assertThat(isEntryPointUnauthorized(response))
              .as("@PublicEndpoint %s must pass the security chain; got %d %s",
                  endpoint, response.getStatus(), response.getContentAsString())
              .isFalse();
          assertThat(isAccessDenied(response))
              .as("@PublicEndpoint %s must not be denied (%s); got %d %s",
                  endpoint, ACCESS_DENIED_CODE, response.getStatus(),
                  response.getContentAsString())
              .isFalse();
        });
  }

  /**
   * Dispatch-order guard (code review L-2): {@link PublicEndpointRequestMatcher} only knows the
   * {@code requestMappingHandlerMapping}. Each public {@code (method, pattern)} is resolved the
   * way {@code DispatcherServlet} resolves it, through every {@link HandlerMapping} bean in order,
   * and the first mapping that returns a handler must return that same {@code @PublicEndpoint}
   * handler method, so no higher-precedence mapping (actuator's is order -100) takes the request
   * while the matcher answers "public".
   */
  @TestFactory
  Stream<DynamicTest> should_dispatch_to_public_handler_when_resolved_through_ordered_mappings() {
    List<HandlerMapping> orderedMappings = orderedHandlerMappings(context);
    return dynamicTests(
        publicProductionEndpoints(),
        endpoint -> {
          MockHttpServletRequest request = endpoint.servletRequest();
          if (METHODS_WITH_BODY.contains(endpoint.method())) {
            request.setContentType(MediaType.APPLICATION_JSON_VALUE);
          }
          ServletRequestPathUtils.parseAndCache(request);
          assertThat(firstHandler(orderedMappings, request))
              .as("first handler for %s in DispatcherServlet order", endpoint)
              .isInstanceOfSatisfying(HandlerMethod.class, dispatched -> {
                assertThat(dispatched.getMethod()).isEqualTo(endpoint.handler().getMethod());
                assertThat(dispatched.hasMethodAnnotation(PublicEndpoint.class)).isTrue();
              });
        });
  }

  @TestFactory
  Stream<DynamicTest> should_return_entry_point_401_when_anonymous_calls_non_public_endpoint() {
    return dynamicTests(
        endpoints(Endpoint::isProduction).stream().filter(e -> !e.isPublic()).toList(),
        endpoint -> {
          MockHttpServletResponse response = performAnonymously(endpoint);
          assertThat(isEntryPointUnauthorized(response))
              .as("non-public %s must get the entry-point 401 (%s); got %d %s",
                  endpoint, ENTRY_POINT_CODE, response.getStatus(), response.getContentAsString())
              .isTrue();
        });
  }

  /**
   * Authorization matrix, signed-in caller holding no permission (A8, Decision 1): an {@code
   * @AuthenticatedEndpoint} handler needs a signed-in caller and nothing more, so the chain must
   * neither challenge (401) nor deny (403) a caller whose token carries no permission. Under C5 a
   * new user holds zero permissions, which is why {@code me()} is not permission-guarded.
   */
  @TestFactory
  Stream<DynamicTest>
      should_pass_security_when_caller_without_permissions_calls_authenticated_endpoint() {
    return dynamicTests(
        endpoints(Endpoint::isProduction).stream()
            .filter(endpoint -> AnnotatedElementUtils.hasAnnotation(
                endpoint.handler().getMethod(), AuthenticatedEndpoint.class))
            .toList(),
        endpoint -> {
          MockHttpServletResponse response =
              performAs(endpoint, authenticatedWithoutPermissions());
          assertThat(response.getStatus())
              .as("@AuthenticatedEndpoint %s for a caller with no permission; body %s",
                  endpoint, response.getContentAsString())
              .isNotIn(HttpStatus.UNAUTHORIZED.value(), HttpStatus.FORBIDDEN.value());
        });
  }

  /**
   * Authorization matrix, signed-in caller holding no permission (A8, FR-A8.b): a handler
   * classified {@code @RequiresPermission} must be guarded at runtime, not only labelled. Each
   * production handler is invoked on its registered bean (the method-security proxy) as a caller
   * with no permission, and must be denied with {@code PERMISSION_ABSENT} for the permission it
   * declares before its body runs. The call goes to the bean rather than through MockMvc because
   * MVC validates a {@code @Valid @RequestBody} before it invokes the proxy, so a request with a
   * placeholder body stops at 400 and never reaches the guard. The permission-holder outcome of
   * each handler is covered by the rbac {@code *SecurityIT}s and {@code CrossTenantPermissionIT}.
   */
  @TestFactory
  Stream<DynamicTest>
      should_deny_permission_absent_when_caller_without_permissions_invokes_guarded_handler() {
    List<HandlerMethod> guardedHandlers =
        handlerMapping.getHandlerMethods().values().stream()
            .filter(EndpointClassificationWebTest::isProductionHandler)
            .filter(handler -> AnnotatedElementUtils.hasAnnotation(
                handler.getMethod(), RequiresPermission.class))
            .distinct()
            .toList();
    assertThat(guardedHandlers).as("production @RequiresPermission handlers").isNotEmpty();
    return guardedHandlers.stream()
        .map(handler -> DynamicTest.dynamicTest(
            handler.getBeanType().getSimpleName() + "." + handler.getMethod().getName(),
            () -> assertDeniedWithoutPermissions(handler)));
  }

  @Test
  void should_register_only_reviewed_handler_mapping_types_when_context_starts() {
    assertThat(orderedHandlerMappings(context))
        .extracting(mapping -> mapping.getClass().getName())
        .as("HandlerMapping bean types (review a new one, then list it in HANDLER_MAPPING_TYPES)")
        .isNotEmpty()
        .allMatch(HANDLER_MAPPING_TYPES::contains);
  }

  /**
   * Security review F-1: what each handler mapping holds. Functional endpoints and bean-name
   * handlers are absent, URL mappings serve static resources only, and a main-source handler is
   * registered only in {@code requestMappingHandlerMapping}, the mapping every sweep reads.
   */
  @TestFactory
  Stream<DynamicTest> should_hold_only_reviewed_handlers_when_handler_mapping_is_registered() {
    return orderedHandlerMappings(context).stream()
        .map(mapping -> DynamicTest.dynamicTest(
            mapping.getClass().getSimpleName(), () -> assertReviewedHandlers(mapping)));
  }

  @Test
  void should_not_allowlist_production_type_when_handler_is_non_production() {
    assertThat(NON_PRODUCTION_HANDLER_ALLOWLIST)
        .as("NON_PRODUCTION_HANDLER_ALLOWLIST entries that are main-source classes")
        .doesNotContainAnyElementsOf(PRODUCTION_CLASS_NAMES);
  }

  /**
   * Drift guard for {@link #PERMIT_ALL_PATTERNS} and the matcher (security review F-5, US-018
   * T-009). It asks the configured chain's own {@code AuthorizationManager}, the one {@code
   * AuthorizationFilter} consults, about an anonymous caller: for every path of every handler
   * mapping, each sample of the mirror, and the sibling and child of each entry, every HTTP method
   * must be granted exactly when a mirror entry matches the path or {@link
   * PublicEndpointRequestMatcher} matches the request. A {@code permitAll} entry added, removed or
   * widened in {@code SecurityConfig} without the mirror, or a chain that stops consulting the
   * matcher, fails here.
   */
  @TestFactory
  Stream<DynamicTest> should_permit_anonymous_request_only_when_path_is_on_permit_all_list() {
    AuthorizationManager<HttpServletRequest> authorization = authorizationManager(context);
    return driftProbePaths().stream()
        .map(path -> DynamicTest.dynamicTest(path, () -> {
          boolean listed = PERMIT_ALL_PATTERNS.stream()
              .anyMatch(pattern -> PathPatternParser.defaultInstance.parse(pattern)
                  .matches(PathContainer.parsePath(path)));
          List<String> mismatches = ALL_METHODS.stream()
              .filter(method -> isGrantedAnonymously(
                  authorization, context.getServletContext(), method, path)
                  != (listed || matcher.matches(new MockHttpServletRequest(method.name(), path))))
              .map(method -> method + " " + path)
              .toList();
          assertThat(mismatches)
              .as("anonymous access differs from PERMIT_ALL_PATTERNS (on the list: %s) or the "
                  + "public-endpoint matcher; change the mirror together with SecurityConfig",
                  listed)
              .isEmpty();
        }));
  }

  /**
   * Security review F-5: {@code permitAll} matches on path only, so every HTTP method on every
   * {@code permitAll} path is resolved the way {@code DispatcherServlet} resolves it (ordered
   * handler mappings) and must reach no handler, a {@code @PublicEndpoint} handler, or an
   * allowlisted non-production handler. A non-public pattern such as {@code
   * /api/v1/auth/{action}} that also matches a permitted literal fails here.
   */
  @TestFactory
  Stream<DynamicTest> should_reach_only_public_handler_when_request_hits_permit_all_path() {
    List<HandlerMapping> orderedMappings = orderedHandlerMappings(context);
    return permitAllSamplePaths().stream()
        .map(path -> DynamicTest.dynamicTest(path, () ->
            assertThat(permitAllDispatchViolations(orderedMappings, path))
                .as("methods on permitAll path %s that reach a non-public handler", path)
                .isEmpty()));
  }

  @TestFactory
  Stream<DynamicTest> should_match_exactly_when_handler_is_public_endpoint() {
    return dynamicTests(
        endpoints(endpoint -> true),
        endpoint ->
            assertThat(matcher.matches(endpoint.servletRequest()))
                .as("matcher result for %s", endpoint)
                .isEqualTo(endpoint.isPublic()));
  }

  @Test
  void should_not_match_when_same_path_as_public_handler_uses_different_method() {
    List<Endpoint> fixture =
        endpoints(e -> e.handler().getBeanType() == SamePathOtherMethodController.class);
    assertThat(fixture)
        .as("fixture GET %s is registered", PUBLIC_REFRESH_PATH)
        .singleElement()
        .satisfies(e -> assertThat(e.servletRequest().getRequestURI())
            .isEqualTo(PUBLIC_REFRESH_PATH));

    assertThat(matcher.matches(new MockHttpServletRequest("GET", PUBLIC_REFRESH_PATH))).isFalse();
  }

  /**
   * US-018 T-009: {@code permitAll} is the matcher's method-and-pattern decision, so the fixture's
   * {@code GET} on the public refresh path is challenged like any non-public handler.
   */
  @Test
  void should_return_entry_point_401_when_anonymous_uses_other_method_on_public_path()
      throws Exception {
    MockHttpServletResponse response =
        mvc.perform(request(HttpMethod.GET, PUBLIC_REFRESH_PATH)).andReturn().getResponse();

    assertThat(isEntryPointUnauthorized(response))
        .as("anonymous GET %s; got %d %s",
            PUBLIC_REFRESH_PATH, response.getStatus(), response.getContentAsString())
        .isTrue();
  }

  /**
   * US-018 T-009 (STATUS "For T-009"): every {@code @PublicEndpoint} pattern is a literal path. A
   * path variable or wildcard would let the public exemption, which skips the permission-epoch
   * check, cover paths no reviewer listed.
   */
  @TestFactory
  Stream<DynamicTest> should_use_literal_pattern_when_handler_is_public_endpoint() {
    return dynamicTests(
        publicProductionEndpoints(),
        endpoint -> assertThat(endpoint.pattern())
            .as("@PublicEndpoint pattern of %s", endpoint)
            .doesNotContain("{", "*", "?"));
  }

  // ── helpers ────────────────────────────────────────────────────────────────

  private List<Endpoint> endpoints(Predicate<Endpoint> filter) {
    List<Endpoint> endpoints =
        handlerMapping.getHandlerMethods().entrySet().stream()
            .flatMap(entry -> Endpoint.of(entry.getKey(), entry.getValue()))
            .filter(filter)
            .toList();
    assertThat(endpoints).as("handlers found in the handler mapping").isNotEmpty();
    return endpoints;
  }

  private List<Endpoint> publicProductionEndpoints() {
    return endpoints(Endpoint::isProduction).stream().filter(Endpoint::isPublic).toList();
  }

  /**
   * The handler {@code DispatcherServlet} would invoke, or {@code null} when no mapping returns
   * one or the first mapping that matches the path rejects the request ({@code
   * HttpRequestMethodNotSupportedException} and the other {@code ServletException}s a mapping
   * throws become a 4xx error response before any handler runs).
   */
  private static Object firstHandler(List<HandlerMapping> orderedMappings,
      MockHttpServletRequest request) throws Exception {
    for (HandlerMapping mapping : orderedMappings) {
      HandlerExecutionChain chain;
      try {
        chain = mapping.getHandler(request);
      } catch (ServletException rejected) {
        return null;
      }
      if (chain != null) {
        return chain.getHandler();
      }
    }
    return null;
  }

  private static List<HandlerMapping> orderedHandlerMappings(WebApplicationContext context) {
    List<HandlerMapping> orderedMappings =
        new ArrayList<>(
            BeanFactoryUtils.beansOfTypeIncludingAncestors(
                    context, HandlerMapping.class, true, false)
                .values());
    AnnotationAwareOrderComparator.sort(orderedMappings);
    return orderedMappings;
  }

  private void assertReviewedHandlers(HandlerMapping mapping) {
    switch (mapping) {
      case RouterFunctionMapping functional ->
          assertThat(functional.getRouterFunction()).as("functional endpoints").isNull();
      case SimpleUrlHandlerMapping resources -> {
        assertThat(resources.getHandlerMap().values())
            .as("handlers of %s", resources)
            .allMatch(ResourceHttpRequestHandler.class::isInstance);
        assertThat(resources.getRootHandler()).as("root handler of %s", resources).isNull();
      }
      // BeanNameUrlHandlerMapping and the welcome-page mappings
      case AbstractUrlHandlerMapping urls -> {
        assertThat(urls.getHandlerMap()).as("handlers of %s", urls).isEmpty();
        assertThat(urls.getRootHandler()).as("root handler of %s", urls).isNull();
      }
      case AbstractHandlerMethodMapping<?> methods ->
          assertThat(methods.getHandlerMethods().values())
              .as("handlers of %s: a main-source handler only in requestMappingHandlerMapping, "
                  + "any other handler allowlisted", methods)
              .allMatch(handler -> PRODUCTION_CLASS_NAMES.contains(handler.getBeanType().getName())
                  ? methods == handlerMapping
                  : NON_PRODUCTION_HANDLER_ALLOWLIST.contains(handler.getBeanType().getName()));
      default -> fail("unreviewed HandlerMapping type %s", mapping.getClass().getName());
    }
  }

  /**
   * True for a main-source handler; false for an allowlisted non-production one. Any other
   * handler fails the calling sweep instead of being left out silently (security review F-1).
   */
  private static boolean isProductionHandler(HandlerMethod handler) {
    String beanType = handler.getBeanType().getName();
    boolean production = PRODUCTION_CLASS_NAMES.contains(beanType);
    assertThat(production || NON_PRODUCTION_HANDLER_ALLOWLIST.contains(beanType))
        .as("handler %s is neither a main-source class nor in NON_PRODUCTION_HANDLER_ALLOWLIST",
            handler)
        .isTrue();
    return production;
  }

  /**
   * Each HTTP method on {@code path} whose first handler in {@code DispatcherServlet} order is
   * neither absent, a {@code @PublicEndpoint} handler method, nor an allowlisted non-production
   * handler, described as {@code "<METHOD> <path> -> <handler>"}.
   */
  private static List<String> permitAllDispatchViolations(
      List<HandlerMapping> orderedMappings, String path) throws Exception {
    List<String> violations = new ArrayList<>();
    for (RequestMethod method : ALL_METHODS) {
      MockHttpServletRequest request = new MockHttpServletRequest(method.name(), path);
      if (METHODS_WITH_BODY.contains(method)) {
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
      }
      ServletRequestPathUtils.parseAndCache(request);
      Object handler = firstHandler(orderedMappings, request);
      if (!mayServePermitAllPath(handler)) {
        violations.add(method + " " + path + " -> " + describe(handler));
      }
    }
    return violations;
  }

  private static boolean mayServePermitAllPath(Object handler) {
    if (handler == null) {
      return true;
    }
    if (handler instanceof HandlerMethod handlerMethod) {
      return handlerMethod.hasMethodAnnotation(PublicEndpoint.class)
          || isAllowlistedNonProduction(handlerMethod.getBeanType());
    }
    return isAllowlistedNonProduction(handler.getClass());
  }

  private static boolean isAllowlistedNonProduction(Class<?> handlerType) {
    return !PRODUCTION_CLASS_NAMES.contains(handlerType.getName())
        && NON_PRODUCTION_HANDLER_ALLOWLIST.contains(handlerType.getName());
  }

  private static String describe(Object handler) {
    return handler instanceof HandlerMethod handlerMethod
        ? handlerMethod.getBeanType().getSimpleName() + "." + handlerMethod.getMethod().getName()
        : handler.getClass().getName();
  }

  private static AuthorizationManager<HttpServletRequest> authorizationManager(
      WebApplicationContext context) {
    List<AuthorizationManager<HttpServletRequest>> managers =
        context.getBean(FilterChainProxy.class).getFilterChains().stream()
            .flatMap(chain -> chain.getFilters().stream())
            .filter(AuthorizationFilter.class::isInstance)
            .map(filter -> ((AuthorizationFilter) filter).getAuthorizationManager())
            .toList();
    assertThat(managers).as("AuthorizationFilters in the security filter chains").hasSize(1);
    return managers.get(0);
  }

  // The servlet context is what lets an endpoint-aware matcher (the actuator rule) find the web
  // application context; a bare request has none.
  private static boolean isGrantedAnonymously(
      AuthorizationManager<HttpServletRequest> authorization,
      ServletContext servletContext,
      RequestMethod method,
      String path) {
    AuthorizationResult result = authorization.authorize(
        () -> ANONYMOUS, new MockHttpServletRequest(servletContext, method.name(), path));
    return result != null && result.isGranted();
  }

  /** Request paths covering one {@code permitAll} pattern. */
  private static List<String> samplePaths(String pattern) {
    if (pattern.endsWith("/**")) {
      String base = pattern.substring(0, pattern.length() - "/**".length());
      return List.of(base, base + "/" + PROBE_SEGMENT);
    }
    assertThat(pattern)
        .as("permitAll pattern with a wildcard other than a trailing /** (extend samplePaths)")
        .doesNotContain("*", "{");
    return List.of(pattern);
  }

  private static Set<String> permitAllSamplePaths() {
    Set<String> paths = new TreeSet<>();
    PERMIT_ALL_PATTERNS.forEach(pattern -> paths.addAll(samplePaths(pattern)));
    return paths;
  }

  /**
   * The {@code permitAll} samples, the sibling and child of each (they catch an entry widened to a
   * wildcard), and every pattern of every handler-method mapping with its variables and
   * wildcards filled.
   */
  private Set<String> driftProbePaths() {
    Set<String> paths = new TreeSet<>(permitAllSamplePaths());
    for (String sample : permitAllSamplePaths()) {
      paths.add(sample + "/" + PROBE_SEGMENT);
      paths.add(sample.substring(0, sample.lastIndexOf('/')) + "/" + PROBE_SEGMENT);
    }
    for (HandlerMapping mapping : orderedHandlerMappings(context)) {
      if (mapping instanceof AbstractHandlerMethodMapping<?> methods) {
        methods.getHandlerMethods().keySet().stream()
            .filter(RequestMappingInfo.class::isInstance)
            .flatMap(info -> ((RequestMappingInfo) info).getPatternValues().stream())
            .map(EndpointClassificationWebTest::probePath)
            .forEach(paths::add);
      }
    }
    return paths;
  }

  private static String probePath(String pattern) {
    UriTemplate template = new UriTemplate(pattern.replace("/**", "/" + PROBE_SEGMENT));
    Map<String, String> variables = new HashMap<>();
    template.getVariableNames().forEach(name -> variables.put(name, PROBE_SEGMENT));
    return template.expand(variables).getRawPath();
  }

  private MockHttpServletResponse performAnonymously(Endpoint endpoint) throws Exception {
    MockHttpServletRequestBuilder request =
        request(HttpMethod.valueOf(endpoint.method().name()), endpoint.uri());
    if (METHODS_WITH_BODY.contains(endpoint.method())) {
      request.contentType(MediaType.APPLICATION_JSON).content("{}");
    }
    return mvc.perform(request).andReturn().getResponse();
  }

  private MockHttpServletResponse performAs(Endpoint endpoint, Authentication caller)
      throws Exception {
    MockHttpServletRequestBuilder request =
        request(HttpMethod.valueOf(endpoint.method().name()), endpoint.uri())
            .with(authentication(caller));
    if (METHODS_WITH_BODY.contains(endpoint.method())) {
      request.contentType(MediaType.APPLICATION_JSON).content("{}");
    }
    return mvc.perform(request).andReturn().getResponse();
  }

  /**
   * A signed-in caller holding no permission, shaped like the {@code Authentication} that {@code
   * JwtAuthenticationFilter} builds (UUID subject, tenant, token version, empty permissions).
   */
  private static Authentication authenticatedWithoutPermissions() {
    UsernamePasswordAuthenticationToken caller =
        UsernamePasswordAuthenticationToken.authenticated(
            NO_PERMISSION_SUBJECT, null, List.of());
    caller.setDetails(Map.of(
        AuthenticationDetailKeys.TENANT_ID, NO_PERMISSION_TENANT,
        AuthenticationDetailKeys.EMAIL_VERIFIED, true,
        AuthenticationDetailKeys.TOKEN_VERSION, 2,
        AuthenticationDetailKeys.PERMISSIONS, List.of()));
    return caller;
  }

  private static void assertDeniedWithoutPermissions(HandlerMethod handler) {
    Method method = handler.getMethod();
    String required =
        AnnotatedElementUtils.findMergedAnnotation(method, RequiresPermission.class).value();
    Object bean = handler.createWithResolvedBean().getBean();
    ReflectionUtils.makeAccessible(method);
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(authenticatedWithoutPermissions());
    SecurityContextHolder.setContext(context);
    try {
      assertThatThrownBy(() -> method.invoke(bean, placeholderArguments(method)))
          .as("%s invoked on bean %s by a caller with no permission",
              handler, bean.getClass().getName())
          .isInstanceOf(InvocationTargetException.class)
          .cause()
          .isInstanceOfSatisfying(InsufficientPermissionException.class, denied -> {
            assertThat(denied.getRequiredPermission()).isEqualTo(required);
            assertThat(denied.getReason()).isEqualTo(DenialReason.PERMISSION_ABSENT);
          });
    } finally {
      SecurityContextHolder.clearContext();
    }
  }

  /** Null for each reference parameter and the default value for each primitive one. */
  private static Object[] placeholderArguments(Method method) {
    return Arrays.stream(method.getParameterTypes())
        .map(type -> type.isPrimitive() ? Array.get(Array.newInstance(type, 1), 0) : null)
        .toArray();
  }

  /** The response written by {@code SecurityConfig.jwtAuthenticationEntryPoint}. */
  private static boolean isEntryPointUnauthorized(MockHttpServletResponse response)
      throws Exception {
    if (response.getStatus() != HttpStatus.UNAUTHORIZED.value()) {
      return false;
    }
    Map<String, Object> body = JsonPath.parse(response.getContentAsString()).read("$");
    return ENTRY_POINT_CODE.equals(body.get("code")) && !body.containsKey("instance");
  }

  /** A 403 from {@code SecurityConfig.accessDeniedHandler} or the advice's access-denied handler. */
  private static boolean isAccessDenied(MockHttpServletResponse response) throws Exception {
    if (response.getStatus() != HttpStatus.FORBIDDEN.value()) {
      return false;
    }
    Map<String, Object> body = JsonPath.parse(response.getContentAsString()).read("$");
    return ACCESS_DENIED_CODE.equals(body.get("code"));
  }

  private static Stream<DynamicTest> dynamicTests(
      List<Endpoint> endpoints, EndpointAssertion assertion) {
    assertThat(endpoints).as("endpoints to sweep").isNotEmpty();
    return endpoints.stream()
        .map(endpoint -> DynamicTest.dynamicTest(
            endpoint.toString(), () -> assertion.verify(endpoint)));
  }

  @FunctionalInterface
  private interface EndpointAssertion {
    void verify(Endpoint endpoint) throws Exception;
  }

  /** One {@code (HTTP method, path pattern)} pair of a handler, with path variables filled. */
  private record Endpoint(RequestMethod method, String pattern, URI uri, HandlerMethod handler) {

    static Stream<Endpoint> of(RequestMappingInfo info, HandlerMethod handler) {
      Set<RequestMethod> methods = info.getMethodsCondition().getMethods();
      // A mapping without a method condition is dispatched for GET too.
      Set<RequestMethod> swept = methods.isEmpty() ? Set.of(RequestMethod.GET) : methods;
      return info.getPatternValues().stream()
          .flatMap(pattern -> swept.stream()
              .map(method -> new Endpoint(method, pattern, expand(pattern), handler)));
    }

    private static URI expand(String pattern) {
      UriTemplate template = new UriTemplate(pattern);
      Map<String, String> variables = new HashMap<>();
      template.getVariableNames().forEach(name -> variables.put(name, UUID.randomUUID().toString()));
      return template.expand(variables);
    }

    boolean isPublic() {
      return handler.hasMethodAnnotation(PublicEndpoint.class);
    }

    boolean isProduction() {
      return isProductionHandler(handler);
    }

    MockHttpServletRequest servletRequest() {
      return new MockHttpServletRequest(method.name(), uri.getRawPath());
    }

    @Override
    public String toString() {
      return method + " " + pattern + " -> " + handler.getBeanType().getSimpleName() + "."
          + handler.getMethod().getName();
    }
  }

  // ── fixture: a non-public handler on a public handler's path, other method ─

  @RestController
  static class SamePathOtherMethodController {
    @GetMapping(PUBLIC_REFRESH_PATH)
    public void refreshViaGet() {
      // fixture: never invoked; only its mapping matters
    }
  }

  @TestConfiguration(proxyBeanMethods = false)
  static class SamePathOtherMethodFixtureConfig {
    @Bean
    SamePathOtherMethodController samePathOtherMethodController() {
      return new SamePathOtherMethodController();
    }
  }

  // ── probe: a non-public pattern that matches permitAll literals (F-5) ──────

  /**
   * The security review F-5 case, closed by US-018 T-009. This dedicated context is the sweep
   * context plus {@link AuthSegmentProbeController}, whose authenticated-only {@code GET
   * /api/v1/auth/{action}} binds no identifier (so it passes the ArchUnit rules) and also matches
   * the public literal {@code /api/v1/auth/login}. While {@code permitAll} listed that literal by
   * path, the probe served anonymous {@code GET /api/v1/auth/login}; now that {@code permitAll} is
   * the matcher's method-and-pattern decision, the overlapping non-public mapping makes the request
   * non-public. The probe is imported only here, never into the sweep context: it is imported as a
   * plain class because Spring Boot adds every static nested {@code @TestConfiguration} of a test
   * class to that class's own context.
   */
  @Nested
  @Import(AuthSegmentProbeController.class)
  class PermitAllOverlapProbe {

    @Autowired private WebApplicationContext probeContext;

    @Test
    void should_deny_anonymous_access_when_non_public_pattern_matches_public_literal() {
      AuthorizationManager<HttpServletRequest> authorization = authorizationManager(probeContext);

      assertThat(isGrantedAnonymously(
          authorization, probeContext.getServletContext(), RequestMethod.GET, "/api/v1/auth/login"))
          .as("anonymous GET /api/v1/auth/login, served by the non-public probe")
          .isFalse();
      assertThat(isGrantedAnonymously(
          authorization, probeContext.getServletContext(), RequestMethod.HEAD, "/api/v1/auth/login"))
          .as("anonymous HEAD /api/v1/auth/login, served by the non-public probe")
          .isFalse();
      assertThat(isGrantedAnonymously(
          authorization, probeContext.getServletContext(), RequestMethod.POST, "/api/v1/auth/login"))
          .as("anonymous POST /api/v1/auth/login, the public login handler")
          .isTrue();
    }
  }

  @RestController
  static class AuthSegmentProbeController {
    @GetMapping("/api/v1/auth/{action}")
    @AuthenticatedEndpoint
    public String segment(Authentication authentication) {
      return "probe: never invoked; only its mapping matters";
    }
  }
}
