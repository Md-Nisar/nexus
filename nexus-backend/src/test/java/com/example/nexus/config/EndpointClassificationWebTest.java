package com.example.nexus.config;

import static java.util.stream.Collectors.toUnmodifiableSet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;

import com.example.nexus.common.security.PublicEndpoint;
import com.example.nexus.identity.application.service.LogoutUseCase;
import com.example.nexus.identity.infrastructure.web.PublicEndpointRequestMatcher;
import com.jayway.jsonpath.JsonPath;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.UriTemplate;

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
 * <p>The sweep is limited to production handlers (classes outside test sources): the handler
 * mapping also holds springdoc's and Spring Boot's handlers, and the test-only fixture below.
 *
 * <p>The matcher sweep checks {@link PublicEndpointRequestMatcher} against every mapping. The
 * fixture {@link SamePathOtherMethodController} maps {@code GET} on the public refresh pattern;
 * it is kept out of the anonymous sweep because {@code permitAll} matches on path only, so it is
 * reachable anonymously today. That is outside this test's scope: the fixture proves the matcher
 * does not repeat it.
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
  private static final String PUBLIC_REFRESH_PATH = "/api/v1/auth/refresh";
  private static final Set<RequestMethod> METHODS_WITH_BODY =
      Set.of(RequestMethod.POST, RequestMethod.PUT, RequestMethod.PATCH);

  /** Production {@code @RestController} classes: the same import scope as the ArchUnit rules. */
  private static final Set<String> PRODUCTION_CONTROLLERS =
      new ClassFileImporter()
          .withImportOption(new ImportOption.DoNotIncludeTests())
          .importPackages("com.example.nexus")
          .stream()
          .filter(javaClass -> javaClass.isMetaAnnotatedWith(RestController.class))
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
        .as("production @RestController classes registered as handlers (a feature flag is off?)")
        .isNotEmpty()
        .allMatch(registered::contains);
  }

  @TestFactory
  Stream<DynamicTest> should_not_return_entry_point_401_when_anonymous_calls_public_endpoint() {
    return dynamicTests(
        endpoints(Endpoint::isProduction).stream().filter(Endpoint::isPublic).toList(),
        endpoint -> {
          MockHttpServletResponse response = performAnonymously(endpoint);
          assertThat(isEntryPointUnauthorized(response))
              .as("@PublicEndpoint %s must pass the security chain; got %d %s",
                  endpoint, response.getStatus(), response.getContentAsString())
              .isFalse();
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

  private MockHttpServletResponse performAnonymously(Endpoint endpoint) throws Exception {
    MockHttpServletRequestBuilder request =
        request(HttpMethod.valueOf(endpoint.method().name()), endpoint.uri());
    if (METHODS_WITH_BODY.contains(endpoint.method())) {
      request.contentType(MediaType.APPLICATION_JSON).content("{}");
    }
    return mvc.perform(request).andReturn().getResponse();
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
      return PRODUCTION_CONTROLLERS.contains(handler.getBeanType().getName());
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
}
