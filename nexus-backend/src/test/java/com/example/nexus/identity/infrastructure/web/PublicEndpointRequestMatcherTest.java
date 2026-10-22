package com.example.nexus.identity.infrastructure.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;

import com.example.nexus.identity.interfaces.rest.JwksController;
import com.example.nexus.identity.interfaces.rest.LoginController;
import com.example.nexus.identity.interfaces.rest.UserProfileController;
import com.example.nexus.identity.interfaces.rest.dto.LoginRequest;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.RequestPath;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.ServletRequestPathUtils;

/**
 * Unit tests for {@link PublicEndpointRequestMatcher} (US-018 A8, design §3.1, RC-44.1).
 *
 * <p>No Spring context: a real {@link RequestMappingHandlerMapping} is filled with {@code
 * registerMapping} using the real {@link LoginController} and {@link UserProfileController}
 * handler methods, so the {@code @PublicEndpoint} / {@code @AuthenticatedEndpoint} markers read by
 * the matcher are the production ones.
 */
@Tag("UnitTest")
class PublicEndpointRequestMatcherTest {

  private static final String LOGIN = "/api/v1/auth/login";
  private static final String REFRESH = "/api/v1/auth/refresh";
  private static final String LOGOUT = "/api/v1/auth/logout";
  private static final String ME = "/api/v1/users/me";
  private static final String JWKS = "/.well-known/jwks.json";

  private final LoginController loginController = mock(LoginController.class);
  private final UserProfileController profileController = mock(UserProfileController.class);
  private final JwksController jwksController = mock(JwksController.class);
  private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
  private RequestMappingHandlerMapping handlerMapping;

  @BeforeEach
  void setUp() throws NoSuchMethodException {
    handlerMapping = new RequestMappingHandlerMapping();
    registerPost(LOGIN, loginMethod("login", LoginRequest.class));
    registerPost(REFRESH, loginMethod("refresh", String.class));
    registerPost(LOGOUT, loginMethod("logout", String.class));
    handlerMapping.registerMapping(
        RequestMappingInfo.paths(ME).methods(RequestMethod.GET).build(),
        profileController,
        meMethod());
  }

  @ParameterizedTest
  @ValueSource(strings = {LOGIN, REFRESH, LOGOUT})
  void should_match_when_anonymous_post_to_public_auth_endpoint(String path) {
    assertThat(matcher().matches(request("POST", path))).isTrue();
  }

  @Test
  void should_not_match_when_method_differs_on_public_pattern() {
    assertThat(matcher().matches(request("GET", REFRESH))).isFalse();
  }

  @Test
  void should_not_match_when_path_parsing_throws() {
    // A context path that is not a prefix of the request URI makes RequestPath.parse throw.
    MockHttpServletRequest request = request("POST", LOGIN);
    request.setContextPath("/not-a-prefix");

    assertThat(matcher().matches(request)).isFalse();
  }

  @Test
  void should_not_match_when_condition_evaluation_throws_after_path_is_parsed() {
    assertThat(matcher().matches(requestWhoseMethodThrows(LOGIN))).isFalse();
  }

  @Test
  void should_leave_no_cached_request_path_when_condition_evaluation_throws() {
    // Precondition: the path itself parses, so matches() caches it before evaluation throws.
    assertThatCode(() -> ServletRequestPathUtils.parseAndCache(requestWhoseMethodThrows(LOGIN)))
        .doesNotThrowAnyException();
    MockHttpServletRequest request = requestWhoseMethodThrows(LOGIN);

    matcher().matches(request);

    assertThat(request.getAttribute(ServletRequestPathUtils.PATH_ATTRIBUTE)).isNull();
  }

  // Each request addresses no handler under MVC dispatch, so none may be public (fail closed).
  @ParameterizedTest
  @CsvSource({
    "POST, /api/v1/auth/login/",
    "POST, /API/V1/AUTH/LOGIN",
    "POST, /api/v1//auth/login",
    "post, /api/v1/auth/login",
    "PROPFIND, /api/v1/auth/login"
  })
  void should_not_match_when_request_is_not_canonical_public_method_and_path(
      String method, String path) {
    assertThat(matcher().matches(request(method, path))).isFalse();
  }

  @Test
  void should_not_match_when_path_unknown() {
    assertThat(matcher().matches(request("POST", "/api/v1/auth/unknown"))).isFalse();
  }

  @Test
  void should_not_match_when_handler_is_authenticated_endpoint() {
    assertThat(matcher().matches(request("GET", "/api/v1/users/me"))).isFalse();
  }

  @Test
  void should_not_match_when_non_public_mapping_also_matches_request() throws Exception {
    handlerMapping.registerMapping(
        RequestMappingInfo.paths("/api/v1/auth/{action}").methods(RequestMethod.POST).build(),
        profileController,
        meMethod());

    assertThat(matcher().matches(request("POST", LOGIN))).isFalse();
  }

  @Test
  void should_not_match_when_public_handler_declares_no_http_method() throws Exception {
    handlerMapping.registerMapping(
        RequestMappingInfo.paths("/api/v1/auth/any-method").build(),
        loginController,
        loginMethod("login", LoginRequest.class));

    assertThat(matcher().matches(request("POST", "/api/v1/auth/any-method"))).isFalse();
  }

  // An AntPathMatcher-based mapping is the only way to get a null path-patterns condition; Spring
  // has deprecated it for removal, and this case goes away with it.
  @SuppressWarnings("removal")
  @Test
  void should_not_match_when_public_handler_has_no_path_patterns_condition() throws Exception {
    RequestMappingInfo.BuilderConfiguration antPathOptions =
        new RequestMappingInfo.BuilderConfiguration();
    antPathOptions.setPathMatcher(new AntPathMatcher());
    handlerMapping.registerMapping(
        RequestMappingInfo.paths("/api/v1/auth/ant-style")
            .methods(RequestMethod.POST)
            .options(antPathOptions)
            .build(),
        loginController,
        loginMethod("login", LoginRequest.class));

    assertThat(matcher().matches(request("POST", "/api/v1/auth/ant-style"))).isFalse();
    // Such a mapping cannot be evaluated, so it counts as matching every request (fail closed).
    assertThat(matcher().matches(request("POST", LOGIN))).isFalse();
  }

  @Test
  void should_match_when_head_request_targets_public_get_endpoint() throws Exception {
    handlerMapping.registerMapping(
        RequestMappingInfo.paths(JWKS).methods(RequestMethod.GET).build(),
        jwksController,
        JwksController.class.getDeclaredMethod("jwks"));

    assertThat(matcher().matches(request("HEAD", JWKS))).isTrue();
  }

  @Test
  void should_match_when_cors_preflight_requests_post_on_public_endpoint() {
    assertThat(matcher().matches(preflight(LOGIN, "POST"))).isTrue();
  }

  @Test
  void should_not_match_when_cors_preflight_requests_get_on_authenticated_endpoint() {
    assertThat(matcher().matches(preflight(ME, "GET"))).isFalse();
  }

  @Test
  void should_not_match_when_plain_options_request_targets_public_endpoint() {
    assertThat(matcher().matches(request("OPTIONS", LOGIN))).isFalse();
  }

  @Test
  void should_match_when_request_has_valid_context_path() {
    MockHttpServletRequest request = request("POST", "/nexus" + LOGIN);
    request.setContextPath("/nexus");

    assertThat(matcher().matches(request)).isTrue();
  }

  @Test
  void should_match_when_request_lacks_media_type_required_by_consumes_condition()
      throws Exception {
    handlerMapping = new RequestMappingHandlerMapping();
    handlerMapping.registerMapping(
        RequestMappingInfo.paths(LOGIN)
            .methods(RequestMethod.POST)
            .consumes("application/json")
            .build(),
        loginController,
        loginMethod("login", LoginRequest.class));

    assertThat(matcher().matches(request("POST", LOGIN))).isTrue();
  }

  @Test
  void should_restore_previously_cached_request_path_when_matching() {
    MockHttpServletRequest request = request("POST", LOGIN);
    RequestPath previous = RequestPath.parse("/previous", null);
    request.setAttribute(ServletRequestPathUtils.PATH_ATTRIBUTE, previous);

    matcher().matches(request);

    assertThat(request.getAttribute(ServletRequestPathUtils.PATH_ATTRIBUTE)).isSameAs(previous);
  }

  @Test
  void should_leave_no_cached_request_path_when_none_was_cached_before() {
    MockHttpServletRequest request = request("POST", LOGIN);

    matcher().matches(request);

    assertThat(request.getAttribute(ServletRequestPathUtils.PATH_ATTRIBUTE)).isNull();
  }

  private PublicEndpointRequestMatcher matcher() {
    return new PublicEndpointRequestMatcher(handlerMapping, meterRegistry);
  }

  @Test
  void should_incrementFailedClosedCounter_when_matchingThrows() {
    PublicEndpointRequestMatcher matcher = matcher();

    matcher.matches(requestWhoseMethodThrows(LOGIN));

    assertThat(failedClosedCount()).isEqualTo(1.0);
  }

  @Test
  void should_notIncrementCounter_when_requestSimplyNotPublic() {
    PublicEndpointRequestMatcher matcher = matcher();

    matcher.matches(request("GET", ME));
    matcher.matches(request("GET", REFRESH));

    assertThat(failedClosedCount()).isZero();
  }

  @Test
  void should_registerFailedClosedCounterAtZero_when_constructed() {
    matcher();

    assertThat(failedClosedCount()).isZero();
  }

  private double failedClosedCount() {
    return meterRegistry.get("nexus.security.public_match_failed_closed").counter().count();
  }

  private void registerPost(String path, Method method) {
    handlerMapping.registerMapping(
        RequestMappingInfo.paths(path).methods(RequestMethod.POST).build(),
        loginController,
        method);
  }

  private static Method loginMethod(String name, Class<?> firstParameter)
      throws NoSuchMethodException {
    return LoginController.class.getDeclaredMethod(
        name, firstParameter, HttpServletRequest.class);
  }

  private static Method meMethod() throws NoSuchMethodException {
    return UserProfileController.class.getDeclaredMethod("me", Authentication.class);
  }

  private static MockHttpServletRequest request(String method, String uri) {
    return new MockHttpServletRequest(method, uri);
  }

  /**
   * A request whose path parses, but whose {@code getMethod()} throws: the method condition reads
   * it, so evaluation fails after {@code parseAndCache} has cached the parsed path.
   */
  private static MockHttpServletRequest requestWhoseMethodThrows(String uri) {
    return new MockHttpServletRequest("POST", uri) {
      @Override
      public String getMethod() {
        throw new IllegalStateException("fixture: method unavailable");
      }
    };
  }

  private static MockHttpServletRequest preflight(String uri, String requestedMethod) {
    MockHttpServletRequest request = request("OPTIONS", uri);
    request.addHeader(HttpHeaders.ORIGIN, "http://localhost:2000");
    request.addHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, requestedMethod);
    return request;
  }
}
