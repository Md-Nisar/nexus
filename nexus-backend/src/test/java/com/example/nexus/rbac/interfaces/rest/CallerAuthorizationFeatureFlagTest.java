package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.example.nexus.common.security.AuthenticationDetailKeys;
import com.jayway.jsonpath.JsonPath;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * US-019 T-008 (design §15, B4 row): with {@code feature.nexus-us019-user-directory.enabled} false,
 * {@link CallerAuthorizationController} is not registered and {@code GET
 * /api/v1/users/me/authorization} is the generic 404 {@code RESOURCE_NOT_FOUND} for a signed-in
 * caller. The other {@code /api/v1/users} controllers stay on (test profile).
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.MOCK,
    properties = {
      "feature.nexus-us019-user-directory.enabled=false",
      "spring.datasource.url=jdbc:h2:mem:nexus-caller-authorization-flag-test;DB_CLOSE_DELAY=-1",
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
@Tag("WebSliceTest")
class CallerAuthorizationFeatureFlagTest {

  private static final String CALLER = "0b6f3c1a-2d4e-4f5a-8b9c-1d2e3f4a5b6c";
  private static final String TENANT = "7c1e2d3f-4a5b-4c6d-9e8f-0a1b2c3d4e5f";

  @Autowired private WebApplicationContext context;
  @Autowired private ApplicationContext applicationContext;

  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  @Test
  void should_return404ResourceNotFound_when_flagIsOff() throws Exception {
    assertThat(applicationContext.getBeanNamesForType(CallerAuthorizationController.class))
        .isEmpty();

    MockHttpServletResponse response =
        mvc.perform(get("/api/v1/users/me/authorization").with(authentication(signedIn())))
            .andReturn()
            .getResponse();

    assertThat(response.getStatus()).isEqualTo(404);
    assertThat((String) JsonPath.read(response.getContentAsString(), "$.code"))
        .isEqualTo("RESOURCE_NOT_FOUND");
  }

  private static Authentication signedIn() {
    UsernamePasswordAuthenticationToken caller =
        UsernamePasswordAuthenticationToken.authenticated(CALLER, null, List.of());
    caller.setDetails(
        Map.of(
            AuthenticationDetailKeys.TENANT_ID, TENANT,
            AuthenticationDetailKeys.EMAIL_VERIFIED, true,
            AuthenticationDetailKeys.TOKEN_VERSION, 2,
            AuthenticationDetailKeys.PERMISSIONS, List.of()));
    return caller;
  }
}
