package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.example.nexus.common.security.AuthenticationDetailKeys;
import com.example.nexus.common.security.Permissions;
import com.jayway.jsonpath.JsonPath;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * US-019 T-004 (design §4.2 "Flag off"): with {@code feature.nexus-us019-user-directory.enabled}
 * false, the directory controller is not registered and every directory route is the generic 404
 * {@code RESOURCE_NOT_FOUND}, even for a caller holding {@code user:directory:read}. The other
 * {@code /api/v1/users} controllers stay on (test profile), so the 404 is the directory's alone.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.MOCK,
    properties = {
      "feature.nexus-us019-user-directory.enabled=false",
      "spring.datasource.url=jdbc:h2:mem:nexus-user-directory-flag-test;DB_CLOSE_DELAY=-1",
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
class UserDirectoryFeatureFlagTest {

  private static final String READER = "0b6f3c1a-2d4e-4f5a-8b9c-1d2e3f4a5b6c";
  private static final String TENANT = "7c1e2d3f-4a5b-4c6d-9e8f-0a1b2c3d4e5f";

  @Autowired private WebApplicationContext context;
  @Autowired private ApplicationContext applicationContext;

  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "/api/v1/users",
        "/api/v1/users?status=ACTIVE&page=0&size=20",
        "/api/v1/users?ids=5f0c2d1e-9a7b-4c3d-8e6f-0a1b2c3d4e5f",
        "/api/v1/users/5f0c2d1e-9a7b-4c3d-8e6f-0a1b2c3d4e5f"
      })
  void should_return404ResourceNotFound_when_flagIsOff(String uri) throws Exception {
    assertThat(applicationContext.getBeanNamesForType(UserDirectoryController.class)).isEmpty();

    MockHttpServletResponse response =
        mvc.perform(get(uri).with(authentication(directoryReader())))
            .andReturn()
            .getResponse();

    assertThat(response.getStatus()).as("GET %s", uri).isEqualTo(404);
    assertThat((String) JsonPath.read(response.getContentAsString(), "$.code"))
        .isEqualTo("RESOURCE_NOT_FOUND");
  }

  @Test
  void should_return404ResourceNotFound_when_flagIsOffAndTheLookupIsPosted() throws Exception {
    MockHttpServletResponse response =
        mvc.perform(
                post("/api/v1/users/lookup")
                    .with(authentication(directoryReader()))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"email\":\"reader@example.test\"}"))
            .andReturn()
            .getResponse();

    assertThat(response.getStatus()).isEqualTo(404);
    assertThat((String) JsonPath.read(response.getContentAsString(), "$.code"))
        .isEqualTo("RESOURCE_NOT_FOUND");
  }

  private static Authentication directoryReader() {
    UsernamePasswordAuthenticationToken caller =
        UsernamePasswordAuthenticationToken.authenticated(READER, null, List.of());
    caller.setDetails(
        Map.of(
            AuthenticationDetailKeys.TENANT_ID, TENANT,
            AuthenticationDetailKeys.EMAIL_VERIFIED, true,
            AuthenticationDetailKeys.TOKEN_VERSION, 2,
            AuthenticationDetailKeys.PERMISSIONS, List.of(Permissions.USER_DIRECTORY_READ)));
    return caller;
  }
}
