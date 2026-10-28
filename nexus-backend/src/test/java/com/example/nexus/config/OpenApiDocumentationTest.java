package com.example.nexus.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.example.nexus.identity.application.service.LogoutUseCase;
import com.jayway.jsonpath.JsonPath;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Validates OpenAPI documentation for throttled and mutation endpoints.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.MOCK,
    properties = {
      "spring.datasource.url=jdbc:h2:mem:nexus-openapi-catalogue-test;DB_CLOSE_DELAY=-1",
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
class OpenApiDocumentationTest {

  @Autowired private WebApplicationContext context;
  @MockitoBean LogoutUseCase logoutUseCase;
  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  @Test
  void should_document_429_on_throttled_endpoints() throws Exception {
    String docs = mvc.perform(get("/v3/api-docs")).andReturn().getResponse().getContentAsString();
    Map<String, Object> createRoleResponses =
        JsonPath.read(docs, "$.paths['/api/v1/roles'].post.responses");
    assertThat(createRoleResponses).containsKey("429");
  }
}
