package com.example.nexus.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.example.nexus.identity.application.service.LogoutUseCase;
import com.jayway.jsonpath.JsonPath;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
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
 * US-019 B10: every RBAC and directory operation documents its {@code ProblemDetail} errors, and a
 * code that production sources throw but no operation documents fails the build. Reads the live
 * {@code /v3/api-docs} (test profile, every feature flag on, H2, no Docker).
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
class OpenApiErrorCatalogueTest {

  private static final Set<String> CATALOGUED_TAGS =
      Set.of(
          "Role Management",
          "Role Assignment",
          "Access Review",
          "Caller Authorization",
          "User Directory");
  private static final String PROBLEM_REF = "#/components/schemas/ProblemDetail";
  private static final Pattern CODE_LITERAL =
      Pattern.compile(
          "\"(RBAC_0\\d\\d|USER_DIR_\\d{3}|[A-Z][A-Z_]*_NOT_FOUND|PRECONDITION_[A-Z_]+)\"");
  private static final Path MAIN_SOURCES = Path.of("src/main/java/com/example/nexus");
  private static final List<String> HTTP_METHODS = List.of("get", "post", "put", "patch", "delete");

  @Autowired private WebApplicationContext context;

  @MockitoBean LogoutUseCase logoutUseCase;

  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  @Test
  void should_reference_problem_detail_when_a_catalogued_operation_declares_an_error_response()
      throws Exception {
    List<String> offenders = new ArrayList<>();
    int inspected = 0;
    for (Map.Entry<String, Map<String, Object>> operation : catalogued(apiDocs())) {
      Map<String, Object> responses = castMap(operation.getValue().get("responses"));
      for (Map.Entry<String, Object> response : responses.entrySet()) {
        if (response.getKey().startsWith("4") || response.getKey().startsWith("5")) {
          inspected++;
          if (!PROBLEM_REF.equals(problemSchemaRef(response.getValue()))) {
            offenders.add(operation.getKey() + " " + response.getKey());
          }
        }
      }
    }

    assertThat(inspected).as("error responses inspected").isGreaterThan(40);
    assertThat(offenders).as("error responses without the ProblemDetail schema").isEmpty();
  }

  @Test
  void should_register_problem_detail_schema_with_reason_and_required_permission()
      throws Exception {
    Map<String, Object> properties =
        JsonPath.read(apiDocs(), "$.components.schemas.ProblemDetail.properties");

    assertThat(properties.keySet())
        .contains(
            "type",
            "title",
            "status",
            "detail",
            "instance",
            "code",
            "traceId",
            "details",
            "requiredPermission",
            "reason");
  }

  @Test
  void should_document_every_code_literal_when_production_sources_throw_it() throws Exception {
    Set<String> documented = documentedCodes(apiDocs());

    Set<String> undocumented = undocumentedCodes(scannedSourceText(), documented);

    assertThat(undocumented).as("codes thrown but documented on no operation").isEmpty();
  }

  @Test
  void should_report_a_code_when_a_fixture_throws_an_undocumented_one() throws Exception {
    Set<String> documented = documentedCodes(apiDocs());
    String fixture = "throw new SomeException(\"RBAC_099\"); \"USER_DIR_999\"; \"WIDGET_NOT_FOUND\"";

    assertThat(undocumentedCodes(fixture, documented))
        .containsExactlyInAnyOrder("RBAC_099", "USER_DIR_999", "WIDGET_NOT_FOUND");
  }

  @Test
  void should_not_report_a_code_when_a_fixture_throws_only_documented_ones() throws Exception {
    Set<String> documented = documentedCodes(apiDocs());

    assertThat(undocumentedCodes("\"RBAC_011\" \"USER_DIR_001\" \"PRECONDITION_FAILED\"", documented))
        .isEmpty();
  }

  @Test
  void should_describe_etag_semantics_and_read_only_lookup_when_operations_are_documented()
      throws Exception {
    String docs = apiDocs();

    assertThat(
            (String)
                JsonPath.read(
                    docs, "$.paths['/api/v1/roles/{roleId}/permissions'].put.description"))
        .contains("validates the permission set")
        .contains("304");
    assertThat(
            (String) JsonPath.read(docs, "$.paths['/api/v1/users/lookup'].post.description"))
        .contains("safe and read-only")
        .contains("POST keeps personal data out of URLs");
  }

  /**
   * Review R2-2: the lookup mapping no longer declares {@code consumes} (so the permission check can
   * precede the media-type check); the contract still advertises a JSON request body.
   */
  @Test
  void should_advertiseAJsonRequestBody_when_describingTheLookupOperation() throws Exception {
    Map<String, Object> content =
        JsonPath.read(apiDocs(), "$.paths['/api/v1/users/lookup'].post.requestBody.content");

    assertThat(content).containsOnlyKeys("application/json");
  }

  private String apiDocs() throws Exception {
    return mvc.perform(get("/v3/api-docs")).andReturn().getResponse().getContentAsString();
  }

  private static List<Map.Entry<String, Map<String, Object>>> catalogued(String docs) {
    Map<String, Map<String, Object>> paths = JsonPath.read(docs, "$.paths");
    List<Map.Entry<String, Map<String, Object>>> operations = new ArrayList<>();
    paths.forEach(
        (path, item) ->
            HTTP_METHODS.stream()
                .filter(item::containsKey)
                .forEach(
                    method -> {
                      Map<String, Object> operation = castMap(item.get(method));
                      List<String> tags = castList(operation.get("tags"));
                      if (tags.stream().anyMatch(CATALOGUED_TAGS::contains)) {
                        operations.add(Map.entry(method + " " + path, operation));
                      }
                    }));
    return operations;
  }

  private static String problemSchemaRef(Object response) {
    Map<String, Object> content = castMap(castMap(response).get("content"));
    if (content == null || !content.containsKey("application/problem+json")) {
      return null;
    }
    Map<String, Object> schema =
        castMap(castMap(content.get("application/problem+json")).get("schema"));
    return schema == null ? null : (String) schema.get("$ref");
  }

  private static Set<String> documentedCodes(String docs) {
    Set<String> codes = new TreeSet<>();
    for (Map.Entry<String, Map<String, Object>> operation : catalogued(docs)) {
      Object listed = operation.getValue().get("x-nexus-error-codes");
      if (listed != null) {
        codes.addAll(castList(listed));
      }
    }
    return codes;
  }

  private static Set<String> undocumentedCodes(String sourceText, Set<String> documented) {
    Set<String> found = new TreeSet<>();
    Matcher matcher = CODE_LITERAL.matcher(sourceText);
    while (matcher.find()) {
      found.add(matcher.group(1));
    }
    found.removeAll(documented);
    return found;
  }

  private static String scannedSourceText() throws IOException {
    StringBuilder text = new StringBuilder();
    try (Stream<Path> files = Files.walk(MAIN_SOURCES)) {
      for (Path file : files.filter(OpenApiErrorCatalogueTest::isScanned).toList()) {
        text.append(Files.readString(file)).append('\n');
      }
    }
    return text.toString();
  }

  private static boolean isScanned(Path file) {
    String path = file.toString().replace('\\', '/');
    String name = file.getFileName().toString();
    if (!name.endsWith(".java")) {
      return false;
    }
    return path.contains("/nexus/rbac/")
        || (path.contains("/nexus/identity/") && name.contains("Director"))
        || name.startsWith("Precondition");
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> castMap(Object value) {
    return (Map<String, Object>) value;
  }

  @SuppressWarnings("unchecked")
  private static List<String> castList(Object value) {
    return (List<String>) value;
  }
}
