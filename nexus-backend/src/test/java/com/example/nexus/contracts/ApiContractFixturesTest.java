package com.example.nexus.contracts;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.security.CallerFacingDenialReason;
import com.example.nexus.common.security.Permissions;
import com.example.nexus.identity.interfaces.rest.dto.DirectoryPageLinks;
import com.example.nexus.identity.interfaces.rest.dto.DirectoryPageMetadata;
import com.example.nexus.identity.interfaces.rest.dto.UserDirectoryEntryResponse;
import com.example.nexus.identity.interfaces.rest.dto.UserDirectoryPageResponse;
import com.example.nexus.identity.interfaces.rest.dto.UserLookupRequest;
import com.example.nexus.identity.interfaces.rest.dto.UserLookupResponse;
import com.example.nexus.rbac.interfaces.rest.dto.CallerAuthorizationResponse;
import com.example.nexus.rbac.interfaces.rest.dto.PageLinks;
import com.example.nexus.rbac.interfaces.rest.dto.PageMetadata;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionResponse;
import com.example.nexus.rbac.interfaces.rest.dto.ReplaceRolePermissionsRequest;
import com.example.nexus.rbac.interfaces.rest.dto.RoleListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.RoleResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.json.JsonTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * US-019 T-028 (design §11.2, RC-67(b)): serialises canonical instances of the real response
 * records and problem bodies with the application's {@link ObjectMapper} and compares them with
 * the files under {@code contracts/api}, which the frontend's {@code api-contract.spec.ts} also
 * reads. A difference fails the build; {@code -Dcontracts.update=true} rewrites the files for
 * review. Fixtures hold only {@code example.test} addresses and fixed ids.
 */
@Tag("UnitTest")
@JsonTest
class ApiContractFixturesTest {

  private static final Path CONTRACTS = Path.of("..", "contracts", "api");
  private static final boolean UPDATE = Boolean.getBoolean("contracts.update");
  private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");
  private static final String ROLE_ID = "0190a000-0000-7000-8000-00000000000a";
  private static final String USER_ID = "0190a000-0000-7000-8000-000000000001";
  private static final String TRACE_ID = "0190a000-0000-7000-8000-0000000000ff";

  @Autowired private ObjectMapper mapper;

  @Test
  void should_matchEveryCommittedFixture_when_theRecordsAreSerialised() throws IOException {
    Map<String, Object> fixtures = fixtures();

    for (Map.Entry<String, Object> fixture : fixtures.entrySet()) {
      Path file = CONTRACTS.resolve(fixture.getKey() + ".json");
      JsonNode actual = mapper.readTree(mapper.writeValueAsString(fixture.getValue()));
      if (UPDATE) {
        Files.createDirectories(CONTRACTS);
        Files.writeString(file, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(actual) + "\n");
      }
      assertThat(file).as("fixture %s (run with -Dcontracts.update=true)", file).exists();
      assertThat(mapper.readTree(Files.readString(file)))
          .as("fixture %s differs from the serialised record", fixture.getKey())
          .isEqualTo(actual);
    }
  }

  @Test
  void should_haveNoFixtureWithoutARecord_when_theDirectoryIsListed() throws IOException {
    try (var files = Files.list(CONTRACTS)) {
      List<String> committed =
          files.map(p -> p.getFileName().toString().replace(".json", "")).sorted().toList();
      assertThat(committed).containsExactlyElementsOf(fixtures().keySet());
    }
  }

  @Test
  void should_keepNoPersonalDataInFixtures_when_theyAreSerialised() throws IOException {
    for (Object fixture : fixtures().values()) {
      assertThat(mapper.writeValueAsString(fixture)).doesNotContain("@example.com");
    }
  }

  private Map<String, Object> fixtures() {
    Map<String, Object> fixtures = new TreeMap<>();
    PermissionResponse sensitive = permission("0190a000-0000-7000-8000-000000000108", Permissions.USER_DIRECTORY_READ, "Read the tenant user directory, including email addresses");
    fixtures.put("permission-response", sensitive);
    fixtures.put("permission-catalogue", new PermissionListResponse(catalogue()));
    RoleResponse role = new RoleResponse(ROLE_ID, "Support", "Read-only support staff", false, CREATED_AT, 3L, 2);
    fixtures.put("role-response", role);
    fixtures.put("role-list-response", new RoleListResponse(List.of(role), new PageMetadata(20, 0, 1L, 1), new PageLinks(null, null)));
    fixtures.put("caller-authorization-response", new CallerAuthorizationResponse(USER_ID, List.of(new CallerAuthorizationResponse.RoleEntry(ROLE_ID, "Support")), List.of(Permissions.AUDIT_READ, Permissions.ROLE_READ), false));
    fixtures.put("replace-role-permissions-request", new ReplaceRolePermissionsRequest(List.of("0190a000-0000-7000-8000-000000000104")));
    UserDirectoryEntryResponse entry = new UserDirectoryEntryResponse("0190a000-0000-7000-8000-000000000108", "ada@example.test", "ACTIVE", true, CREATED_AT);
    fixtures.put("user-directory-entry", entry);
    fixtures.put("user-directory-page", new UserDirectoryPageResponse(List.of(entry), new DirectoryPageMetadata(20, 0, 1L, 1), new DirectoryPageLinks(null, null)));
    fixtures.put("user-lookup-request", new UserLookupRequest("ada@example.test"));
    fixtures.put("user-lookup-response", new UserLookupResponse(List.of(entry)));
    ProblemDetail denied = problem(HttpStatus.FORBIDDEN, "RBAC_001", "Access denied");
    denied.setProperty("requiredPermission", Permissions.ROLE_WRITE);
    denied.setProperty("reason", CallerFacingDenialReason.GRANT_EXCEEDS_CALLER.name());
    fixtures.put("problem-rbac-001", denied);
    fixtures.put("problem-rbac-012", problem(HttpStatus.CONFLICT, "RBAC_012", "The role's classification changed while the request waited; retry"));
    return fixtures;
  }

  private static List<PermissionResponse> catalogue() {
    return List.of(
        permission("0190a000-0000-7000-8000-000000000100", Permissions.TENANT_READ, "Read tenant configuration and metadata"),
        permission("0190a000-0000-7000-8000-000000000101", Permissions.TENANT_WRITE, "Create and modify tenant configuration"),
        permission("0190a000-0000-7000-8000-000000000102", Permissions.USER_READ, "Read user accounts and profiles"),
        permission("0190a000-0000-7000-8000-000000000103", Permissions.USER_WRITE, "Create and modify user accounts"),
        permission("0190a000-0000-7000-8000-000000000104", Permissions.ROLE_READ, "Read roles and their permission assignments"),
        permission("0190a000-0000-7000-8000-000000000105", Permissions.ROLE_WRITE, "Create roles and manage role-permission assignments"),
        permission("0190a000-0000-7000-8000-000000000106", Permissions.AUDIT_READ, "Read the authentication and audit event trail"),
        permission("0190a000-0000-7000-8000-000000000107", Permissions.USER_ROLE_ASSIGN, "Assign and revoke roles for users in the tenant"),
        permission("0190a000-0000-7000-8000-000000000108", Permissions.USER_DIRECTORY_READ, "Read the tenant user directory, including email addresses"));
  }

  private static PermissionResponse permission(String id, String name, String description) {
    return new PermissionResponse(id, name, description, Permissions.SENSITIVE.contains(name));
  }

  private static ProblemDetail problem(HttpStatus status, String code, String detail) {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
    problem.setProperty("code", code);
    problem.setProperty("traceId", TRACE_ID);
    return problem;
  }
}
