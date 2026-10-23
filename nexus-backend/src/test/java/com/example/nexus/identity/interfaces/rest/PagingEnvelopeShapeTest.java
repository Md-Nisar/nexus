package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.identity.domain.DirectoryPage;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.interfaces.rest.dto.DirectoryPageLinks;
import com.example.nexus.identity.interfaces.rest.dto.DirectoryPageMetadata;
import com.example.nexus.identity.interfaces.rest.dto.UserDirectoryEntryResponse;
import com.example.nexus.identity.interfaces.rest.dto.UserDirectoryPageResponse;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.interfaces.rest.dto.PageLinks;
import com.example.nexus.rbac.interfaces.rest.dto.PageMetadata;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionPageResponse;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionResponse;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * US-019 T-004 (design §4.6): the directory keeps identity-local copies of the paging types, so this
 * guard serializes an RBAC page and a directory page and pins the same envelope key structure,
 * plus the directory's own link rules (status echoed, batch links null).
 */
@Tag("UnitTest")
class PagingEnvelopeShapeTest {

  private static final ObjectMapper JSON = JsonMapper.builder().build();

  @Test
  void should_serializeTheSameEnvelopeKeys_when_comparedWithTheRbacPage() {
    PageResult<String> rbacResult = new PageResult<>(List.of("x"), 45, 1, 20);
    PermissionPageResponse rbac =
        new PermissionPageResponse(
            List.of(new PermissionResponse("id", "user:read", "d", false)),
            PageMetadata.of(rbacResult),
            PageLinks.of("/api/v1/permissions", rbacResult));
    DirectoryPage<String> directoryResult = new DirectoryPage<>(List.of("x"), 45, 1, 20);
    UserDirectoryPageResponse directory =
        new UserDirectoryPageResponse(
            List.of(entry()),
            DirectoryPageMetadata.of(directoryResult),
            DirectoryPageLinks.of("/api/v1/users", null, directoryResult));

    JsonNode rbacJson = JSON.valueToTree(rbac);
    JsonNode directoryJson = JSON.valueToTree(directory);

    assertThat(keys(directoryJson)).isEqualTo(keys(rbacJson));
    assertThat(keys(directoryJson.get("page"))).isEqualTo(keys(rbacJson.get("page")));
    assertThat(keys(directoryJson.get("links"))).isEqualTo(keys(rbacJson.get("links")));
    assertThat(directoryJson.get("data").isArray()).isTrue();
    assertThat(directoryJson.get("page")).isEqualTo(rbacJson.get("page"));
    assertThat(directory.links())
        .isEqualTo(
            new DirectoryPageLinks(
                rbac.links().next().replace("/api/v1/permissions", "/api/v1/users"),
                rbac.links().prev().replace("/api/v1/permissions", "/api/v1/users")));
  }

  @Test
  void should_echoStatusInBothLinks_when_theListIsFiltered() {
    DirectoryPage<String> result = new DirectoryPage<>(List.of("x"), 45, 1, 20);

    DirectoryPageLinks links = DirectoryPageLinks.of("/api/v1/users", UserStatus.ACTIVE, result);

    assertThat(links.next()).isEqualTo("/api/v1/users?status=ACTIVE&page=2&size=20");
    assertThat(links.prev()).isEqualTo("/api/v1/users?status=ACTIVE&page=0&size=20");
  }

  @Test
  void should_linkBackToTheLastPage_when_thePageIsPastTheEnd() {
    DirectoryPage<String> result = new DirectoryPage<>(List.of(), 45, 9, 20);

    DirectoryPageLinks links = DirectoryPageLinks.of("/api/v1/users", null, result);

    assertThat(links.next()).isNull();
    assertThat(links.prev()).isEqualTo("/api/v1/users?page=2&size=20");
  }

  @Test
  void should_haveNullLinksAndASinglePage_when_theEnvelopeIsABatch() {
    JsonNode json =
        JSON.valueToTree(
            new UserDirectoryPageResponse(
                List.of(entry(), entry()),
                DirectoryPageMetadata.ofBatch(2),
                DirectoryPageLinks.NONE));

    assertThat(json.get("page").toString())
        .isEqualTo("{\"size\":2,\"number\":0,\"totalElements\":2,\"totalPages\":1}");
    assertThat(json.get("links").toString()).isEqualTo("{\"next\":null,\"prev\":null}");
  }

  @Test
  void should_haveZeroPages_when_theBatchIsEmpty() {
    assertThat(DirectoryPageMetadata.ofBatch(0))
        .isEqualTo(new DirectoryPageMetadata(0, 0, 0, 0));
  }

  @Test
  void should_serializeExactlyTheFiveEntryFields_when_anEntryIsWritten() {
    JsonNode json = JSON.valueToTree(entry());

    assertThat(keys(json))
        .containsExactlyInAnyOrder("userId", "email", "status", "emailVerified", "createdAt");
    assertThat(json.get("createdAt").asString()).isEqualTo("2026-01-01T00:00:00Z");
  }

  private static UserDirectoryEntryResponse entry() {
    return new UserDirectoryEntryResponse(
        "019f6839-0000-7000-8000-0000000000b1",
        "reader@example.test",
        "ACTIVE",
        true,
        Instant.parse("2026-01-01T00:00:00Z"));
  }

  private static Set<String> keys(JsonNode node) {
    return new TreeSet<>(node.propertyNames());
  }
}
