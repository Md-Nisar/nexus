package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.common.domain.PreconditionFailedException;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.common.web.GlobalExceptionHandler;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RoleCounts;
import com.example.nexus.rbac.domain.RolePermissionSet;
import com.example.nexus.rbac.domain.RoleView;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * MockMvc slice over {@link RoleController} with a mocked {@link RoleManagementService},
 * mirroring {@code UserRoleControllerTest}'s standalone pattern. {@code @RequiresPermission}
 * enforcement is intentionally NOT exercised via a runtime 403 here — a standalone MockMvc setup
 * has no Spring AOP proxy, so each endpoint's negative control below is a structural assertion
 * that {@code @RequiresPermission} is present with the expected value; the runtime denial path is
 * covered end-to-end by T-010's cross-layer ITs (matching {@code UserRoleControllerTest} and
 * {@code RoleAssignmentSecurityIT}'s existing split).
 */
@Tag("UnitTest")
class RoleControllerTest {

  private static final UUID PRINCIPAL_USER_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000002");
  private static final UUID ROLE_ID = UUID.fromString("00000000-0000-7000-8000-000000000003");
  private static final UUID PERMISSION_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000004");
  private static final Instant CREATED_AT = Instant.parse("2026-07-28T09:12:00.123456Z");

  private static final String ETAG_VALUE = "rp1-F06EYk4CPm7zxsme_6h7xQ1ikSY55XJ7I2ZMbjEshXY";

  private RoleManagementService roleManagementService;
  private SimpleMeterRegistry meterRegistry;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    roleManagementService = mock(RoleManagementService.class);
    meterRegistry = new SimpleMeterRegistry();
    RoleController controller = new RoleController(roleManagementService, meterRegistry);
    mockMvc =
        MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(new GlobalExceptionHandler(meterRegistry))
            .build();
  }

  // ── createRole ───────────────────────────────────────────────────────

  @Test
  void should_support_idempotent_role_creation() throws Exception {
    Authentication auth = authentication();
    when(roleManagementService.createRole(any(), eq("Billing Manager"), any(), any()))
        .thenReturn(roleView(ROLE_ID, "Billing Manager", "Manages invoices", false));

    // First request with Idempotency-Key
    mockMvc
        .perform(
            post("/api/v1/roles")
                .header("Idempotency-Key", "idemp-key-12345")
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Billing Manager\",\"description\":\"Manages invoices\"}"))
        .andExpect(status().isCreated())
        .andExpect(header().string("Location", "/api/v1/roles/" + ROLE_ID))
        .andExpect(jsonPath("$.id").value(ROLE_ID.toString()));

    // Second request with same Idempotency-Key
    mockMvc
        .perform(
            post("/api/v1/roles")
                .header("Idempotency-Key", "idemp-key-12345")
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Billing Manager\",\"description\":\"Manages invoices\"}"))
        .andExpect(status().isCreated())
        .andExpect(header().string("Location", "/api/v1/roles/" + ROLE_ID))
        .andExpect(jsonPath("$.id").value(ROLE_ID.toString()));

    // Verify service was only called once
    verify(roleManagementService, org.mockito.Mockito.times(1))
        .createRole(any(), eq("Billing Manager"), any(), any());
  }

  @Test
  void should_return201WithLocationAndBody_when_createRoleSucceeds() throws Exception {
    Authentication auth = authentication();
    when(roleManagementService.createRole(any(), eq("Billing Manager"), any(), any()))
        .thenReturn(roleView(ROLE_ID, "Billing Manager", "Manages invoices", false));

    mockMvc
        .perform(
            post("/api/v1/roles")
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Billing Manager\",\"description\":\"Manages invoices\"}"))
        .andExpect(status().isCreated())
        .andExpect(header().string("Location", "/api/v1/roles/" + ROLE_ID))
        .andExpect(jsonPath("$.id").value(ROLE_ID.toString()))
        .andExpect(jsonPath("$.name").value("Billing Manager"))
        .andExpect(jsonPath("$.description").value("Manages invoices"));
  }

  /**
   * Boolean JSON naming trap, pinned (03-design.md §8.4/D5): the serialised key must be the
   * literal string {@code isSystemRole}, never {@code systemRole}. Asserted against the raw
   * response body, not just the deserialized {@code jsonPath} value, so a rename would fail this
   * test even if some lenient deserializer would otherwise tolerate it.
   */
  @Test
  void should_serializeIsSystemRoleAsLiteralJsonKey_when_roleResponseSerialized() throws Exception {
    Authentication auth = authentication();
    when(roleManagementService.createRole(any(), any(), any(), any()))
        .thenReturn(roleView(ROLE_ID, "Billing Manager", null, false));

    String body =
        mockMvc
            .perform(
                post("/api/v1/roles")
                    .principal(auth)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"name\":\"Billing Manager\"}"))
            .andExpect(status().isCreated())
            .andReturn()
            .getResponse()
            .getContentAsString();

    assertThat(body).contains("\"isSystemRole\"");
    assertThat(body).doesNotContain("\"systemRole\"");
  }

  @Test
  void should_return400_when_nameIsBlank() throws Exception {
    Authentication auth = authentication();

    mockMvc
        .perform(
            post("/api/v1/roles")
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"\"}"))
        .andExpect(status().isBadRequest());
  }

  @Test
  void should_havePermissionAnnotationPresent_when_createRoleInspected() throws Exception {
    assertRequiresPermission("createRole", ROLE_WRITE());
  }

  /**
   * Closes threat-model.md T-T9's mandated gap: {@code description} must never reach a log line,
   * anywhere in the request path. Uses the codebase's existing {@code ListAppender} pattern
   * ({@code RoleAssignmentServiceTest}), attached to the root logger so it captures every logger
   * in the JVM during the request, not just one class's.
   */
  @Test
  void should_neverLogDescription_when_creatingRoleWithMarkerDescription() throws Exception {
    Authentication auth = authentication();
    String marker = "SECRET-DESCRIPTION-MARKER-" + UUID.randomUUID();
    when(roleManagementService.createRole(any(), any(), any(), any()))
        .thenReturn(roleView(ROLE_ID, "Billing Manager", marker, false));

    ListAppender<ILoggingEvent> appender = startRootLogCapture();
    try {
      mockMvc
          .perform(
              post("/api/v1/roles")
                  .principal(auth)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{\"name\":\"Billing Manager\",\"description\":\"" + marker + "\"}"))
          .andExpect(status().isCreated());
    } finally {
      stopRootLogCapture(appender);
    }

    boolean leaked =
        appender.list.stream()
            .anyMatch(
                event ->
                    event.getFormattedMessage().contains(marker)
                        || keyValueContains(event, marker));
    assertThat(leaked)
        .as("description must never be written to a log line (threat-model.md T-T9/RC-3)")
        .isFalse();
  }

  // ── listRoles ────────────────────────────────────────────────────────

  @Test
  void should_return200WithDataPageAndLinks_when_listingRolesWithDefaults() throws Exception {
    Authentication auth = authentication();
    when(roleManagementService.listRoles(any(), eq(0), eq(20)))
        .thenReturn(
            new PageResult<>(List.of(roleView(ROLE_ID, "Billing Manager", "d", false)), 1, 0, 20));

    mockMvc
        .perform(get("/api/v1/roles").principal(auth))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data").isArray())
        .andExpect(jsonPath("$.data[0].id").value(ROLE_ID.toString()))
        .andExpect(jsonPath("$.page.size").value(20))
        .andExpect(jsonPath("$.page.number").value(0))
        .andExpect(jsonPath("$.page.totalElements").value(1))
        .andExpect(jsonPath("$.page.totalPages").value(1))
        .andExpect(jsonPath("$.links.next").value((Object) null))
        .andExpect(jsonPath("$.links.prev").value((Object) null));
  }

  @Test
  void should_acceptTheMaximumPageSize_when_sizeIs100() throws Exception {
    when(roleManagementService.listRoles(any(), eq(0), eq(100)))
        .thenReturn(new PageResult<>(List.of(), 0, 0, 100));

    mockMvc
        .perform(get("/api/v1/roles").param("size", "100").principal(authentication()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.page.size").value(100));
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.CsvSource({
    "page,-1",
    "page,abc",
    "page,2147483648",
    "size,0",
    "size,101",
    "size,-5",
    "size,ten"
  })
  void should_return400ValidationFailedAndNotClamp_when_pageOrSizeIsOutOfRange(
      String name, String value) throws Exception {
    mockMvc
        .perform(get("/api/v1/roles").param(name, value).principal(authentication()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
        .andExpect(jsonPath("$.details[0].field").value(name));

    org.mockito.Mockito.verifyNoInteractions(roleManagementService);
  }

  @Test
  void should_linkOnlyToTheNextPage_when_onTheFirstPageOfSeveral() throws Exception {
    when(roleManagementService.listRoles(any(), eq(0), eq(2)))
        .thenReturn(new PageResult<>(List.of(), 5, 0, 2));

    mockMvc
        .perform(get("/api/v1/roles").param("size", "2").principal(authentication()))
        .andExpect(jsonPath("$.page.totalPages").value(3))
        .andExpect(jsonPath("$.links.next").value("/api/v1/roles?page=1&size=2"))
        .andExpect(jsonPath("$.links.prev").value((Object) null));
  }

  @Test
  void should_linkBothWays_when_onAMiddlePage() throws Exception {
    when(roleManagementService.listRoles(any(), eq(1), eq(2)))
        .thenReturn(new PageResult<>(List.of(), 5, 1, 2));

    mockMvc
        .perform(
            get("/api/v1/roles").param("page", "1").param("size", "2").principal(authentication()))
        .andExpect(jsonPath("$.links.next").value("/api/v1/roles?page=2&size=2"))
        .andExpect(jsonPath("$.links.prev").value("/api/v1/roles?page=0&size=2"));
  }

  @Test
  void should_linkOnlyToThePreviousPage_when_onTheLastPage() throws Exception {
    when(roleManagementService.listRoles(any(), eq(2), eq(2)))
        .thenReturn(new PageResult<>(List.of(), 5, 2, 2));

    mockMvc
        .perform(
            get("/api/v1/roles").param("page", "2").param("size", "2").principal(authentication()))
        .andExpect(jsonPath("$.links.next").value((Object) null))
        .andExpect(jsonPath("$.links.prev").value("/api/v1/roles?page=1&size=2"));
  }

  @Test
  void should_havePermissionAnnotationPresent_when_listRolesInspected() throws Exception {
    assertRequiresPermission("listRoles", ROLE_READ());
  }

  // ── getRole ──────────────────────────────────────────────────────────

  @Test
  void should_return200WithRoleShape_when_gettingOneRole() throws Exception {
    Authentication auth = authentication();
    when(roleManagementService.getRole(any(), eq(ROLE_ID)))
        .thenReturn(roleView(ROLE_ID, "Billing Manager", "Manages invoices", false));

    String body =
        mockMvc
            .perform(get("/api/v1/roles/{roleId}", ROLE_ID).principal(auth))
            .andExpect(status().isOk())
            .andExpect(header().doesNotExist("ETag"))
            .andExpect(jsonPath("$.id").value(ROLE_ID.toString()))
            .andExpect(jsonPath("$.name").value("Billing Manager"))
            .andExpect(jsonPath("$.description").value("Manages invoices"))
            .andExpect(jsonPath("$.isSystemRole").value(false))
            .andReturn()
            .getResponse()
            .getContentAsString();

    assertThat(body).contains("\"createdAt\"");
  }

  @Test
  void should_return400_when_getRolePathRoleIdIsMalformed() throws Exception {
    Authentication auth = authentication();

    mockMvc
        .perform(get("/api/v1/roles/{roleId}", "not-a-uuid").principal(auth))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("roleId"));
  }

  @Test
  void should_return404RoleNotFound_when_serviceReportsNoSuchRole() throws Exception {
    Authentication auth = authentication();
    when(roleManagementService.getRole(any(), eq(ROLE_ID)))
        .thenThrow(new com.example.nexus.common.domain.ResourceNotFoundException("ROLE_NOT_FOUND", "No such role"));

    mockMvc
        .perform(get("/api/v1/roles/{roleId}", ROLE_ID).principal(auth))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("ROLE_NOT_FOUND"));
  }

  @Test
  void should_havePermissionAnnotationPresent_when_getRoleInspected() throws Exception {
    assertRequiresPermission("getRole", ROLE_READ());
  }

  // ── listRolePermissions ──────────────────────────────────────────────

  @Test
  void should_return200WithDataEnvelope_when_listingRolePermissions() throws Exception {
    Authentication auth = authentication();
    when(roleManagementService.listRolePermissions(any(), eq(ROLE_ID)))
        .thenReturn(
            new RolePermissionSet(
                ROLE_ID,
                List.of(new PermissionView(PERMISSION_ID, "user:read", "Read users")),
                ETAG_VALUE));

    mockMvc
        .perform(get("/api/v1/roles/{roleId}/permissions", ROLE_ID).principal(auth))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data").isArray())
        .andExpect(jsonPath("$.data[0].id").value(PERMISSION_ID.toString()));
  }

  /** US-019 B8: the GET serves the set's version as a strong, quoted ETag. */
  @Test
  void should_serveTheSetVersionAsAStrongETag_when_listingRolePermissions() throws Exception {
    when(roleManagementService.listRolePermissions(any(), eq(ROLE_ID)))
        .thenReturn(new RolePermissionSet(ROLE_ID, List.of(), ETAG_VALUE));

    mockMvc
        .perform(get("/api/v1/roles/{roleId}/permissions", ROLE_ID).principal(authentication()))
        .andExpect(status().isOk())
        .andExpect(header().string("ETag", "\"" + ETAG_VALUE + "\""));
  }

  // ── replaceRolePermissions (US-019 B8) ───────────────────────────────

  private static final UUID OTHER_PERMISSION_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000005");

  private org.springframework.test.web.servlet.ResultActions putReplace(String body, String ifMatch)
      throws Exception {
    var request =
        put("/api/v1/roles/{roleId}/permissions", ROLE_ID)
            .principal(authentication())
            .contentType(MediaType.APPLICATION_JSON)
            .content(body);
    if (ifMatch != null) {
      request = request.header("If-Match", ifMatch);
    }
    return mockMvc.perform(request);
  }

  @Test
  void should_return200WithTheNewSetAndETag_when_replaceSucceeds() throws Exception {
    when(roleManagementService.replaceRolePermissions(
            any(), eq(ROLE_ID), eq(Set.of(PERMISSION_ID)), eq("rp1-old"), any()))
        .thenReturn(
            new RolePermissionSet(
                ROLE_ID,
                List.of(new PermissionView(PERMISSION_ID, "user:read", "Read users")),
                ETAG_VALUE));

    putReplace("{\"permissionIds\":[\"" + PERMISSION_ID + "\"]}", "\"rp1-old\"")
        .andExpect(status().isOk())
        .andExpect(header().string("ETag", "\"" + ETAG_VALUE + "\""))
        .andExpect(jsonPath("$.data[0].id").value(PERMISSION_ID.toString()))
        .andExpect(jsonPath("$.data[0].isSensitive").value(false));
  }

  @Test
  void should_passAnEmptySet_when_theBodyListIsEmpty() throws Exception {
    when(roleManagementService.replaceRolePermissions(
            any(), eq(ROLE_ID), eq(Set.of()), eq("rp1-old"), any()))
        .thenReturn(new RolePermissionSet(ROLE_ID, List.of(), ETAG_VALUE));

    putReplace("{\"permissionIds\":[]}", "\"rp1-old\"")
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data").isEmpty());
  }

  @Test
  void should_return428WithoutCallingTheService_when_ifMatchIsAbsent() throws Exception {
    putReplace("{\"permissionIds\":[]}", null)
        .andExpect(status().isPreconditionRequired())
        .andExpect(jsonPath("$.code").value("PRECONDITION_REQUIRED"));

    verifyNoInteractions(roleManagementService);
    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_replace")
                .tag("outcome", "precondition_required")
                .tag("lockPath", "none")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void should_return428_when_ifMatchListsTwoTags() throws Exception {
    putReplace("{\"permissionIds\":[]}", "\"rp1-a\", \"rp1-b\"")
        .andExpect(status().isPreconditionRequired());

    verifyNoInteractions(roleManagementService);
  }

  @Test
  void should_return428_when_ifMatchIsAStar() throws Exception {
    putReplace("{\"permissionIds\":[]}", "*").andExpect(status().isPreconditionRequired());
  }

  @Test
  void should_return428_when_ifMatchIsWeak() throws Exception {
    putReplace("{\"permissionIds\":[]}", "W/\"rp1-a\"")
        .andExpect(status().isPreconditionRequired());
  }

  /** RC-58.1: 400 is decided before 428, so a malformed body without If-Match is a 400. */
  @Test
  void should_return400Not428_when_theBodyIsInvalidAndIfMatchIsAbsent() throws Exception {
    putReplace("{\"permissionIds\":[\"nope\"]}", null)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("permissionIds[0]"));

    verifyNoInteractions(roleManagementService);
  }

  @Test
  void should_return400_when_permissionIdsIsMissing() throws Exception {
    putReplace("{}", "\"rp1-a\"")
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("permissionIds"));
  }

  @Test
  void should_return400_when_moreThanOneHundredIdsAreSent() throws Exception {
    StringBuilder ids = new StringBuilder();
    for (int i = 0; i < 101; i++) {
      ids.append(i == 0 ? "" : ",")
          .append('"')
          .append(String.format("00000000-0000-7000-8000-%012d", i))
          .append('"');
    }

    putReplace("{\"permissionIds\":[" + ids + "]}", "\"rp1-a\"")
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("permissionIds"));
    verifyNoInteractions(roleManagementService);
  }

  @Test
  void should_acceptExactlyOneHundredIds_when_atTheBound() throws Exception {
    StringBuilder ids = new StringBuilder();
    for (int i = 0; i < 100; i++) {
      ids.append(i == 0 ? "" : ",")
          .append('"')
          .append(String.format("00000000-0000-7000-8000-%012d", i))
          .append('"');
    }
    when(roleManagementService.replaceRolePermissions(any(), eq(ROLE_ID), any(), any(), any()))
        .thenReturn(new RolePermissionSet(ROLE_ID, List.of(), ETAG_VALUE));

    putReplace("{\"permissionIds\":[" + ids + "]}", "\"rp1-a\"").andExpect(status().isOk());
  }

  @Test
  void should_return400_when_anIdRepeatsInAnotherCase() throws Exception {
    String lower = OTHER_PERMISSION_ID.toString();
    String upper = lower.toUpperCase(java.util.Locale.ROOT);

    putReplace("{\"permissionIds\":[\"" + lower + "\",\"" + upper + "\"]}", "\"rp1-a\"")
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("permissionIds[1]"));
    verifyNoInteractions(roleManagementService);
  }

  @Test
  void should_return400_when_anElementIsNull() throws Exception {
    putReplace("{\"permissionIds\":[null]}", "\"rp1-a\"")
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("permissionIds[0]"));
  }

  @Test
  void should_return400_when_theReplacePathRoleIdIsMalformed() throws Exception {
    mockMvc
        .perform(
            put("/api/v1/roles/{roleId}/permissions", "not-a-uuid")
                .principal(authentication())
                .contentType(MediaType.APPLICATION_JSON)
                .header("If-Match", "\"rp1-a\"")
                .content("{\"permissionIds\":[]}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("roleId"));
  }

  @Test
  void should_return415_when_theReplaceBodyIsNotJson() throws Exception {
    mockMvc
        .perform(
            put("/api/v1/roles/{roleId}/permissions", ROLE_ID)
                .principal(authentication())
                .contentType(MediaType.TEXT_PLAIN)
                .header("If-Match", "\"rp1-a\"")
                .content("permissionIds"))
        .andExpect(status().isUnsupportedMediaType());
  }

  /** RC-58.2: the 412 body is the standard problem fields only, and no ETag header is sent. */
  @Test
  void should_return412WithoutETagOrState_when_theServiceReportsAStaleTag() throws Exception {
    when(roleManagementService.replaceRolePermissions(any(), eq(ROLE_ID), any(), any(), any()))
        .thenThrow(new PreconditionFailedException());

    putReplace("{\"permissionIds\":[\"" + PERMISSION_ID + "\"]}", "\"rp1-old\"")
        .andExpect(status().isPreconditionFailed())
        .andExpect(header().doesNotExist("ETag"))
        .andExpect(jsonPath("$.code").value("PRECONDITION_FAILED"))
        .andExpect(jsonPath("$.data").doesNotExist())
        .andExpect(jsonPath("$.permissionIds").doesNotExist());
  }

  @Test
  void should_havePermissionAnnotationPresent_when_replaceRolePermissionsInspected()
      throws Exception {
    assertRequiresPermission("replaceRolePermissions", ROLE_WRITE());
  }

  @Test
  void should_return400_when_listRolePermissionsPathRoleIdIsMalformed() throws Exception {
    Authentication auth = authentication();

    mockMvc
        .perform(get("/api/v1/roles/{roleId}/permissions", "not-a-uuid").principal(auth))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("roleId"));
  }

  @Test
  void should_havePermissionAnnotationPresent_when_listRolePermissionsInspected() throws Exception {
    assertRequiresPermission("listRolePermissions", ROLE_READ());
  }

  // ── attachPermission ─────────────────────────────────────────────────

  @Test
  void should_return201WithLocationAndBody_when_attachPermissionSucceeds() throws Exception {
    Authentication auth = authentication();
    when(roleManagementService.attachPermission(any(), eq(ROLE_ID), eq(PERMISSION_ID), any()))
        .thenReturn(new PermissionView(PERMISSION_ID, "user:read", "Read users"));

    mockMvc
        .perform(
            post("/api/v1/roles/{roleId}/permissions", ROLE_ID)
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"permissionId\":\"" + PERMISSION_ID + "\"}"))
        .andExpect(status().isCreated())
        .andExpect(
            header()
                .string(
                    "Location", "/api/v1/roles/" + ROLE_ID + "/permissions/" + PERMISSION_ID))
        .andExpect(jsonPath("$.id").value(PERMISSION_ID.toString()))
        .andExpect(jsonPath("$.name").value("user:read"));
  }

  @Test
  void should_return400_when_attachPermissionBodyIdIsMalformed() throws Exception {
    Authentication auth = authentication();

    mockMvc
        .perform(
            post("/api/v1/roles/{roleId}/permissions", ROLE_ID)
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"permissionId\":\"not-a-uuid\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("permissionId"));
  }

  @Test
  void should_return400_when_attachPermissionPathRoleIdIsMalformed() throws Exception {
    Authentication auth = authentication();

    mockMvc
        .perform(
            post("/api/v1/roles/{roleId}/permissions", "not-a-uuid")
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"permissionId\":\"" + PERMISSION_ID + "\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("roleId"));
  }

  @Test
  void should_havePermissionAnnotationPresent_when_attachPermissionInspected() throws Exception {
    assertRequiresPermission("attachPermission", ROLE_WRITE());
  }

  // ── detachPermission ─────────────────────────────────────────────────

  @Test
  void should_return204NoContent_when_detachPermissionSucceeds() throws Exception {
    Authentication auth = authentication();

    mockMvc
        .perform(
            delete("/api/v1/roles/{roleId}/permissions/{permissionId}", ROLE_ID, PERMISSION_ID)
                .principal(auth))
        .andExpect(status().isNoContent())
        .andExpect(jsonPath("$").doesNotExist());
  }

  @Test
  void should_return400_when_detachPermissionPathPermissionIdIsMalformed() throws Exception {
    Authentication auth = authentication();

    mockMvc
        .perform(
            delete("/api/v1/roles/{roleId}/permissions/{permissionId}", ROLE_ID, "not-a-uuid")
                .principal(auth))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("permissionId"));
  }

  @Test
  void should_havePermissionAnnotationPresent_when_detachPermissionInspected() throws Exception {
    assertRequiresPermission("detachPermission", ROLE_WRITE());
  }

  // ── softDeleteRole (US-018 C1) ───────────────────────────────────────────

  @Test
  void should_return204NoContent_when_deleteRoleSucceeds() throws Exception {
    mockMvc
        .perform(delete("/api/v1/roles/{roleId}", ROLE_ID).principal(authentication()))
        .andExpect(status().isNoContent())
        .andExpect(jsonPath("$").doesNotExist());

    org.mockito.Mockito.verify(roleManagementService).softDeleteRole(any(), eq(ROLE_ID), any());
  }

  @Test
  void should_return400_when_deleteRolePathRoleIdIsMalformed() throws Exception {
    mockMvc
        .perform(delete("/api/v1/roles/{roleId}", "not-a-uuid").principal(authentication()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("roleId"));
  }

  @Test
  void should_return409Rbac009_when_theRoleStillHasActiveHolders() throws Exception {
    org.mockito.Mockito.doThrow(new com.example.nexus.rbac.domain.RoleHasHoldersException())
        .when(roleManagementService)
        .softDeleteRole(any(), eq(ROLE_ID), any());

    mockMvc
        .perform(delete("/api/v1/roles/{roleId}", ROLE_ID).principal(authentication()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("RBAC_009"));
  }

  @Test
  void should_return404_when_deleteTargetsAMissingOrDeletedRole() throws Exception {
    org.mockito.Mockito.doThrow(
            new com.example.nexus.common.domain.ResourceNotFoundException(
                "ROLE_NOT_FOUND", "No such role"))
        .when(roleManagementService)
        .softDeleteRole(any(), eq(ROLE_ID), any());

    mockMvc
        .perform(delete("/api/v1/roles/{roleId}", ROLE_ID).principal(authentication()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("ROLE_NOT_FOUND"));
  }

  @Test
  void should_havePermissionAnnotationPresent_when_deleteRoleInspected() throws Exception {
    assertRequiresPermission("softDeleteRole", ROLE_WRITE());
  }

  // ── updateRole / PATCH (US-018 C1) ────────────────────────────────────

  @Test
  void should_return200WithTheUpdatedRole_when_patchSucceeds() throws Exception {
    when(roleManagementService.updateRole(any(), eq(ROLE_ID), eq("Renamed"), any(), any()))
        .thenReturn(roleView(ROLE_ID, "Renamed", "d", false));

    mockMvc
        .perform(
            patch("/api/v1/roles/{roleId}", ROLE_ID)
                .principal(authentication())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Renamed\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id").value(ROLE_ID.toString()))
        .andExpect(jsonPath("$.name").value("Renamed"))
        .andExpect(jsonPath("$.isSystemRole").value(false));
  }

  @Test
  void should_return400_when_patchBodyIsEmpty() throws Exception {
    mockMvc
        .perform(
            patch("/api/v1/roles/{roleId}", ROLE_ID)
                .principal(authentication())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
  }

  @Test
  void should_return400_when_patchNameIsOversizeOrMalformed() throws Exception {
    mockMvc
        .perform(
            patch("/api/v1/roles/{roleId}", ROLE_ID)
                .principal(authentication())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"" + "a".repeat(65) + "\"}"))
        .andExpect(status().isBadRequest());
    mockMvc
        .perform(
            patch("/api/v1/roles/{roleId}", ROLE_ID)
                .principal(authentication())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"bad\\nname\"}"))
        .andExpect(status().isBadRequest());
  }

  @Test
  void should_return400_when_patchPathRoleIdIsMalformed() throws Exception {
    mockMvc
        .perform(
            patch("/api/v1/roles/{roleId}", "not-a-uuid")
                .principal(authentication())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Renamed\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("roleId"));
  }

  @Test
  void should_return409Rbac006_when_patchNameIsTaken() throws Exception {
    when(roleManagementService.updateRole(any(), eq(ROLE_ID), any(), any(), any()))
        .thenThrow(new com.example.nexus.rbac.domain.DuplicateRoleNameException());

    mockMvc
        .perform(
            patch("/api/v1/roles/{roleId}", ROLE_ID)
                .principal(authentication())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Taken\"}"))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("RBAC_006"));
  }

  @Test
  void should_return404_when_patchTargetsAMissingOrDeletedRole() throws Exception {
    when(roleManagementService.updateRole(any(), eq(ROLE_ID), any(), any(), any()))
        .thenThrow(
            new com.example.nexus.common.domain.ResourceNotFoundException(
                "ROLE_NOT_FOUND", "No such role"));

    mockMvc
        .perform(
            patch("/api/v1/roles/{roleId}", ROLE_ID)
                .principal(authentication())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"description\":\"x\"}"))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("ROLE_NOT_FOUND"));
  }

  @Test
  void should_havePermissionAnnotationPresent_when_updateRoleInspected() throws Exception {
    assertRequiresPermission("updateRole", ROLE_WRITE());
  }

  // ── Helpers ──────────────────────────────────────────────────────────

  private static String ROLE_WRITE() {
    return "role:write";
  }

  private static String ROLE_READ() {
    return "role:read";
  }

  // ── B6 counts: all four RoleResponse producers carry both fields ─────────────────────

  @Test
  void should_returnZeroCountsWithoutQueryingThem_when_createRoleSucceeds() throws Exception {
    when(roleManagementService.createRole(any(), any(), any(), any()))
        .thenReturn(roleView(ROLE_ID, "Billing Manager", null, false));

    mockMvc
        .perform(
            post("/api/v1/roles")
                .principal(authentication())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Billing Manager\"}"))
        .andExpect(jsonPath("$.memberCount").value(0))
        .andExpect(jsonPath("$.permissionCount").value(0));

    verify(roleManagementService, never()).countsForRoles(any(), any());
  }

  @Test
  void should_returnCountsPerRole_when_listingRoles() throws Exception {
    UUID otherRoleId = UUID.fromString("00000000-0000-7000-8000-000000000009");
    when(roleManagementService.listRoles(any(), eq(0), eq(20)))
        .thenReturn(
            new PageResult<>(
                List.of(
                    roleView(ROLE_ID, "A", null, false), roleView(otherRoleId, "B", null, false)),
                2,
                0,
                20));
    when(roleManagementService.countsForRoles(any(), any()))
        .thenReturn(Map.of(ROLE_ID, new RoleCounts(ROLE_ID, 3L, 5)));

    mockMvc
        .perform(get("/api/v1/roles").principal(authentication()))
        .andExpect(jsonPath("$.data[0].memberCount").value(3))
        .andExpect(jsonPath("$.data[0].permissionCount").value(5))
        .andExpect(jsonPath("$.data[1].memberCount").value(0))
        .andExpect(jsonPath("$.data[1].permissionCount").value(0));
  }

  @Test
  void should_returnCounts_when_gettingOneRole() throws Exception {
    when(roleManagementService.getRole(any(), eq(ROLE_ID)))
        .thenReturn(roleView(ROLE_ID, "A", null, false));
    when(roleManagementService.countsForRoles(any(), eq(List.of(ROLE_ID))))
        .thenReturn(Map.of(ROLE_ID, new RoleCounts(ROLE_ID, 1L, 7)));

    mockMvc
        .perform(get("/api/v1/roles/{roleId}", ROLE_ID).principal(authentication()))
        .andExpect(jsonPath("$.memberCount").value(1))
        .andExpect(jsonPath("$.permissionCount").value(7));
  }

  @Test
  void should_returnCounts_when_patchSucceeds() throws Exception {
    when(roleManagementService.updateRole(any(), eq(ROLE_ID), any(), any(), any()))
        .thenReturn(roleView(ROLE_ID, "Renamed", null, false));
    when(roleManagementService.countsForRoles(any(), eq(List.of(ROLE_ID))))
        .thenReturn(Map.of(ROLE_ID, new RoleCounts(ROLE_ID, 2L, 4)));

    mockMvc
        .perform(
            patch("/api/v1/roles/{roleId}", ROLE_ID)
                .principal(authentication())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Renamed\"}"))
        .andExpect(jsonPath("$.memberCount").value(2))
        .andExpect(jsonPath("$.permissionCount").value(4));
  }

  private static void assertRequiresPermission(String methodName, String expectedPermission)
      throws NoSuchMethodException {
    Method method =
        java.util.Arrays.stream(RoleController.class.getMethods())
            .filter(m -> m.getName().equals(methodName))
            .findFirst()
            .orElseThrow();
    RequiresPermission annotation = method.getAnnotation(RequiresPermission.class);

    assertThat(annotation).as("%s must carry @RequiresPermission", methodName).isNotNull();
    assertThat(annotation.value()).isEqualTo(expectedPermission);
  }

  private static RoleView roleView(UUID id, String name, String description, boolean systemRole) {
    return new RoleView(id, TENANT_ID, name, description, systemRole, CREATED_AT);
  }

  private static Authentication authentication() {
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(PRINCIPAL_USER_ID.toString(), null, List.of());
    auth.setDetails(
        Map.of("tenantId", TENANT_ID.toString(), "permissions", List.of("role:read", "role:write")));
    return auth;
  }

  // ── Log-capture helpers (mirrors RoleAssignmentServiceTest's pattern, root logger) ──────

  private static ListAppender<ILoggingEvent> startRootLogCapture() {
    Logger rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    rootLogger.addAppender(listAppender);
    return listAppender;
  }

  private static void stopRootLogCapture(ListAppender<ILoggingEvent> listAppender) {
    Logger rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    rootLogger.detachAppender(listAppender);
    listAppender.stop();
  }

  private static boolean keyValueContains(ILoggingEvent event, String marker) {
    if (event.getKeyValuePairs() == null) {
      return false;
    }
    return event.getKeyValuePairs().stream()
        .anyMatch(kv -> kv.value != null && String.valueOf(kv.value).contains(marker));
  }
}
