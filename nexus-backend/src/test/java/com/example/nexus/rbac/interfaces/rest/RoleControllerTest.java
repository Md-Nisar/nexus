package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.common.web.GlobalExceptionHandler;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RoleView;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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

  private RoleManagementService roleManagementService;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    roleManagementService = mock(RoleManagementService.class);
    SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    RoleController controller = new RoleController(roleManagementService);
    mockMvc =
        MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(new GlobalExceptionHandler(meterRegistry))
            .build();
  }

  // ── createRole ───────────────────────────────────────────────────────

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
  void should_return200WithDataEnvelope_when_listingRoles() throws Exception {
    Authentication auth = authentication();
    when(roleManagementService.listRoles(any()))
        .thenReturn(List.of(roleView(ROLE_ID, "Billing Manager", "d", false)));

    mockMvc
        .perform(get("/api/v1/roles").principal(auth))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data").isArray())
        .andExpect(jsonPath("$.data[0].id").value(ROLE_ID.toString()));
  }

  @Test
  void should_havePermissionAnnotationPresent_when_listRolesInspected() throws Exception {
    assertRequiresPermission("listRoles", ROLE_READ());
  }

  // ── listRolePermissions ──────────────────────────────────────────────

  @Test
  void should_return200WithDataEnvelope_when_listingRolePermissions() throws Exception {
    Authentication auth = authentication();
    when(roleManagementService.listRolePermissions(any(), eq(ROLE_ID)))
        .thenReturn(List.of(new PermissionView(PERMISSION_ID, "user:read", "Read users")));

    mockMvc
        .perform(get("/api/v1/roles/{roleId}/permissions", ROLE_ID).principal(auth))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data").isArray())
        .andExpect(jsonPath("$.data[0].id").value(PERMISSION_ID.toString()));
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

  // ── Helpers ──────────────────────────────────────────────────────────

  private static String ROLE_WRITE() {
    return "role:write";
  }

  private static String ROLE_READ() {
    return "role:read";
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
