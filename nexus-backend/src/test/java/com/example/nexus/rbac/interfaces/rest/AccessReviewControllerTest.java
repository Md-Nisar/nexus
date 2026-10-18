package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.common.web.GlobalExceptionHandler;
import com.example.nexus.rbac.application.AccessReviewService;
import com.example.nexus.rbac.domain.EffectivePermission;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionHolder;
import com.example.nexus.rbac.domain.RoleHolder;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * MockMvc slice over {@link AccessReviewController} with a mocked service (US-018 T-029). Standalone,
 * so there is no AOP proxy: {@code @RequiresPermission("audit:read")} is asserted structurally on
 * every handler; the runtime denial path is the cross-layer ITs' concern, as for {@link
 * RoleControllerTest}.
 */
@Tag("UnitTest")
class AccessReviewControllerTest {

  private static final UUID PRINCIPAL = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID TENANT = UUID.fromString("00000000-0000-7000-8000-000000000002");
  private static final UUID ROLE_ID = UUID.fromString("00000000-0000-7000-8000-000000000003");
  private static final UUID PERMISSION_ID = UUID.fromString("00000000-0000-7000-8000-000000000004");
  private static final UUID USER_ID = UUID.fromString("00000000-0000-7000-8000-000000000005");
  private static final UUID ASSIGNER = UUID.fromString("00000000-0000-7000-8000-000000000006");

  private AccessReviewService service;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    service = mock(AccessReviewService.class);
    mockMvc =
        MockMvcBuilders.standaloneSetup(new AccessReviewController(service))
            .setControllerAdvice(new GlobalExceptionHandler(new SimpleMeterRegistry()))
            .build();
  }

  private static Authentication authentication() {
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(PRINCIPAL.toString(), null, List.of());
    auth.setDetails(Map.of("tenantId", TENANT.toString(), "permissions", List.of("audit:read")));
    return auth;
  }

  // ── role holders ───────────────────────────────────────────────────────────────────────

  @Test
  void should_return200WithIdsPageAndLinks_when_listingRoleHolders() throws Exception {
    UUID assignment = UUID.randomUUID();
    when(service.listRoleHolders(any(), eq(ROLE_ID), eq(0), eq(20)))
        .thenReturn(
            new PageResult<>(
                List.of(new RoleHolder(USER_ID, assignment, Instant.parse("2026-10-01T10:00:00Z"), ASSIGNER)),
                1,
                0,
                20));

    mockMvc
        .perform(get("/api/v1/roles/{roleId}/holders", ROLE_ID).principal(authentication()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].userId").value(USER_ID.toString()))
        .andExpect(jsonPath("$.data[0].assignmentId").value(assignment.toString()))
        .andExpect(jsonPath("$.data[0].assignedBy").value(ASSIGNER.toString()))
        .andExpect(jsonPath("$.page.totalElements").value(1))
        .andExpect(jsonPath("$.links.next").value((Object) null))
        .andExpect(jsonPath("$.data[0].email").doesNotExist())
        .andExpect(jsonPath("$.data[0].name").doesNotExist());
  }

  @Test
  void should_omitAssignedBy_when_theServiceRedactedIt() throws Exception {
    when(service.listRoleHolders(any(), eq(ROLE_ID), eq(0), eq(20)))
        .thenReturn(
            new PageResult<>(
                List.of(new RoleHolder(USER_ID, UUID.randomUUID(), Instant.now(), null)), 1, 0, 20));

    mockMvc
        .perform(get("/api/v1/roles/{roleId}/holders", ROLE_ID).principal(authentication()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].assignedBy").doesNotExist());
  }

  @Test
  void should_linkWithTheRolePath_when_moreRoleHolderPagesExist() throws Exception {
    when(service.listRoleHolders(any(), eq(ROLE_ID), eq(0), eq(2)))
        .thenReturn(new PageResult<>(List.of(), 5, 0, 2));

    mockMvc
        .perform(
            get("/api/v1/roles/{roleId}/holders", ROLE_ID).param("size", "2").principal(authentication()))
        .andExpect(
            jsonPath("$.links.next").value("/api/v1/roles/" + ROLE_ID + "/holders?page=1&size=2"));
  }

  @Test
  void should_return404_when_theRoleIsNotFoundForHolders() throws Exception {
    when(service.listRoleHolders(any(), eq(ROLE_ID), eq(0), eq(20)))
        .thenThrow(new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role"));

    mockMvc
        .perform(get("/api/v1/roles/{roleId}/holders", ROLE_ID).principal(authentication()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("ROLE_NOT_FOUND"));
  }

  @Test
  void should_return400_when_theRoleIdOrPagingIsInvalid() throws Exception {
    mockMvc
        .perform(get("/api/v1/roles/{roleId}/holders", "not-a-uuid").principal(authentication()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("roleId"));
    mockMvc
        .perform(
            get("/api/v1/roles/{roleId}/holders", ROLE_ID).param("size", "101").principal(authentication()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    mockMvc
        .perform(
            get("/api/v1/roles/{roleId}/holders", ROLE_ID).param("page", "-1").principal(authentication()))
        .andExpect(status().isBadRequest());
    verifyNoInteractions(service);
  }

  // ── permission holders ─────────────────────────────────────────────────────────────────

  @Test
  void should_return200WithViaRoleIds_when_listingPermissionHolders() throws Exception {
    UUID second = UUID.randomUUID();
    when(service.listPermissionHolders(any(), eq(PERMISSION_ID), eq(0), eq(20)))
        .thenReturn(
            new PageResult<>(
                List.of(new PermissionHolder(USER_ID, List.of(ROLE_ID, second))), 1, 0, 20));

    mockMvc
        .perform(
            get("/api/v1/permissions/{permissionId}/holders", PERMISSION_ID).principal(authentication()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].userId").value(USER_ID.toString()))
        .andExpect(jsonPath("$.data[0].viaRoleIds[0]").value(ROLE_ID.toString()))
        .andExpect(jsonPath("$.data[0].viaRoleIds[1]").value(second.toString()))
        .andExpect(jsonPath("$.page.size").value(20));
  }

  @Test
  void should_return404_when_thePermissionIsUnknown() throws Exception {
    when(service.listPermissionHolders(any(), eq(PERMISSION_ID), eq(0), eq(20)))
        .thenThrow(new ResourceNotFoundException("PERMISSION_NOT_FOUND", "No such permission"));

    mockMvc
        .perform(
            get("/api/v1/permissions/{permissionId}/holders", PERMISSION_ID).principal(authentication()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("PERMISSION_NOT_FOUND"));
  }

  @Test
  void should_return400_when_thePermissionIdIsMalformed() throws Exception {
    mockMvc
        .perform(get("/api/v1/permissions/{permissionId}/holders", "x").principal(authentication()))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("permissionId"));
  }

  // ── effective permissions ──────────────────────────────────────────────────────────────

  @Test
  void should_return200WithNamesAndRoleIds_when_gettingEffectivePermissions() throws Exception {
    when(service.getEffectivePermissions(any(), eq(USER_ID)))
        .thenReturn(List.of(new EffectivePermission("audit:read", List.of(ROLE_ID))));

    mockMvc
        .perform(get("/api/v1/users/{userId}/effective-permissions", USER_ID).principal(authentication()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userId").value(USER_ID.toString()))
        .andExpect(jsonPath("$.permissions[0].name").value("audit:read"))
        .andExpect(jsonPath("$.permissions[0].viaRoleIds[0]").value(ROLE_ID.toString()))
        .andExpect(jsonPath("$.page").doesNotExist());
  }

  @Test
  void should_return200WithAnEmptyList_when_theUserHoldsNothing() throws Exception {
    when(service.getEffectivePermissions(any(), eq(USER_ID))).thenReturn(List.of());

    mockMvc
        .perform(get("/api/v1/users/{userId}/effective-permissions", USER_ID).principal(authentication()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.permissions").isEmpty());
  }

  @Test
  void should_return404_when_theUserIsNotFoundForEffectivePermissions() throws Exception {
    when(service.getEffectivePermissions(any(), eq(USER_ID)))
        .thenThrow(new ResourceNotFoundException("USER_NOT_FOUND", "No such user"));

    mockMvc
        .perform(get("/api/v1/users/{userId}/effective-permissions", USER_ID).principal(authentication()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("USER_NOT_FOUND"));
  }

  // ── structural: every handler needs audit:read ─────────────────────────────────────────

  @Test
  void should_requireAuditRead_when_everyHandlerIsInspected() {
    List<Method> handlers =
        Arrays.stream(AccessReviewController.class.getDeclaredMethods())
            .filter(m -> java.lang.reflect.Modifier.isPublic(m.getModifiers()))
            .filter(m -> m.isAnnotationPresent(org.springframework.web.bind.annotation.GetMapping.class))
            .toList();

    assertThat(handlers).hasSize(3);
    assertThat(handlers)
        .allSatisfy(
            m -> {
              RequiresPermission annotation = m.getAnnotation(RequiresPermission.class);
              assertThat(annotation).as("%s must carry @RequiresPermission", m.getName()).isNotNull();
              assertThat(annotation.value()).isEqualTo("audit:read");
            });
  }
}
