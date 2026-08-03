package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.web.GlobalExceptionHandler;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.RoleChangeActor;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * MockMvc slice over {@link UserRoleController} with a mocked {@link RoleAssignmentService},
 * mirroring {@code LoginControllerTest}'s pattern (standalone setup + the real {@link
 * GlobalExceptionHandler}, no Spring Security context). {@code @RequiresPermission}/{@code
 * @PreAuthorize} enforcement is intentionally NOT exercised here — Spring AOP method security
 * needs a real application context/proxy, which a standalone MockMvc setup does not provide.
 * Permission enforcement (positive + negative, per endpoint) is covered by {@code
 * RoleAssignmentSecurityIT} (T-019). This class covers everything the controller itself is
 * responsible for: principal/tenant unwrapping, path/body validation, response shaping.
 */
@Tag("UnitTest")
class UserRoleControllerTest {

  private static final UUID PRINCIPAL_USER_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000002");
  private static final UUID PATH_USER_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000099");
  private static final UUID ROLE_ID = UUID.fromString("00000000-0000-7000-8000-000000000003");

  private RoleAssignmentService roleAssignmentService;
  private SimpleMeterRegistry meterRegistry;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    roleAssignmentService = mock(RoleAssignmentService.class);
    meterRegistry = new SimpleMeterRegistry();
    UserRoleController controller = new UserRoleController(roleAssignmentService);
    mockMvc =
        MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(new GlobalExceptionHandler(meterRegistry))
            .build();
  }

  /**
   * Asserts the given {@code reason} was the actual {@link
   * com.example.nexus.common.security.DenialReason} that fired, via the {@code
   * nexus.rbac.permission_denied{reason}} counter {@code GlobalExceptionHandler} increments on
   * every {@code InsufficientPermissionException} -- the response body itself does not expose
   * {@code reason}, so this is the only way this test class can distinguish
   * {@code MALFORMED_AUTHENTICATION} from {@code MISSING_TENANT} etc.
   */
  private void assertDenialReasonRecorded(String reason) {
    assertThat(meterRegistry.find("nexus.rbac.permission_denied").tag("reason", reason).counter())
        .as("counter tagged reason=%s", reason)
        .isNotNull();
    assertThat(
            meterRegistry.find("nexus.rbac.permission_denied").tag("reason", reason).counter()
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void should_invokeServiceWithPrincipalAsActor_when_pathUserIdDiffersFromPrincipal()
      throws Exception {
    // Path userId (PATH_USER_ID) is deliberately different from the JWT principal
    // (PRINCIPAL_USER_ID) -- this is the mandatory T-E10 provenance assertion: the actor must
    // always be sourced from the principal, never from the path, and the two must never be
    // confused.
    Authentication auth = authentication(PRINCIPAL_USER_ID.toString(), TENANT_ID.toString());
    when(roleAssignmentService.assign(any(), any(), any(), any()))
        .thenReturn(activeAssignment(PATH_USER_ID, ROLE_ID, null));

    mockMvc
        .perform(
            post("/api/v1/users/{userId}/roles", PATH_USER_ID)
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleId\":\"" + ROLE_ID + "\"}"))
        .andExpect(status().isCreated());

    ArgumentCaptor<RoleChangeActor> actorCaptor = ArgumentCaptor.forClass(RoleChangeActor.class);
    ArgumentCaptor<UUID> targetCaptor = ArgumentCaptor.forClass(UUID.class);
    verify(roleAssignmentService)
        .assign(actorCaptor.capture(), targetCaptor.capture(), eq(ROLE_ID), any());

    assertThat(actorCaptor.getValue().userId()).isEqualTo(PRINCIPAL_USER_ID);
    assertThat(actorCaptor.getValue().tenantId()).isEqualTo(TENANT_ID);
    assertThat(targetCaptor.getValue()).isEqualTo(PATH_USER_ID);
  }

  @Test
  void should_return403_when_principalIsNotAUuidString() throws Exception {
    Authentication auth = authentication("not-a-uuid", TENANT_ID.toString());

    mockMvc
        .perform(
            get("/api/v1/users/{userId}/roles", PATH_USER_ID).principal(auth))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("RBAC_001"))
        .andExpect(jsonPath("$.requiredPermission").value("user:read"));
    assertDenialReasonRecorded("MALFORMED_AUTHENTICATION");
  }

  @Test
  void should_return403_when_principalIsNull() throws Exception {
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(null, null, List.of());
    auth.setDetails(Map.of("tenantId", TENANT_ID.toString(), "permissions", List.of()));

    mockMvc
        .perform(get("/api/v1/users/{userId}/roles", PATH_USER_ID).principal(auth))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("RBAC_001"));
    assertDenialReasonRecorded("MALFORMED_AUTHENTICATION");
  }

  @Test
  void should_return403_when_authenticationDetailsMissingTenant() throws Exception {
    // Confirms AuthenticatedRequestDetails.fromAuthentication's own existing fail-closed
    // MISSING_TENANT behavior still fires through this controller -- not reimplementing its test.
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(PRINCIPAL_USER_ID.toString(), null, List.of());
    auth.setDetails(Map.of("permissions", List.of()));

    mockMvc
        .perform(get("/api/v1/users/{userId}/roles", PATH_USER_ID).principal(auth))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("RBAC_001"));
    assertDenialReasonRecorded("MISSING_TENANT");
  }

  @Test
  void should_return400_when_pathUserIdIsMalformed() throws Exception {
    Authentication auth = authentication(PRINCIPAL_USER_ID.toString(), TENANT_ID.toString());

    mockMvc
        .perform(get("/api/v1/users/{userId}/roles", "not-a-uuid").principal(auth))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("userId"));
  }

  @Test
  void should_return400_when_pathRoleIdIsMalformed() throws Exception {
    Authentication auth = authentication(PRINCIPAL_USER_ID.toString(), TENANT_ID.toString());

    mockMvc
        .perform(
            delete("/api/v1/users/{userId}/roles/{roleId}", PATH_USER_ID, "not-a-uuid")
                .principal(auth))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("roleId"));
  }

  @Test
  void should_return400WithDetails_when_roleIdBodyFieldIsMalformed() throws Exception {
    Authentication auth = authentication(PRINCIPAL_USER_ID.toString(), TENANT_ID.toString());

    mockMvc
        .perform(
            post("/api/v1/users/{userId}/roles", PATH_USER_ID)
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleId\":\"not-a-uuid\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("roleId"));
  }

  @Test
  void should_return400WithDetails_when_roleIdBodyFieldIsMissing() throws Exception {
    Authentication auth = authentication(PRINCIPAL_USER_ID.toString(), TENANT_ID.toString());

    mockMvc
        .perform(
            post("/api/v1/users/{userId}/roles", PATH_USER_ID)
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.details[0].field").value("roleId"));
  }

  @Test
  void should_return201WithLocationHeaderAndBody_when_assignSucceeds() throws Exception {
    Authentication auth = authentication(PRINCIPAL_USER_ID.toString(), TENANT_ID.toString());
    Instant assignedAt = Instant.parse("2026-07-28T09:12:00.123456Z");
    when(roleAssignmentService.assign(any(), eq(PATH_USER_ID), eq(ROLE_ID), any()))
        .thenReturn(
            new ActiveRoleAssignment(
                PATH_USER_ID, ROLE_ID, "MEMBER", assignedAt, PRINCIPAL_USER_ID));

    mockMvc
        .perform(
            post("/api/v1/users/{userId}/roles", PATH_USER_ID)
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleId\":\"" + ROLE_ID + "\"}"))
        .andExpect(status().isCreated())
        .andExpect(
            header()
                .string(
                    "Location", "/api/v1/users/" + PATH_USER_ID + "/roles/" + ROLE_ID))
        .andExpect(jsonPath("$.userId").value(PATH_USER_ID.toString()))
        .andExpect(jsonPath("$.roleId").value(ROLE_ID.toString()))
        .andExpect(jsonPath("$.roleName").value("MEMBER"))
        .andExpect(jsonPath("$.assignedBy").value(PRINCIPAL_USER_ID.toString()));
  }

  @Test
  void should_return200WithDataEnvelope_when_listingRoles() throws Exception {
    Authentication auth = authentication(PRINCIPAL_USER_ID.toString(), TENANT_ID.toString());
    when(roleAssignmentService.listActive(any(), eq(PATH_USER_ID)))
        .thenReturn(List.of(activeAssignment(PATH_USER_ID, ROLE_ID, PRINCIPAL_USER_ID)));

    mockMvc
        .perform(get("/api/v1/users/{userId}/roles", PATH_USER_ID).principal(auth))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data").isArray())
        .andExpect(jsonPath("$.data[0].userId").value(PATH_USER_ID.toString()))
        .andExpect(jsonPath("$.data[0].roleId").value(ROLE_ID.toString()));
  }

  @Test
  void should_serializeNullAssignedBy_when_serviceReturnsRedactedAssignment() throws Exception {
    Authentication auth = authentication(PRINCIPAL_USER_ID.toString(), TENANT_ID.toString());
    when(roleAssignmentService.listActive(any(), eq(PATH_USER_ID)))
        .thenReturn(List.of(activeAssignment(PATH_USER_ID, ROLE_ID, null)));

    mockMvc
        .perform(get("/api/v1/users/{userId}/roles", PATH_USER_ID).principal(auth))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].assignedBy").doesNotExist());
  }

  @Test
  void should_return204NoContent_when_revokeSucceeds() throws Exception {
    Authentication auth = authentication(PRINCIPAL_USER_ID.toString(), TENANT_ID.toString());

    mockMvc
        .perform(
            delete("/api/v1/users/{userId}/roles/{roleId}", PATH_USER_ID, ROLE_ID)
                .principal(auth))
        .andExpect(status().isNoContent())
        .andExpect(jsonPath("$").doesNotExist());

    verify(roleAssignmentService)
        .revoke(any(RoleChangeActor.class), eq(PATH_USER_ID), eq(ROLE_ID), any(RequestContext.class));
  }

  private static ActiveRoleAssignment activeAssignment(UUID userId, UUID roleId, UUID assignedBy) {
    return new ActiveRoleAssignment(
        userId, roleId, "MEMBER", Instant.parse("2026-07-28T09:12:00.123456Z"), assignedBy);
  }

  private static Authentication authentication(String principal, String tenantId) {
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(principal, null, List.of());
    auth.setDetails(Map.of("tenantId", tenantId, "permissions", List.of("user:read", "user:write")));
    return auth;
  }
}
