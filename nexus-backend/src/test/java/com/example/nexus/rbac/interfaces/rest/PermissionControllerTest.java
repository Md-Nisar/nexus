package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.nexus.common.web.GlobalExceptionHandler;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PermissionView;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * MockMvc slice over {@link PermissionController} with a mocked {@link RoleManagementService},
 * mirroring {@code UserRoleControllerTest}'s standalone pattern. {@code @RequiresPermission}
 * enforcement is intentionally NOT exercised here — Spring AOP method security needs a real
 * application context, which a standalone MockMvc setup does not provide; the negative-control
 * test below documents that expectation without asserting it through this slice.
 */
@Tag("UnitTest")
class PermissionControllerTest {

  private static final UUID PERMISSION_ID =
      UUID.fromString("019f6839-1802-7000-8000-000000000003");

  private RoleManagementService roleManagementService;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    roleManagementService = mock(RoleManagementService.class);
    SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    PermissionController controller = new PermissionController(roleManagementService);
    mockMvc =
        MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(new GlobalExceptionHandler(meterRegistry))
            .build();
  }

  @Test
  void should_return200WithDataEnvelope_when_listingPermissions() throws Exception {
    when(roleManagementService.listAllPermissions())
        .thenReturn(List.of(new PermissionView(PERMISSION_ID, "user:read", "Read user accounts")));

    mockMvc
        .perform(get("/api/v1/permissions"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data").isArray())
        .andExpect(jsonPath("$.data[0].id").value(PERMISSION_ID.toString()))
        .andExpect(jsonPath("$.data[0].name").value("user:read"))
        .andExpect(jsonPath("$.data[0].description").value("Read user accounts"));
  }

  @Test
  void should_return200WithEmptyDataArray_when_noPermissionsExist() throws Exception {
    when(roleManagementService.listAllPermissions()).thenReturn(List.of());

    mockMvc
        .perform(get("/api/v1/permissions"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data").isArray())
        .andExpect(jsonPath("$.data").isEmpty());
  }

  /**
   * Negative-control 403 per T-006's testing requirement. This standalone slice has no Spring AOP
   * proxy, so {@code @RequiresPermission("role:read")} cannot actually fire here — this documents
   * the contract (the annotation is present, verified by reflection) rather than exercising the
   * denial path, which is covered end-to-end by T-010's cross-layer ITs.
   */
  @Test
  void should_havePermissionAnnotationPresent_when_listPermissionsInspected() throws Exception {
    var method = PermissionController.class.getMethod("listPermissions");
    var annotation = method.getAnnotation(com.example.nexus.common.security.RequiresPermission.class);

    assertThat(annotation).isNotNull();
    assertThat(annotation.value()).isEqualTo("role:read");
  }
}
