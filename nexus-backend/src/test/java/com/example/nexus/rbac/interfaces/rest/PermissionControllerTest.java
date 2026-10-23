package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.nexus.common.security.Permissions;
import com.example.nexus.common.web.GlobalExceptionHandler;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionResponse;
import com.jayway.jsonpath.JsonPath;
import tools.jackson.databind.ObjectMapper;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
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

  private static final UUID PERMISSION_ID = RbacSeededPermissionIds.USER_READ;

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
    when(roleManagementService.listAllPermissions(0, 20))
        .thenReturn(
            new PageResult<>(
                List.of(new PermissionView(PERMISSION_ID, "user:read", "Read user accounts")),
                1,
                0,
                20));

    mockMvc
        .perform(get("/api/v1/permissions"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data").isArray())
        .andExpect(jsonPath("$.data[0].id").value(PERMISSION_ID.toString()))
        .andExpect(jsonPath("$.data[0].name").value("user:read"))
        .andExpect(jsonPath("$.data[0].description").value("Read user accounts"))
        .andExpect(jsonPath("$.page.totalElements").value(1))
        .andExpect(jsonPath("$.links.next").value((Object) null));
  }

  @Test
  void should_flagEveryCatalogueRowAsSensitiveExactlyWhenInSensitiveSet_when_listingPermissions()
      throws Exception {
    List<PermissionView> rows =
        Permissions.ALL.stream()
            .map(name -> new PermissionView(UUID.randomUUID(), name, "d"))
            .toList();
    when(roleManagementService.listAllPermissions(0, 20))
        .thenReturn(new PageResult<>(rows, rows.size(), 0, 20));

    String body =
        mockMvc
            .perform(get("/api/v1/permissions"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();

    for (PermissionView row : rows) {
      boolean expected = Permissions.SENSITIVE.contains(row.name());
      assertThat(JsonPath.<List<Boolean>>read(body, "$.data[?(@.name=='" + row.name() + "')].isSensitive"))
          .containsExactly(expected);
    }
  }

  @Test
  void should_serialiseKeyAsIsSensitive_when_mappingAPermission() {
    PermissionResponse response =
        PermissionController.toResponse(new PermissionView(PERMISSION_ID, "role:write", "d"));

    assertThat(new ObjectMapper().writeValueAsString(response))
        .contains("\"isSensitive\":true")
        .doesNotContain("\"sensitive\"");
  }

  @Test
  void should_linkToTheNextPage_when_moreCataloguePagesExist() throws Exception {
    when(roleManagementService.listAllPermissions(0, 3))
        .thenReturn(new PageResult<>(List.of(), 8, 0, 3));

    mockMvc
        .perform(get("/api/v1/permissions").param("size", "3"))
        .andExpect(jsonPath("$.page.totalPages").value(3))
        .andExpect(jsonPath("$.links.next").value("/api/v1/permissions?page=1&size=3"))
        .andExpect(jsonPath("$.links.prev").value((Object) null));
  }

  @Test
  void should_return400_when_sizeIs101OrPageIsNegative() throws Exception {
    mockMvc
        .perform(get("/api/v1/permissions").param("size", "101"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    mockMvc
        .perform(get("/api/v1/permissions").param("page", "-1"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
  }

  @Test
  void should_return200WithEmptyDataArray_when_noPermissionsExist() throws Exception {
    when(roleManagementService.listAllPermissions(0, 20))
        .thenReturn(new PageResult<>(List.of(), 0, 0, 20));

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
    var method = PermissionController.class.getMethod("listPermissions", String.class, String.class);
    var annotation = method.getAnnotation(com.example.nexus.common.security.RequiresPermission.class);

    assertThat(annotation).isNotNull();
    assertThat(annotation.value()).isEqualTo("role:read");
  }
}
