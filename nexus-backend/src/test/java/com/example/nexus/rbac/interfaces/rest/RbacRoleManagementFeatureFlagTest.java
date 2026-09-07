package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.example.nexus.rbac.application.RoleManagementService;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * US-015 T-008 — confirms {@code feature.nexus-us015-rbac-role-management.enabled} genuinely
 * gates whether {@link RoleController} and {@link PermissionController} are registered, without
 * loading the full application context (mirrors {@code SchedulingConfigTest}'s pattern for the
 * US-008 flag).
 */
@Tag("UnitTest")
class RbacRoleManagementFeatureFlagTest {

  private static final String FLAG = "feature.nexus-us015-rbac-role-management.enabled";

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner()
          .withUserConfiguration(RoleController.class, PermissionController.class)
          .withBean(RoleManagementService.class, () -> mock(RoleManagementService.class));

  @Test
  void should_notRegisterRbacControllers_when_flagDefaulted() {
    contextRunner.run(
        context -> {
          assertThat(context).doesNotHaveBean(RoleController.class);
          assertThat(context).doesNotHaveBean(PermissionController.class);
        });
  }

  @Test
  void should_notRegisterRbacControllers_when_flagExplicitlyFalse() {
    contextRunner
        .withPropertyValues(FLAG + "=false")
        .run(
            context -> {
              assertThat(context).doesNotHaveBean(RoleController.class);
              assertThat(context).doesNotHaveBean(PermissionController.class);
            });
  }

  @Test
  void should_registerRbacControllers_when_flagExplicitlyTrue() {
    contextRunner
        .withPropertyValues(FLAG + "=true")
        .run(
            context -> {
              assertThat(context).hasSingleBean(RoleController.class);
              assertThat(context).hasSingleBean(PermissionController.class);
            });
  }
}
