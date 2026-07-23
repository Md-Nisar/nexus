package com.example.nexus.common.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

class InsufficientPermissionExceptionTest {

  @Test
  void should_extendAccessDeniedException() {
    InsufficientPermissionException exception =
        new InsufficientPermissionException("user:write", DenialReason.PERMISSION_ABSENT);

    assertThat(exception).isInstanceOf(AccessDeniedException.class);
  }

  @Test
  void should_exposeRequiredPermission_when_constructed() {
    InsufficientPermissionException exception =
        new InsufficientPermissionException("user:write", DenialReason.PERMISSION_ABSENT);

    assertThat(exception.getRequiredPermission()).isEqualTo("user:write");
  }

  @Test
  void should_includeRequiredPermissionInMessage_when_constructed() {
    InsufficientPermissionException exception =
        new InsufficientPermissionException("user:write", DenialReason.PERMISSION_ABSENT);

    assertThat(exception.getMessage()).isNotNull().contains("user:write");
  }

  @Test
  void should_storeRequiredPermission_when_constructedWithBlankString() {
    InsufficientPermissionException exception =
        new InsufficientPermissionException("", DenialReason.PERMISSION_ABSENT);

    assertThat(exception.getRequiredPermission()).isEmpty();
  }

  @Test
  void should_exposeReason_when_constructedWithPermissionAbsent() {
    InsufficientPermissionException exception =
        new InsufficientPermissionException("user:write", DenialReason.PERMISSION_ABSENT);

    assertThat(exception.getReason()).isEqualTo(DenialReason.PERMISSION_ABSENT);
  }

  @Test
  void should_exposeReason_when_constructedWithMalformedAuthentication() {
    InsufficientPermissionException exception =
        new InsufficientPermissionException("user:write", DenialReason.MALFORMED_AUTHENTICATION);

    assertThat(exception.getReason()).isEqualTo(DenialReason.MALFORMED_AUTHENTICATION);
  }

  @Test
  void should_exposeReason_when_constructedWithMissingTenant() {
    InsufficientPermissionException exception =
        new InsufficientPermissionException("user:write", DenialReason.MISSING_TENANT);

    assertThat(exception.getReason()).isEqualTo(DenialReason.MISSING_TENANT);
  }
}
