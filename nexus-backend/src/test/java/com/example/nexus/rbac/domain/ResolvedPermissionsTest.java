package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class ResolvedPermissionsTest {

  @Test
  void should_sortAndDedupe_when_constructed() {
    ResolvedPermissions resolved =
        new ResolvedPermissions(
            List.of("MEMBER", "TENANT_ADMIN", "MEMBER"),
            List.of("user:read", "tenant:read", "user:read"));

    assertThat(resolved.roles()).containsExactly("MEMBER", "TENANT_ADMIN");
    assertThat(resolved.permissions()).containsExactly("tenant:read", "user:read");
  }

  @Test
  void should_returnEmptyLists_when_empty() {
    ResolvedPermissions resolved = ResolvedPermissions.empty();

    assertThat(resolved.roles()).isEmpty();
    assertThat(resolved.permissions()).isEmpty();
  }
}
