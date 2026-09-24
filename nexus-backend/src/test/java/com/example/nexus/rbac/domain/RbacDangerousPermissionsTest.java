package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RbacDangerousPermissionsTest {

  @Test
  void should_containRoleWriteUserWriteTenantWrite_when_checked() {
    assertThat(RbacDangerousPermissions.NAMES)
        .containsExactlyInAnyOrder("role:write", "user:write", "tenant:write");
  }

  @Test
  void should_returnTrue_when_permissionNameMatchesCaseInsensitively() {
    assertThat(RbacDangerousPermissions.contains("role:write")).isTrue();
    assertThat(RbacDangerousPermissions.contains("ROLE:WRITE")).isTrue();
    assertThat(RbacDangerousPermissions.contains("User:Write")).isTrue();
    assertThat(RbacDangerousPermissions.contains("tenant:write")).isTrue();
  }

  @Test
  void should_returnFalse_when_permissionNameIsNotDangerous() {
    assertThat(RbacDangerousPermissions.contains("user:read")).isFalse();
    assertThat(RbacDangerousPermissions.contains("role:read")).isFalse();
  }

  @Test
  void should_returnFalse_when_permissionNameIsNull() {
    assertThat(RbacDangerousPermissions.contains(null)).isFalse();
  }

  @Test
  void should_returnFalse_when_carriesAnyGivenNullCollection() {
    assertThat(RbacDangerousPermissions.carriesAny(null)).isFalse();
  }

  @Test
  void should_returnFalse_when_carriesAnyGivenEmptyCollection() {
    assertThat(RbacDangerousPermissions.carriesAny(List.of())).isFalse();
  }

  @Test
  void should_returnTrue_when_carriesAnyGivenOneCaseInsensitiveMatch() {
    assertThat(RbacDangerousPermissions.carriesAny(List.of("User:Write", "user:read"))).isTrue();
  }

  /**
   * MC-B regression assertion 1 (03-design.md §4.1/§11.2): a duplicate-bearing input must return
   * {@code false} -- pins the per-name, case-insensitive {@code anyMatch} shape and rejects a
   * count-based implementation, which would return {@code true} here.
   */
  @Test
  void should_returnFalse_when_carriesAllGivenDuplicateEntriesOfSameName() {
    assertThat(
            RbacDangerousPermissions.carriesAll(
                Arrays.asList("user:write", "user:write", "user:write")))
        .isFalse();
  }

  /**
   * MC-B regression assertion 2 (03-design.md §4.1/§11.2): a case-variant match on all three names
   * must return {@code true} -- rejects a case-sensitive {@code containsAll}.
   */
  @Test
  void should_returnTrue_when_carriesAllGivenCaseInsensitiveMatchesForAllThreeNames() {
    assertThat(
            RbacDangerousPermissions.carriesAll(
                Arrays.asList("Role:Write", "USER:write", "tenant:WRITE")))
        .isTrue();
  }

  /**
   * MC-B regression assertion 3 (03-design.md §4.1/§11.2): exactly two of three present must
   * return {@code false}.
   */
  @Test
  void should_returnFalse_when_carriesAllGivenExactlyTwoOfThreeNames() {
    assertThat(RbacDangerousPermissions.carriesAll(Arrays.asList("role:write", "user:write")))
        .isFalse();
  }

  @Test
  void should_returnFalse_when_carriesAllGivenNullCollection() {
    assertThat(RbacDangerousPermissions.carriesAll(null)).isFalse();
  }

  @Test
  void should_returnFalse_when_carriesAllGivenEmptyCollection() {
    assertThat(RbacDangerousPermissions.carriesAll(List.of())).isFalse();
  }

  @Test
  void should_returnFalse_when_carriesAllGivenCollectionContainingNullElement() {
    assertThat(
            RbacDangerousPermissions.carriesAll(
                Arrays.asList("role:write", "user:write", null)))
        .isFalse();
  }
}
