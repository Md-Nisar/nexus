package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RbacAdminEquivalenceTest {

  @Test
  void should_returnTrue_when_isAdminEquivalentGivenNameMatchesTenantAdminRegardlessOfPermissions() {
    assertThat(RbacAdminEquivalence.isAdminEquivalent("TENANT_ADMIN", List.of())).isTrue();
  }

  @Test
  void should_returnTrue_when_isAdminEquivalentGivenTenantAdminNameCaseInsensitiveMatch() {
    assertThat(RbacAdminEquivalence.isAdminEquivalent("tenant_admin", List.of())).isTrue();
  }

  @Test
  void should_returnTrue_when_isAdminEquivalentGivenNonAdminNameAndOneDangerousPermission() {
    assertThat(RbacAdminEquivalence.isAdminEquivalent("CUSTOM", List.of("user:write"))).isTrue();
  }

  @Test
  void should_returnTrue_when_isAdminEquivalentGivenNonAdminNameAndAllThreeDangerousPermissions() {
    assertThat(
            RbacAdminEquivalence.isAdminEquivalent(
                "CUSTOM", Arrays.asList("role:write", "user:write", "tenant:write")))
        .isTrue();
  }

  @Test
  void should_returnTrue_when_isAdminEquivalentGivenNonAdminNameAndCaseVariantDangerousPermission() {
    assertThat(RbacAdminEquivalence.isAdminEquivalent("CUSTOM", List.of("User:Write"))).isTrue();
  }

  @Test
  void should_returnFalse_when_isAdminEquivalentGivenNonAdminNameAndNoPermissions() {
    assertThat(RbacAdminEquivalence.isAdminEquivalent("CUSTOM", List.of("user:read"))).isFalse();
  }

  @Test
  void should_returnFalse_when_isAdminEquivalentGivenNonAdminNameAndEmptyPermissionCollection() {
    assertThat(RbacAdminEquivalence.isAdminEquivalent("CUSTOM", List.of())).isFalse();
  }

  @Test
  void should_returnFalse_when_isAdminEquivalentGivenNonAdminNameAndNullPermissionCollection() {
    assertThat(RbacAdminEquivalence.isAdminEquivalent("CUSTOM", null)).isFalse();
  }

  @Test
  void should_returnTrue_when_isFullyAdminEquivalentGivenNameMatchesTenantAdmin() {
    assertThat(RbacAdminEquivalence.isFullyAdminEquivalent("TENANT_ADMIN", List.of())).isTrue();
  }

  /**
   * The named vacuity regression test (ADR-0018 D2, 03-design.md §4.1/§5.2): a caller holding
   * exactly {@code user:write} -- and therefore ANY-admin-equivalent -- must NOT pass the
   * caller-side ALL test. If this assertion is ever "fixed" to {@code isTrue()}, the caller-side
   * predicate has been silently collapsed onto the target-side one and the gate is vacuous.
   */
  @Test
  void should_returnFalse_when_isFullyAdminEquivalentGivenCallerHoldsOnlyUserWrite() {
    assertThat(RbacAdminEquivalence.isFullyAdminEquivalent("CUSTOM", List.of("user:write")))
        .isFalse();
  }

  @Test
  void should_returnFalse_when_isFullyAdminEquivalentGivenNonAdminNameAndExactlyTwoDangerousPermissions() {
    assertThat(
            RbacAdminEquivalence.isFullyAdminEquivalent(
                "CUSTOM", Arrays.asList("role:write", "user:write")))
        .isFalse();
  }

  @Test
  void should_returnTrue_when_isFullyAdminEquivalentGivenNonAdminNameAndAllThreeDangerousPermissionsCaseVariants() {
    assertThat(
            RbacAdminEquivalence.isFullyAdminEquivalent(
                "CUSTOM", Arrays.asList("Role:Write", "USER:write", "tenant:WRITE")))
        .isTrue();
  }

  @Test
  void should_returnFalse_when_isFullyAdminEquivalentGivenNonAdminNameAndNoPermissions() {
    assertThat(RbacAdminEquivalence.isFullyAdminEquivalent("CUSTOM", List.of("user:read")))
        .isFalse();
  }

  @Test
  void should_returnFalse_when_isFullyAdminEquivalentGivenNonAdminNameAndNullPermissionCollection() {
    assertThat(RbacAdminEquivalence.isFullyAdminEquivalent("CUSTOM", null)).isFalse();
  }

  @Test
  void should_returnFalse_when_isFullyAdminEquivalentGivenNonAdminNameAndEmptyPermissionCollection() {
    assertThat(RbacAdminEquivalence.isFullyAdminEquivalent("CUSTOM", List.of())).isFalse();
  }
}
