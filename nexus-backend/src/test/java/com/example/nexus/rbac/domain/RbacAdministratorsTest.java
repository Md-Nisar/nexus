package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * MC-1 (US-018 03-design.md §2.1): the single "admin-defining" predicate. An empty catalogue must
 * fail closed, or every caller would be an administrator whenever {@code permissions} is
 * unreadable.
 */
@Tag("UnitTest")
class RbacAdministratorsTest {

  private static final UUID P1 = UUID.randomUUID();
  private static final UUID P2 = UUID.randomUUID();
  private static final UUID P3 = UUID.randomUUID();

  @Test
  void should_returnFalse_when_catalogueEmpty() {
    assertThat(RbacAdministrators.isAdminDefining(Set.of(P1, P2), Set.of())).isFalse();
  }

  @Test
  void should_returnFalse_when_catalogueEmptyAndRoleSetEmpty() {
    assertThat(RbacAdministrators.isAdminDefining(Set.of(), Set.of())).isFalse();
  }

  @Test
  void should_returnTrue_when_roleSetIsStrictSupersetOfCatalogue() {
    assertThat(RbacAdministrators.isAdminDefining(Set.of(P1, P2, P3), Set.of(P1, P2))).isTrue();
  }

  @Test
  void should_returnTrue_when_roleSetEqualsCatalogue() {
    assertThat(RbacAdministrators.isAdminDefining(Set.of(P1, P2, P3), Set.of(P1, P2, P3)))
        .isTrue();
  }

  @Test
  void should_returnFalse_when_roleSetOnePermissionShortOfCatalogue() {
    assertThat(RbacAdministrators.isAdminDefining(Set.of(P1, P2), Set.of(P1, P2, P3))).isFalse();
  }

  @Test
  void should_returnFalse_when_roleSetEmptyAndCatalogueNonEmpty() {
    assertThat(RbacAdministrators.isAdminDefining(Set.of(), Set.of(P1))).isFalse();
  }
}
