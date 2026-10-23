package com.example.nexus.common.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * B5 Test 1 (US-018 T-022, TS-13, FR-B5.a): every {@code @RequiresPermission} value on the
 * production classpath is a member of {@link Permissions#ALL}. Constants are inlined into the
 * annotation at compile time, so the check reads annotation <b>values</b> from the class files, not
 * references.
 */
@Tag("UnitTest")
class PermissionsCatalogueTest {

  @Test
  void should_findOnlyCatalogueNames_when_scanningProductionRequiresPermissionValues() {
    JavaClasses production =
        new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("com.example.nexus");

    List<String> values = requiredPermissionValues(production);

    assertThat(values).as("the scan must find the guarded handlers").isNotEmpty();
    assertThat(unknown(values)).isEmpty();
  }

  @Test
  void should_reportUnknownName_when_aHandlerUsesRolesReadInsteadOfRoleRead() {
    JavaClasses fixture = new ClassFileImporter().importClasses(WrongNameHandler.class);

    assertThat(unknown(requiredPermissionValues(fixture))).containsExactly("roles:read");
  }

  @Test
  void should_listAllNineCatalogueEntries_when_readingPermissionsAll() {
    assertThat(Permissions.ALL)
        .containsExactlyInAnyOrder(
            "tenant:read", "tenant:write", "user:read", "user:write", "role:read", "role:write",
            "audit:read", "user:role:assign", "user:directory:read");
  }

  @Test
  void should_partitionTheCatalogue_when_unioningSensitiveAndNonSensitive() {
    Set<String> union = new HashSet<>(Permissions.SENSITIVE);
    union.addAll(Permissions.NON_SENSITIVE);

    assertThat(union).isEqualTo(Permissions.ALL);
  }

  @Test
  void should_haveNoOverlap_when_intersectingSensitiveAndNonSensitive() {
    Set<String> intersection = new HashSet<>(Permissions.SENSITIVE);
    intersection.retainAll(Permissions.NON_SENSITIVE);

    assertThat(intersection).isEmpty();
  }

  @Test
  void should_classifyTheProposedDefaults_when_readingTheSets() {
    assertThat(Permissions.NON_SENSITIVE)
        .containsExactlyInAnyOrder("tenant:read", "user:read", "role:read");
  }

  private static List<String> requiredPermissionValues(JavaClasses classes) {
    List<String> values = new ArrayList<>();
    for (var javaClass : classes) {
      for (JavaMethod method : javaClass.getMethods()) {
        method
            .tryGetAnnotationOfType(RequiresPermission.class)
            .ifPresent(annotation -> values.add(annotation.value()));
      }
    }
    return values;
  }

  private static List<String> unknown(List<String> values) {
    return values.stream().filter(value -> !Permissions.ALL.contains(value)).toList();
  }

  /** Test-only handler with a name that is not in the catalogue. */
  static class WrongNameHandler {
    @RequiresPermission("roles:read")
    public void handle() {}
  }
}
