package com.example.nexus.architecture;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.common.security.Permissions;
import com.example.nexus.rbac.interfaces.rest.PermissionController;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Proves the US-019 RC-63(k) rule fires. The failing fixtures are nested classes of this test, so
 * they sit outside the production ArchUnit import ({@code DoNotIncludeTests}).
 */
@Tag("UnitTest")
class SensitivitySetsContainmentRuleTest {

  @Test
  void should_fail_when_anotherClassReadsTheSensitiveSet() {
    JavaClasses fixture = new ClassFileImporter().importClasses(SensitiveReaderFixture.class);

    assertThatThrownBy(
            () ->
                ArchitectureRules.SENSITIVITY_SETS_ARE_READ_ONLY_BY_THE_RESPONSE_MAPPER.check(
                    fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(SensitiveReaderFixture.class.getName());
  }

  @Test
  void should_fail_when_anotherClassReadsTheNonSensitiveSet() {
    JavaClasses fixture = new ClassFileImporter().importClasses(NonSensitiveReaderFixture.class);

    assertThatThrownBy(
            () ->
                ArchitectureRules.SENSITIVITY_SETS_ARE_READ_ONLY_BY_THE_RESPONSE_MAPPER.check(
                    fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(NonSensitiveReaderFixture.class.getName());
  }

  @Test
  void should_pass_when_anotherClassReadsOnlyTheFullCatalogue() {
    JavaClasses fixture = new ClassFileImporter().importClasses(CatalogueReaderFixture.class);

    assertThatCode(
            () ->
                ArchitectureRules.SENSITIVITY_SETS_ARE_READ_ONLY_BY_THE_RESPONSE_MAPPER.check(
                    fixture))
        .doesNotThrowAnyException();
  }

  @Test
  void should_pass_when_onlyTheResponseMapperReadsTheSets() {
    JavaClasses mapper = new ClassFileImporter().importClasses(PermissionController.class);

    assertThatCode(
            () ->
                ArchitectureRules.SENSITIVITY_SETS_ARE_READ_ONLY_BY_THE_RESPONSE_MAPPER.check(
                    mapper))
        .doesNotThrowAnyException();
  }

  /** A server-side rule that would let a UX hint drive an authorization decision. */
  static class SensitiveReaderFixture {
    boolean deny(String permission) {
      return Permissions.SENSITIVE.contains(permission);
    }
  }

  static class NonSensitiveReaderFixture {
    boolean allow(String permission) {
      return Permissions.NON_SENSITIVE.contains(permission);
    }
  }

  static class CatalogueReaderFixture {
    boolean known(String permission) {
      return Permissions.ALL.contains(permission);
    }
  }
}
