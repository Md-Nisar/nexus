package com.example.nexus.architecture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.identity.infrastructure.persistence.JpaUserDirectoryQueryAdapter;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * US-019 RC-61.2: proves the containment rule on the unscoped {@code JpaUserRepository#countByIdIn}
 * fires on another caller and passes for its adapter, and pins the "count only" condition of the
 * Security sign-off. The failing fixture is a nested class of this test, outside the production
 * ArchUnit import ({@code DoNotIncludeTests}).
 */
@Tag("UnitTest")
class DirectoryUserCountContainmentRuleTest {

  @Test
  void should_fail_when_anotherClassCallsTheUnscopedCount() {
    JavaClasses fixture = new ClassFileImporter().importClasses(CountCallerFixture.class);

    assertThatThrownBy(
            () ->
                ArchitectureRules.UNSCOPED_USER_COUNT_IS_CALLED_ONLY_BY_THE_DIRECTORY_ADAPTER.check(
                    fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(CountCallerFixture.class.getName());
  }

  @Test
  void should_pass_when_anotherClassCallsADifferentRepositoryMethod() {
    JavaClasses fixture = new ClassFileImporter().importClasses(OtherMethodCallerFixture.class);

    assertThatCode(
            () ->
                ArchitectureRules.UNSCOPED_USER_COUNT_IS_CALLED_ONLY_BY_THE_DIRECTORY_ADAPTER.check(
                    fixture))
        .doesNotThrowAnyException();
  }

  @Test
  void should_pass_when_onlyTheDirectoryAdapterCallsTheUnscopedCount() {
    JavaClasses adapter =
        new ClassFileImporter().importClasses(JpaUserDirectoryQueryAdapter.class);

    assertThatCode(
            () ->
                ArchitectureRules.UNSCOPED_USER_COUNT_IS_CALLED_ONLY_BY_THE_DIRECTORY_ADAPTER.check(
                    adapter))
        .doesNotThrowAnyException();
  }

  @Test
  void should_returnOnlyACount_when_theUnscopedMethodIsDeclared() throws NoSuchMethodException {
    assertThat(JpaUserRepository.class.getMethod("countByIdIn", Collection.class).getReturnType())
        .as("RC-61.2 sign-off condition 1: count only, never rows")
        .isEqualTo(long.class);
  }

  /** Reaches the unscoped count without going through the directory adapter. */
  static class CountCallerFixture {

    private final JpaUserRepository repository;

    CountCallerFixture(JpaUserRepository repository) {
      this.repository = repository;
    }

    long oracle(UUID id) {
      return repository.countByIdIn(List.of(id));
    }
  }

  /** Uses the same repository for something else: must stay allowed. */
  static class OtherMethodCallerFixture {

    private final JpaUserRepository repository;

    OtherMethodCallerFixture(JpaUserRepository repository) {
      this.repository = repository;
    }

    long count() {
      return repository.count();
    }
  }
}
