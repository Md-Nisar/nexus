package com.example.nexus.architecture;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.identity.application.UserDirectoryService;
import com.example.nexus.identity.application.port.out.UserDirectoryQueryPort;
import com.example.nexus.identity.infrastructure.persistence.JpaUserDirectoryQueryAdapter;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * US-019 review R2-3: {@code existsById} on the users table is unscoped by tenant, like {@code
 * countByIdIn}, so it is contained the same way. The port's {@code existsById} may be called only by
 * {@link UserDirectoryService} (a by-id miss, never in a response), and the repository's only by
 * {@link JpaUserDirectoryQueryAdapter}. The failing fixtures are nested classes of this test,
 * outside the production ArchUnit import ({@code DoNotIncludeTests}).
 */
@Tag("UnitTest")
class DirectoryUserExistenceContainmentRuleTest {

  @Test
  void should_fail_when_anotherClassCallsThePortsExistsById() {
    JavaClasses fixture = new ClassFileImporter().importClasses(PortCallerFixture.class);

    assertThatThrownBy(
            () ->
                ArchitectureRules.UNSCOPED_USER_EXISTENCE_PROBE_IS_CALLED_ONLY_BY_THE_DIRECTORY_SERVICE
                    .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(PortCallerFixture.class.getName());
  }

  @Test
  void should_pass_when_onlyTheDirectoryServiceCallsThePortsExistsById() {
    JavaClasses service = new ClassFileImporter().importClasses(UserDirectoryService.class);

    assertThatCode(
            () ->
                ArchitectureRules.UNSCOPED_USER_EXISTENCE_PROBE_IS_CALLED_ONLY_BY_THE_DIRECTORY_SERVICE
                    .check(service))
        .doesNotThrowAnyException();
  }

  @Test
  void should_fail_when_anotherClassCallsTheRepositorysExistsById() {
    JavaClasses fixture = new ClassFileImporter().importClasses(RepositoryCallerFixture.class);

    assertThatThrownBy(
            () ->
                ArchitectureRules.UNSCOPED_USER_EXISTS_BY_ID_IS_CALLED_ONLY_BY_THE_DIRECTORY_ADAPTER
                    .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(RepositoryCallerFixture.class.getName());
  }

  @Test
  void should_pass_when_onlyTheDirectoryAdapterCallsTheRepositorysExistsById() {
    JavaClasses adapter =
        new ClassFileImporter().importClasses(JpaUserDirectoryQueryAdapter.class);

    assertThatCode(
            () ->
                ArchitectureRules.UNSCOPED_USER_EXISTS_BY_ID_IS_CALLED_ONLY_BY_THE_DIRECTORY_ADAPTER
                    .check(adapter))
        .doesNotThrowAnyException();
  }

  /** Reaches the port's existence probe without being the directory service. */
  static class PortCallerFixture {

    private final UserDirectoryQueryPort port;

    PortCallerFixture(UserDirectoryQueryPort port) {
      this.port = port;
    }

    boolean oracle(UUID id) {
      return port.existsById(id);
    }
  }

  /** Reaches the repository's existence probe without being the directory adapter. */
  static class RepositoryCallerFixture {

    private final JpaUserRepository repository;

    RepositoryCallerFixture(JpaUserRepository repository) {
      this.repository = repository;
    }

    boolean oracle(UUID id) {
      return repository.existsById(id);
    }
  }
}
