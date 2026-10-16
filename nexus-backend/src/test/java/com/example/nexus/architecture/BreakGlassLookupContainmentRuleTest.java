package com.example.nexus.architecture;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.identity.infrastructure.persistence.BreakGlassGrantLookupAdapter;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Proves the two US-018 M5 security-review L-3 rules fire (and only on what they should). The
 * failing fixtures are nested classes of this test: they sit outside every {@code @SpringBootTest}
 * component scan and outside the production ArchUnit import ({@code DoNotIncludeTests}), so they
 * never trip {@link HexagonalArchitectureTest}.
 */
@Tag("UnitTest")
class BreakGlassLookupContainmentRuleTest {

  // ── BREAK_GLASS_GRANT_LOOKUP_PORT_IS_CONTAINED ──────────────────────────────────────────

  @Test
  void should_failPortRule_when_anotherClassHoldsThePort() {
    JavaClasses fixture = new ClassFileImporter().importClasses(PortConsumerFixture.class);

    assertThatThrownBy(
            () -> ArchitectureRules.BREAK_GLASS_GRANT_LOOKUP_PORT_IS_CONTAINED.check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(PortConsumerFixture.class.getName());
  }

  @Test
  void should_failPortRule_when_anotherClassImplementsThePort() {
    JavaClasses fixture = new ClassFileImporter().importClasses(SecondAdapterFixture.class);

    assertThatThrownBy(
            () -> ArchitectureRules.BREAK_GLASS_GRANT_LOOKUP_PORT_IS_CONTAINED.check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(SecondAdapterFixture.class.getName());
  }

  @Test
  void should_passPortRule_when_onlyTheServiceAndItsAdapterTouchThePort() {
    JavaClasses production =
        new ClassFileImporter()
            .importClasses(
                BootstrapAdminService.class,
                BreakGlassGrantLookupAdapter.class,
                BreakGlassGrantLookupPort.class);

    assertThatCode(
            () -> ArchitectureRules.BREAK_GLASS_GRANT_LOOKUP_PORT_IS_CONTAINED.check(production))
        .doesNotThrowAnyException();
  }

  // ── GLOBAL_BREAK_GLASS_REPLAY_QUERY_IS_CALLED_ONLY_BY_ITS_ADAPTER ───────────────────────

  @Test
  void should_failQueryRule_when_anotherClassCallsTheGlobalQueryDirectly() {
    JavaClasses fixture = new ClassFileImporter().importClasses(RepositoryCallerFixture.class);

    assertThatThrownBy(
            () ->
                ArchitectureRules.GLOBAL_BREAK_GLASS_REPLAY_QUERY_IS_CALLED_ONLY_BY_ITS_ADAPTER
                    .check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(RepositoryCallerFixture.class.getName());
  }

  @Test
  void should_passQueryRule_when_anotherClassCallsADifferentRepositoryMethod() {
    JavaClasses fixture =
        new ClassFileImporter().importClasses(OtherRepositoryMethodCallerFixture.class);

    assertThatCode(
            () ->
                ArchitectureRules.GLOBAL_BREAK_GLASS_REPLAY_QUERY_IS_CALLED_ONLY_BY_ITS_ADAPTER
                    .check(fixture))
        .doesNotThrowAnyException();
  }

  @Test
  void should_passQueryRule_when_onlyTheAdapterCallsTheGlobalQuery() {
    JavaClasses adapter = new ClassFileImporter().importClasses(BreakGlassGrantLookupAdapter.class);

    assertThatCode(
            () ->
                ArchitectureRules.GLOBAL_BREAK_GLASS_REPLAY_QUERY_IS_CALLED_ONLY_BY_ITS_ADAPTER
                    .check(adapter))
        .doesNotThrowAnyException();
  }

  /** A consumer of the cross-tenant lookup that is not the break-glass service. */
  static class PortConsumerFixture {

    private final BreakGlassGrantLookupPort port;

    PortConsumerFixture(BreakGlassGrantLookupPort port) {
      this.port = port;
    }

    boolean oracle(String changeRef) {
      return port.existsSuccessfulGrantWithChangeRef(changeRef);
    }
  }

  /** A second implementation of the port. */
  static class SecondAdapterFixture implements BreakGlassGrantLookupPort {

    @Override
    public boolean existsSuccessfulGrantWithChangeRef(String changeRef) {
      return false;
    }
  }

  /** Bypasses the port by calling the unscoped repository query itself. */
  static class RepositoryCallerFixture {

    private final JpaAuthEventRepository repository;

    RepositoryCallerFixture(JpaAuthEventRepository repository) {
      this.repository = repository;
    }

    boolean oracle(String changeRef) {
      return repository.existsSuccessfulBreakGlassGrantWithChangeRef(changeRef) != 0;
    }
  }

  /** Uses the same repository for something else: not the oracle, must stay allowed. */
  static class OtherRepositoryMethodCallerFixture {

    private final JpaAuthEventRepository repository;

    OtherRepositoryMethodCallerFixture(JpaAuthEventRepository repository) {
      this.repository = repository;
    }

    long count() {
      return repository.count();
    }
  }
}
