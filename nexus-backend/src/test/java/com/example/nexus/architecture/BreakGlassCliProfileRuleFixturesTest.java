package com.example.nexus.architecture;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

/**
 * Proves the US-018 A7 profile rule in {@link HexagonalArchitectureTest} fires (T-008 (e)): the
 * rule is pointed at this package, and each fixture is a bean that does or does not satisfy it.
 * Static nested classes, for the reason given on {@code AccessMarkerRuleFixturesTest}.
 */
@Tag("UnitTest")
class BreakGlassCliProfileRuleFixturesTest {

  private static final ArchRule RULE =
      HexagonalArchitectureTest.cliBeansMustBeProfileGatedToBreakGlass("..architecture..");

  private static JavaClasses fixture(Class<?> type) {
    return new ClassFileImporter().importClasses(type);
  }

  @Test
  void should_fail_when_cliBeanHasNoProfile() {
    assertThatThrownBy(() -> RULE.check(fixture(UnprofiledBean.class)))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UnprofiledBean.class.getName());
  }

  @Test
  void should_fail_when_cliBeanIsAlsoActiveInAnotherProfile() {
    assertThatThrownBy(() -> RULE.check(fixture(SharedProfileBean.class)))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(SharedProfileBean.class.getName());
  }

  @Test
  void should_fail_when_cliBeanProfileIsANegatedExpression() {
    assertThatThrownBy(() -> RULE.check(fixture(NegatedProfileBean.class)))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(NegatedProfileBean.class.getName());
  }

  @Test
  void should_fail_when_cliBeanIsAMetaAnnotatedComponent() {
    assertThatThrownBy(() -> RULE.check(fixture(UnprofiledServiceBean.class)))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UnprofiledServiceBean.class.getName());
  }

  @Test
  void should_pass_when_cliBeanIsGatedToBreakGlassOnly() {
    assertThatCode(() -> RULE.check(fixture(GatedBean.class))).doesNotThrowAnyException();
  }

  @Component
  static class UnprofiledBean {}

  @Service
  static class UnprofiledServiceBean {}

  @Component
  @Profile({"break-glass", "dev"})
  static class SharedProfileBean {}

  @Component
  @Profile("!prod")
  static class NegatedProfileBean {}

  @Component
  @Profile("break-glass")
  static class GatedBean {}
}
