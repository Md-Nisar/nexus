package com.example.nexus.architecture;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
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

  // M5 M-1: the service and the break-glass-only ports must be gated to break-glass exactly.
  private static final ArchRule SERVICE_RULE =
      HexagonalArchitectureTest.break_glass_only_beans_must_be_profile_gated_to_break_glass;

  @Test
  void should_passServiceProfileRule_when_bootstrapAdminServiceCarriesTheBreakGlassProfile() {
    assertThatCode(() -> SERVICE_RULE.check(fixture(BootstrapAdminService.class)))
        .doesNotThrowAnyException();
  }

  @Test
  void should_failServiceProfileRule_when_aBootstrapAdminServiceSubclassHasNoProfile() {
    assertThatThrownBy(() -> SERVICE_RULE.check(fixture(UnprofiledServiceSubclass.class)))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UnprofiledServiceSubclass.class.getName());
  }

  @Test
  void should_failServiceProfileRule_when_aBreakGlassPortImplementationHasNoProfile() {
    assertThatThrownBy(() -> SERVICE_RULE.check(fixture(UnprofiledAlertAdapter.class)))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UnprofiledAlertAdapter.class.getName());
  }

  @Test
  void should_passServiceProfileRule_when_aBreakGlassPortImplementationIsGated() {
    assertThatCode(() -> SERVICE_RULE.check(fixture(GatedAlertAdapter.class)))
        .doesNotThrowAnyException();
  }

  static class UnprofiledServiceSubclass extends BootstrapAdminService {
    UnprofiledServiceSubclass() {
      super(null, null, null, null, null, null);
    }
  }

  @Component
  static class UnprofiledAlertAdapter implements BreakGlassAlertPort {
    @Override
    public void raise(BreakGlassAlert alert) {}
  }

  @Component
  @Profile("break-glass")
  static class GatedAlertAdapter implements BreakGlassAlertPort {
    @Override
    public void raise(BreakGlassAlert alert) {}
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
