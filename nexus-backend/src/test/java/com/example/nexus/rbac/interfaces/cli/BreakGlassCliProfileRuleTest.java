package com.example.nexus.rbac.interfaces.cli;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.architecture.ArchitectureRules;
import com.example.nexus.common.Profiles;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

/**
 * Proves {@link ArchitectureRules#CLI_BEANS_ARE_BREAK_GLASS_PROFILE_ONLY} fires (US-018 T-008,
 * 03-design.md §7.2 Containment). The fixtures are nested classes of this test, so they sit in
 * {@code rbac.interfaces.cli}, outside every {@code @SpringBootTest} component scan and outside
 * the production ArchUnit import.
 */
@Tag("UnitTest")
class BreakGlassCliProfileRuleTest {

  @Test
  void should_failRule_when_cliComponentHasNoProfile() {
    JavaClasses fixture = new ClassFileImporter().importClasses(UnprofiledCliComponent.class);

    assertThatThrownBy(() -> ArchitectureRules.CLI_BEANS_ARE_BREAK_GLASS_PROFILE_ONLY.check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(UnprofiledCliComponent.class.getName());
  }

  @Test
  void should_failRule_when_cliStereotypeBeanHasAnotherProfile() {
    JavaClasses fixture = new ClassFileImporter().importClasses(DevProfiledCliService.class);

    assertThatThrownBy(() -> ArchitectureRules.CLI_BEANS_ARE_BREAK_GLASS_PROFILE_ONLY.check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(DevProfiledCliService.class.getName());
  }

  @Test
  void should_failRule_when_cliComponentHasBreakGlassPlusAnotherProfile() {
    JavaClasses fixture = new ClassFileImporter().importClasses(WidenedProfileCliComponent.class);

    assertThatThrownBy(() -> ArchitectureRules.CLI_BEANS_ARE_BREAK_GLASS_PROFILE_ONLY.check(fixture))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(WidenedProfileCliComponent.class.getName());
  }

  @Test
  void should_failRule_when_noCliComponentIsImported() {
    JavaClasses fixture = new ClassFileImporter().importClasses(BootstrapAdminCliFixture.class);

    assertThatThrownBy(() -> ArchitectureRules.CLI_BEANS_ARE_BREAK_GLASS_PROFILE_ONLY.check(fixture))
        .isInstanceOf(AssertionError.class);
  }

  @Test
  void should_passRule_when_cliComponentIsTheBreakGlassRunner() {
    JavaClasses fixture = new ClassFileImporter().importClasses(BreakGlassAdminRunner.class);

    assertThatCode(() -> ArchitectureRules.CLI_BEANS_ARE_BREAK_GLASS_PROFILE_ONLY.check(fixture))
        .doesNotThrowAnyException();
  }

  /** A CLI bean that would load in every profile, including a serving pod. */
  @Component
  static class UnprofiledCliComponent {}

  /** A meta-annotated stereotype gated on a non-break-glass profile. */
  @Service
  @Profile(Profiles.DEV)
  static class DevProfiledCliService {}

  /** A CLI bean that also loads under {@code dev}. */
  @Component
  @Profile({Profiles.BREAK_GLASS, Profiles.DEV})
  static class WidenedProfileCliComponent {}
}
