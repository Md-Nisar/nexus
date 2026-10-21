package com.example.nexus.identity.infrastructure.seed;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * US-019 T-023 (RC-63(g), R17, T-E52): in a context whose active profiles include {@code prod} or
 * {@code break-glass}, no dev seed bean is registered, so known-password administrators can never
 * be created there. Each case is a real Spring context evaluating the {@code @Profile}
 * expressions; the seeders' collaborators are deliberately absent, because a bean that is wrongly
 * registered would fail context startup as well as be found.
 */
@Tag("UnitTest")
class DevSeedProfileGuardTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withUserConfiguration(DevDataInitializer.class, DevUserSeeder.class, DevRbacSeeder.class);

  @ParameterizedTest
  @ValueSource(strings = {"prod", "dev,break-glass", "dev,prod", "break-glass"})
  void should_registerNoSeederBean_when_prodOrBreakGlassProfileActive(String profiles) {
    runner
        .withPropertyValues("spring.profiles.active=" + profiles)
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context).doesNotHaveBean(DevDataInitializer.class);
              assertThat(context).doesNotHaveBean(DevUserSeeder.class);
              assertThat(context).doesNotHaveBean(DevRbacSeeder.class);
            });
  }
}
