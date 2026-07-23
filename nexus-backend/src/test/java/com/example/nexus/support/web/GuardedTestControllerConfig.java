package com.example.nexus.support.web;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * Registers {@link GuardedTestController} into a test's {@code ApplicationContext} via an
 * explicit {@code @Bean} method — never {@code @ComponentScan} — mirroring the established
 * {@code TestcontainersConfiguration} pattern. Import this into a test class with
 * {@code @Import(GuardedTestControllerConfig.class)} (see T-013/T-014).
 */
@TestConfiguration(proxyBeanMethods = false)
public class GuardedTestControllerConfig {

  @Bean
  public GuardedTestController guardedTestController() {
    return new GuardedTestController();
  }
}
