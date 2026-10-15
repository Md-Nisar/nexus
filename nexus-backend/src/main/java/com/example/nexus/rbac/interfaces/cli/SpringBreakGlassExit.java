package com.example.nexus.rbac.interfaces.cli;

import com.example.nexus.common.Profiles;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Exits through {@link SpringApplication#exit}, so the context closes cleanly (and any {@code
 * ExitCodeGenerator} runs) before the JVM ends with the code (ADR-0025 1).
 */
@Component
@Profile(Profiles.BREAK_GLASS)
class SpringBreakGlassExit implements BreakGlassExit {

  private final ConfigurableApplicationContext context;

  SpringBreakGlassExit(ConfigurableApplicationContext context) {
    this.context = context;
  }

  @Override
  public void exit(int exitCode) {
    System.exit(SpringApplication.exit(context, () -> exitCode));
  }
}
