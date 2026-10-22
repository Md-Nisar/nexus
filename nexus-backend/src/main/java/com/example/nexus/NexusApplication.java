package com.example.nexus;

import com.example.nexus.common.Profiles;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Main entry point for the Nexus application.
 */
@SpringBootApplication
public class NexusApplication {

  /**
   * Starts the Spring Boot application. Under the {@code break-glass} profile (US-018 A7) the
   * runner has already run when {@code run} returns, so the process exits with its code.
   *
   * @param args command-line arguments
   */
  public static void main(String[] args) {
    ConfigurableApplicationContext context = SpringApplication.run(NexusApplication.class, args);
    if (context.getEnvironment().matchesProfiles(Profiles.BREAK_GLASS)) {
      System.exit(SpringApplication.exit(context));
    }
  }
}