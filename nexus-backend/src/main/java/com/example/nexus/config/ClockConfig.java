package com.example.nexus.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Registers the application-wide {@link Clock} bean. Use UTC in production and mock in tests. */
@Configuration(proxyBeanMethods = false)
public class ClockConfig {

  @Bean
  public Clock systemClock() {
    return Clock.systemUTC();
  }
}
