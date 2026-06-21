package com.example.nexus.identity.infrastructure.security;

import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

/**
 * Wires the Argon2id password encoder and the {@link PasswordHasherPort} adapter bean.
 *
 * <p>{@link EnableAsync} is declared here (exactly once) to activate {@code @Async} processing
 * for {@code MailEventListener}'s {@code @TransactionalEventListener(AFTER_COMMIT)} methods.
 *
 * <p>Encoder parameters come from {@code nexus.identity.argon2.*} properties.
 * OWASP 2023 production minimums are the defaults in {@code application.yml}; lower values
 * in {@code application-dev.yml} keep local iteration fast.
 */
@Configuration
@EnableAsync
public class PasswordEncoderConfig {

  /**
   * Creates an Argon2id encoder with tenant-configured parameters.
   *
   * <p>Salt length (16 bytes) and hash length (32 bytes) are fixed constants consistent with
   * OWASP 2023 guidance; only memory, iterations, and parallelism are tunable via config.
   */
  @Bean
  public Argon2PasswordEncoder argon2PasswordEncoder(
      @Value("${nexus.identity.argon2.memory-kb}") int memoryKb,
      @Value("${nexus.identity.argon2.iterations}") int iterations,
      @Value("${nexus.identity.argon2.parallelism}") int parallelism) {
    return new Argon2PasswordEncoder(16, 32, parallelism, memoryKb, iterations);
  }

  /**
   * Exposes the encoder as a {@link PasswordHasherPort} so application-layer services depend
   * only on the port interface, not on the Spring Security type.
   */
  @Bean
  public PasswordHasherPort passwordHasherPort(Argon2PasswordEncoder encoder) {
    return encoder::encode;
  }
}
