package com.example.nexus.identity.infrastructure.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

/**
 * Loads the common-password denylist from the classpath at startup and exposes it as a
 * {@code Set<String>} bean injected into {@link com.example.nexus.identity.application.PasswordPolicyService}.
 *
 * <p>Fails fast with {@link IllegalStateException} if the denylist file is absent — a missing
 * file is a deployment error, not a recoverable runtime condition.
 */
@Configuration
public class PasswordPolicyConfig {

  /**
   * Returns an immutable set of common passwords loaded from
   * {@code classpath:security/common-passwords.txt}.
   */
  @Bean
  @Qualifier("commonPasswordSet")
  public Set<String> commonPasswordSet() {
    return load("security/common-passwords.txt");
  }

  /**
   * Package-private to allow direct testing without a Spring context.
   *
   * @param classpathPath path relative to the classpath root
   * @return immutable set of non-blank lines from the file
   * @throws IllegalStateException if the file does not exist or cannot be read
   */
  static Set<String> load(String classpathPath) {
    ClassPathResource resource = new ClassPathResource(classpathPath);
    if (!resource.exists()) {
      throw new IllegalStateException(
          "Common password denylist not found at classpath:" + classpathPath
              + "; add the file to src/main/resources/" + classpathPath);
    }
    try (BufferedReader reader =
        new BufferedReader(
            new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
      return reader.lines()
          .filter(Predicate.not(String::isBlank))
          .collect(Collectors.toUnmodifiableSet());
    } catch (IOException e) {
      throw new IllegalStateException(
          "Failed to load common-password denylist from classpath:" + classpathPath, e);
    }
  }
}
