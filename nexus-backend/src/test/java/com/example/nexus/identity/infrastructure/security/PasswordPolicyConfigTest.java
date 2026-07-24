package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class PasswordPolicyConfigTest {

  @Test
  void load_isNonEmpty_when_fileExists() {
    Set<String> set = PasswordPolicyConfig.load("security/common-passwords.txt");
    assertThat(set).isNotEmpty();
  }

  @Test
  void load_failsFast_when_fileNotFound() {
    assertThatThrownBy(() -> PasswordPolicyConfig.load("nonexistent/denylist.txt"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nonexistent/denylist.txt");
  }
}
