package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.common.domain.FieldValidationException;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PasswordPolicyServiceTest {

  private static final String DENYLIST_ENTRY = "Password123!";
  private static final Set<String> DENYLIST = Set.of(DENYLIST_ENTRY);

  private final PasswordPolicyService service = new PasswordPolicyService(DENYLIST);

  @Test
  void validate_throws_AUTH_PWD_001_when_null() {
    assertThatThrownBy(() -> service.validate(null))
        .isInstanceOf(FieldValidationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_PWD_001");
  }

  @Test
  void validate_throws_AUTH_PWD_001_when_tooShort() {
    assertThatThrownBy(() -> service.validate("Ab1!Ab1!Ab1"))
        .isInstanceOf(FieldValidationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_PWD_001");
  }

  @Test
  void validate_passes_when_12Chars() {
    assertThatCode(() -> service.validate("Ab1!Ab1!Ab1!")).doesNotThrowAnyException();
  }

  @Test
  void validate_throws_AUTH_PWD_002_when_commonPassword() {
    assertThatThrownBy(() -> service.validate(DENYLIST_ENTRY))
        .isInstanceOf(FieldValidationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_PWD_002");
  }

  @Test
  void validate_passes_when_notInDenylist12Chars() {
    assertThatCode(() -> service.validate("xK9#mP2@qL7^")).doesNotThrowAnyException();
  }

  @Test
  void validate_passes_when_1024Chars() {
    String maxPassword = "aB1!".repeat(256); // 1024 chars
    assertThatCode(() -> service.validate(maxPassword)).doesNotThrowAnyException();
  }

  @Test
  void validate_throws_AUTH_PWD_001_when_11UnicodeChars() {
    // "ñ".length() == 1 (single UTF-16 code unit); 11 such chars → below minimum
    assertThatThrownBy(() -> service.validate("ñ".repeat(11)))
        .isInstanceOf(FieldValidationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_PWD_001");
  }

  @Test
  void validate_passes_when_12UnicodeChars() {
    assertThatCode(() -> service.validate("ñ".repeat(12))).doesNotThrowAnyException();
  }

  @Test
  void validate_throws_AUTH_PWD_001_when_emptyString() {
    assertThatThrownBy(() -> service.validate(""))
        .isInstanceOf(FieldValidationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_PWD_001");
  }

  @Test
  void validate_passes_when_exactly1025Chars() {
    // One character beyond 1024 — ensures there is no artificial upper-bound check
    String longPassword = "aB1!".repeat(256) + "x"; // 1025 chars
    assertThatCode(() -> service.validate(longPassword)).doesNotThrowAnyException();
  }
}
