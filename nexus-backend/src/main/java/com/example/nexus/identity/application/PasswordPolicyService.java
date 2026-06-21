package com.example.nexus.identity.application;

import com.example.nexus.common.domain.FieldValidationException;
import java.util.Set;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

/**
 * Enforces the application password policy: minimum length and breach-denylist check.
 *
 * <p>Throws {@link FieldValidationException} with code {@code AUTH_PWD_001} and field
 * {@code password} on any violation. A single error code is used for all failure modes to
 * avoid revealing which specific rule was violated.
 *
 * <p>Length is measured in Java {@link String#length()} units (UTF-16 code units). For the
 * BMP, this equals the number of characters. Supplementary-plane characters (code points ≥
 * U+10000) count as 2 units each — callers should be aware when accepting emoji passwords.
 */
@Service
public class PasswordPolicyService {

  static final int MIN_LENGTH = 12;
  private static final String CODE = "AUTH_PWD_001";
  private static final String MESSAGE =
      "Password must be at least 12 characters and must not be a commonly used password.";

  private final Set<String> commonPasswordSet;

  public PasswordPolicyService(
      @Qualifier("commonPasswordSet") Set<String> commonPasswordSet) {
    this.commonPasswordSet = Set.copyOf(commonPasswordSet);
  }

  /**
   * Validates {@code rawPassword} against the password policy.
   *
   * @param rawPassword the plaintext password supplied by the user
   * @throws FieldValidationException with code {@code AUTH_PWD_001} if the password is
   *     {@code null}, shorter than {@value MIN_LENGTH} characters, or present in the
   *     common-password denylist
   */
  public void validate(String rawPassword) {
    if (rawPassword == null || rawPassword.length() < MIN_LENGTH) {
      throw new FieldValidationException(CODE, "password", MESSAGE);
    }
    if (commonPasswordSet.contains(rawPassword)) {
      throw new FieldValidationException(CODE, "password", MESSAGE);
    }
  }
}
