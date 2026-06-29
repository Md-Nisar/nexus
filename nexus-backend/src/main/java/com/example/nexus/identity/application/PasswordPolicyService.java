package com.example.nexus.identity.application;

import com.example.nexus.common.domain.FieldValidationException;
import java.util.Set;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

/**
 * Enforces the application password policy: minimum length and breach-denylist check.
 *
 * <p>Throws {@link FieldValidationException} with a failure-mode-specific error code and field
 * {@code password} on any violation:
 * <ul>
 *   <li>{@code AUTH_PWD_001} — password is {@code null} or shorter than {@value MIN_LENGTH}
 *       characters.</li>
 *   <li>{@code AUTH_PWD_002} — password is present in the common-password denylist.</li>
 * </ul>
 *
 * <p>Length is measured in Java {@link String#length()} units (UTF-16 code units). For the
 * BMP, this equals the number of characters. Supplementary-plane characters (code points ≥
 * U+10000) count as 2 units each — callers should be aware when accepting emoji passwords.
 */
@Service
public class PasswordPolicyService {

  static final int MIN_LENGTH = 12;

  // Stable public API error codes — clients may depend on these values; do not rename.
  private static final String CODE_LENGTH   = "AUTH_PWD_001";
  private static final String CODE_DENYLIST = "AUTH_PWD_002";

  private static final String MSG_LENGTH  = "Password must be at least 12 characters.";
  private static final String MSG_DENYLIST =
      "Password is too common. Choose a less predictable password.";

  private final Set<String> commonPasswordSet;

  public PasswordPolicyService(
      @Qualifier("commonPasswordSet") Set<String> commonPasswordSet) {
    this.commonPasswordSet = Set.copyOf(commonPasswordSet);
  }

  /**
   * Validates {@code rawPassword} against the password policy.
   *
   * <p>Checks are applied in order: length first, denylist second. The first failing check
   * raises a {@link FieldValidationException}; subsequent checks are not evaluated.
   *
   * <p><strong>Denylist limitation:</strong> The breach check is an exact case-sensitive match
   * against the loaded common-password set ({@code Set.contains}). Trivial mutations such as
   * capitalisation, appended digits, or leetspeak substitutions are NOT detected. Normalization
   * (case-fold and leet-collapse) is out of scope for this implementation.
   *
   * @param rawPassword the plaintext password supplied by the user
   * @throws FieldValidationException with code {@code AUTH_PWD_001} if the password is
   *     {@code null} or shorter than {@value MIN_LENGTH} characters
   * @throws FieldValidationException with code {@code AUTH_PWD_002} if the password is present
   *     in the common-password denylist
   */
  public void validate(String rawPassword) {
    if (rawPassword == null || rawPassword.length() < MIN_LENGTH) {
      throw new FieldValidationException(CODE_LENGTH, "password", MSG_LENGTH);
    }
    if (commonPasswordSet.contains(rawPassword)) {
      throw new FieldValidationException(CODE_DENYLIST, "password", MSG_DENYLIST);
    }
  }
}
