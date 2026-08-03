package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link DuplicateRoleAssignmentException}: verifies the fixed static code/message
 * pair and that repeated construction never varies (T-T7 security fix — no constructor accepts a
 * message or cause, so a MySQL constraint-violation message can never leak the constraint name,
 * index name, or {@code active_key} hex fragment into the client-visible response).
 */
@Tag("UnitTest")
class DuplicateRoleAssignmentExceptionTest {

  /**
   * Verifies that code() returns the fixed literal.
   *
   * <p>Given: DuplicateRoleAssignmentException constructed via its no-arg constructor
   * When: code() accessed
   * Then: returns the fixed literal "RBAC_004"
   */
  @Test
  void should_returnFixedCode_when_constructed() {
    DuplicateRoleAssignmentException ex = new DuplicateRoleAssignmentException();

    assertThat(ex.code()).isEqualTo("RBAC_004");
  }

  /**
   * Verifies that getMessage() returns the fixed literal, never DB-supplied text.
   *
   * <p>Given: DuplicateRoleAssignmentException constructed via its no-arg constructor
   * When: getMessage() called
   * Then: returns the fixed literal message
   */
  @Test
  void should_returnFixedMessage_when_constructed() {
    DuplicateRoleAssignmentException ex = new DuplicateRoleAssignmentException();

    assertThat(ex.getMessage()).isEqualTo("This user already actively holds this role");
  }

  /**
   * Verifies that code and message are identical across independent instances, proving there is
   * no hidden message-parameterizing constructor.
   *
   * <p>Given: two independently constructed DuplicateRoleAssignmentException instances
   * When: code() and getMessage() compared
   * Then: both are identical across instances
   */
  @Test
  void should_returnSameCodeAndMessage_when_constructedRepeatedly() {
    DuplicateRoleAssignmentException first = new DuplicateRoleAssignmentException();
    DuplicateRoleAssignmentException second = new DuplicateRoleAssignmentException();

    assertThat(first.code()).isEqualTo(second.code());
    assertThat(first.getMessage()).isEqualTo(second.getMessage());
  }

  /**
   * Verifies that DuplicateRoleAssignmentException is a ConflictException, so it maps to HTTP 409
   * via the existing generic handler with no new handler code required.
   *
   * <p>Given: DuplicateRoleAssignmentException instance
   * When: checked with instanceof
   * Then: is an instance of ConflictException and DomainException
   */
  @Test
  void should_extendConflictException_when_checkedForType() {
    DuplicateRoleAssignmentException ex = new DuplicateRoleAssignmentException();

    assertThat(ex).isInstanceOf(ConflictException.class).isInstanceOf(DomainException.class);
  }
}
