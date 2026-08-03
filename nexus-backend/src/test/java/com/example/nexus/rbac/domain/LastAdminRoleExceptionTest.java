package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link LastAdminRoleException}: verifies the fixed static code/message pair and
 * that repeated construction never varies (T-T7 security fix — no constructor accepts a message
 * or cause, so no DB-supplied text can ever reach the client-visible response).
 */
@Tag("UnitTest")
class LastAdminRoleExceptionTest {

  /**
   * Verifies that code() returns the fixed literal.
   *
   * <p>Given: LastAdminRoleException constructed via its no-arg constructor
   * When: code() accessed
   * Then: returns the fixed literal "RBAC_002"
   */
  @Test
  void should_returnFixedCode_when_constructed() {
    LastAdminRoleException ex = new LastAdminRoleException();

    assertThat(ex.code()).isEqualTo("RBAC_002");
  }

  /**
   * Verifies that getMessage() returns the fixed literal, never DB-supplied text.
   *
   * <p>Given: LastAdminRoleException constructed via its no-arg constructor
   * When: getMessage() called
   * Then: returns the fixed literal message
   */
  @Test
  void should_returnFixedMessage_when_constructed() {
    LastAdminRoleException ex = new LastAdminRoleException();

    assertThat(ex.getMessage())
        .isEqualTo("Cannot revoke the last active TENANT_ADMIN assignment in this tenant");
  }

  /**
   * Verifies that code and message are identical across independent instances, proving there is
   * no hidden message-parameterizing constructor.
   *
   * <p>Given: two independently constructed LastAdminRoleException instances
   * When: code() and getMessage() compared
   * Then: both are identical across instances
   */
  @Test
  void should_returnSameCodeAndMessage_when_constructedRepeatedly() {
    LastAdminRoleException first = new LastAdminRoleException();
    LastAdminRoleException second = new LastAdminRoleException();

    assertThat(first.code()).isEqualTo(second.code());
    assertThat(first.getMessage()).isEqualTo(second.getMessage());
  }

  /**
   * Verifies that LastAdminRoleException is a ConflictException, so it maps to HTTP 409 via the
   * existing generic handler with no new handler code required.
   *
   * <p>Given: LastAdminRoleException instance
   * When: checked with instanceof
   * Then: is an instance of ConflictException and DomainException
   */
  @Test
  void should_extendConflictException_when_checkedForType() {
    LastAdminRoleException ex = new LastAdminRoleException();

    assertThat(ex).isInstanceOf(ConflictException.class).isInstanceOf(DomainException.class);
  }
}
