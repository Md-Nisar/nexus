package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@Tag("UnitTest")
class AuthEventTypeTest {

  private static final Set<AuthEventType> EXPECTED_PRIORITY =
      EnumSet.of(
          AuthEventType.LOCKOUT,
          AuthEventType.TOKEN_REFRESH_REUSE,
          AuthEventType.PASSWORD_CHANGED,
          AuthEventType.ACCOUNT_LOCKED_WRITE_FAILED);

  @ParameterizedTest
  @EnumSource(AuthEventType.class)
  void should_returnMatchingWireName_when_everyConstantChecked(AuthEventType type) {
    assertThat(type.wireName()).isEqualTo(type.name());
  }

  @Test
  void should_returnLockout_when_wireNameCalledOnLockout() {
    assertThat(AuthEventType.LOCKOUT.wireName()).isEqualTo("LOCKOUT");
  }

  @Test
  void should_returnTokenRefreshReuse_when_wireNameCalledOnTokenRefreshReuse() {
    assertThat(AuthEventType.TOKEN_REFRESH_REUSE.wireName()).isEqualTo("TOKEN_REFRESH_REUSE");
  }

  @Test
  void should_returnRegister_when_wireNameCalledOnRegister() {
    assertThat(AuthEventType.REGISTER.wireName()).isEqualTo("REGISTER");
  }

  @Test
  void should_returnVerify_when_wireNameCalledOnVerify() {
    assertThat(AuthEventType.VERIFY.wireName()).isEqualTo("VERIFY");
  }

  @Test
  void should_returnTrue_when_isPriorityCheckedOnLockout() {
    assertThat(AuthEventType.LOCKOUT.isPriority()).isTrue();
  }

  @Test
  void should_returnTrue_when_isPriorityCheckedOnTokenRefreshReuse() {
    assertThat(AuthEventType.TOKEN_REFRESH_REUSE.isPriority()).isTrue();
  }

  @Test
  void should_returnTrue_when_isPriorityCheckedOnPasswordChanged() {
    assertThat(AuthEventType.PASSWORD_CHANGED.isPriority()).isTrue();
  }

  @Test
  void should_returnTrue_when_isPriorityCheckedOnAccountLockedWriteFailed() {
    assertThat(AuthEventType.ACCOUNT_LOCKED_WRITE_FAILED.isPriority()).isTrue();
  }

  @ParameterizedTest
  @EnumSource(value = AuthEventType.class, names = {"LOCKOUT", "TOKEN_REFRESH_REUSE",
      "PASSWORD_CHANGED", "ACCOUNT_LOCKED_WRITE_FAILED"}, mode = EnumSource.Mode.EXCLUDE)
  void should_returnFalse_when_isPriorityCheckedOnAllNonPriorityTypes(AuthEventType type) {
    assertThat(type.isPriority()).isFalse();
  }

  @Test
  void should_containExactlyFourTypes_when_priorityTrueSetCollected() {
    Set<AuthEventType> actualPriority =
        Arrays.stream(AuthEventType.values())
            .filter(AuthEventType::isPriority)
            .collect(Collectors.toSet());

    assertThat(actualPriority).hasSize(4).isEqualTo(EXPECTED_PRIORITY);
  }

  @Test
  void should_defineAllTwentyConstants_when_valuesCalled() {
    assertThat(AuthEventType.values()).hasSize(20);
    assertThat(Arrays.stream(AuthEventType.values()).map(Enum::name))
        .containsExactlyInAnyOrder(
            "LOGIN_SUCCESS",
            "LOGIN_FAILURE",
            "LOCKOUT",
            "LOGOUT",
            "REGISTER",
            "VERIFY",
            "PASSWORD_RESET_REQUESTED",
            "PASSWORD_CHANGED",
            "TOKEN_REFRESH_REUSE",
            "LOGIN_PENDING_ACCOUNT",
            "ACCOUNT_UNLOCKED",
            "ACCOUNT_LOCKED_WRITE_FAILED",
            "REGISTRATION_DUPLICATE_EMAIL",
            "VERIFICATION_FAILED",
            "TOKEN_REFRESH_SUCCESS",
            "TOKEN_REFRESH_FAILURE",
            "PASSWORD_RESET_THROTTLED",
            "PASSWORD_RESET_FAILED",
            "RESEND_REQUESTED",
            "RESEND_THROTTLED");
  }

  @Test
  void should_haveUniqueWireNames_when_allConstantsCompared() {
    long distinctWireNameCount =
        Arrays.stream(AuthEventType.values()).map(AuthEventType::wireName).distinct().count();

    assertThat(distinctWireNameCount).isEqualTo(AuthEventType.values().length);
  }

  @Test
  void should_delegateToStringConstructor_when_enumConstructorUsed() {
    UUID id = UUID.randomUUID();

    AuthEvent event = new AuthEvent(id, AuthEventType.LOGIN_SUCCESS, "SUCCESS");

    assertThat(event.getId()).isEqualTo(id);
    assertThat(event.getEventType()).isEqualTo("LOGIN_SUCCESS");
    assertThat(event.getOutcome()).isEqualTo("SUCCESS");
  }
}
