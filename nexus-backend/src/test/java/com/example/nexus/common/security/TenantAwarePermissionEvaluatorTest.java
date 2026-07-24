package com.example.nexus.common.security;

import static com.example.nexus.common.security.AuthenticationTestFixtures.authenticatedWith;
import static com.example.nexus.common.security.AuthenticationTestFixtures.authenticationWithDetails;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@Tag("UnitTest")
class TenantAwarePermissionEvaluatorTest {

  private final TenantAwarePermissionEvaluator evaluator = new TenantAwarePermissionEvaluator();

  @Test
  void should_returnTrue_when_permissionsContainRequiredPermission() {
    Authentication authentication = authenticatedWith("tenant-a", List.of("tenant:write"));

    boolean result = evaluator.hasPermission(authentication, "tenant:write");

    assertThat(result).isTrue();
  }

  @Test
  void should_throwInsufficientPermissionException_when_permissionsPresentButMissingRequired() {
    Authentication authentication = authenticatedWith("tenant-a", List.of("user:read"));

    assertThatThrownBy(() -> evaluator.hasPermission(authentication, "tenant:write"))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex -> {
              assertThat(((InsufficientPermissionException) ex).getRequiredPermission())
                  .isEqualTo("tenant:write");
              assertThat(((InsufficientPermissionException) ex).getReason())
                  .isEqualTo(DenialReason.PERMISSION_ABSENT);
            });
  }

  @Test
  void should_throwInsufficientPermissionException_when_permissionsEmpty() {
    Authentication authentication = authenticatedWith("tenant-a", List.of());

    assertThatThrownBy(() -> evaluator.hasPermission(authentication, "tenant:write"))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.PERMISSION_ABSENT));
  }

  @Test
  void should_throwInsufficientPermissionException_when_authenticationIsNull() {
    assertThatThrownBy(() -> evaluator.hasPermission(null, "tenant:write"))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION));
  }

  @Test
  void should_throwInsufficientPermissionException_when_authenticationIsUnauthenticated() {
    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken("user-1", "credentials");
    authentication.setAuthenticated(false);

    assertThatThrownBy(() -> evaluator.hasPermission(authentication, "tenant:write"))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION));
  }

  @Test
  void should_throwInsufficientPermissionException_when_detailsIsNotAMap() {
    Authentication authentication = authenticationWithDetails("not-a-map");

    assertThatThrownBy(() -> evaluator.hasPermission(authentication, "tenant:write"))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION));
  }

  @Test
  void should_throwInsufficientPermissionException_when_tenantIdBlank() {
    Authentication authentication = authenticatedWith("", List.of("tenant:write"));

    assertThatThrownBy(() -> evaluator.hasPermission(authentication, "tenant:write"))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MISSING_TENANT));
  }

  @Test
  void should_propagateRequiredPermission_onEveryThrow() {
    String requiredPermission = "tenant:write";

    assertThatThrownBy(() -> evaluator.hasPermission(null, requiredPermission))
        .asInstanceOf(InstanceOfAssertFactories.type(InsufficientPermissionException.class))
        .extracting(InsufficientPermissionException::getRequiredPermission)
        .isEqualTo(requiredPermission);

    UsernamePasswordAuthenticationToken unauthenticated =
        new UsernamePasswordAuthenticationToken("user-1", "credentials");
    unauthenticated.setAuthenticated(false);
    assertThatThrownBy(() -> evaluator.hasPermission(unauthenticated, requiredPermission))
        .asInstanceOf(InstanceOfAssertFactories.type(InsufficientPermissionException.class))
        .extracting(InsufficientPermissionException::getRequiredPermission)
        .isEqualTo(requiredPermission);

    Authentication notAMap = authenticationWithDetails("not-a-map");
    assertThatThrownBy(() -> evaluator.hasPermission(notAMap, requiredPermission))
        .asInstanceOf(InstanceOfAssertFactories.type(InsufficientPermissionException.class))
        .extracting(InsufficientPermissionException::getRequiredPermission)
        .isEqualTo(requiredPermission);

    Authentication blankTenantId = authenticatedWith("", List.of(requiredPermission));
    assertThatThrownBy(() -> evaluator.hasPermission(blankTenantId, requiredPermission))
        .asInstanceOf(InstanceOfAssertFactories.type(InsufficientPermissionException.class))
        .extracting(InsufficientPermissionException::getRequiredPermission)
        .isEqualTo(requiredPermission);

    Authentication missingPermission = authenticatedWith("tenant-a", List.of("user:read"));
    assertThatThrownBy(() -> evaluator.hasPermission(missingPermission, requiredPermission))
        .asInstanceOf(InstanceOfAssertFactories.type(InsufficientPermissionException.class))
        .extracting(InsufficientPermissionException::getRequiredPermission)
        .isEqualTo(requiredPermission);
  }

  @Test
  void should_propagateReason_onEveryThrow() {
    String requiredPermission = "tenant:write";

    assertThatThrownBy(() -> evaluator.hasPermission(null, requiredPermission))
        .asInstanceOf(InstanceOfAssertFactories.type(InsufficientPermissionException.class))
        .extracting(InsufficientPermissionException::getReason)
        .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION);

    UsernamePasswordAuthenticationToken unauthenticated =
        new UsernamePasswordAuthenticationToken("user-1", "credentials");
    unauthenticated.setAuthenticated(false);
    assertThatThrownBy(() -> evaluator.hasPermission(unauthenticated, requiredPermission))
        .asInstanceOf(InstanceOfAssertFactories.type(InsufficientPermissionException.class))
        .extracting(InsufficientPermissionException::getReason)
        .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION);

    Authentication notAMap = authenticationWithDetails("not-a-map");
    assertThatThrownBy(() -> evaluator.hasPermission(notAMap, requiredPermission))
        .asInstanceOf(InstanceOfAssertFactories.type(InsufficientPermissionException.class))
        .extracting(InsufficientPermissionException::getReason)
        .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION);

    Authentication blankTenantId = authenticatedWith("", List.of(requiredPermission));
    assertThatThrownBy(() -> evaluator.hasPermission(blankTenantId, requiredPermission))
        .asInstanceOf(InstanceOfAssertFactories.type(InsufficientPermissionException.class))
        .extracting(InsufficientPermissionException::getReason)
        .isEqualTo(DenialReason.MISSING_TENANT);

    Authentication missingPermission = authenticatedWith("tenant-a", List.of("user:read"));
    assertThatThrownBy(() -> evaluator.hasPermission(missingPermission, requiredPermission))
        .asInstanceOf(InstanceOfAssertFactories.type(InsufficientPermissionException.class))
        .extracting(InsufficientPermissionException::getReason)
        .isEqualTo(DenialReason.PERMISSION_ABSENT);
  }
}
