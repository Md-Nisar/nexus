package com.example.nexus.common.security;

import static com.example.nexus.common.security.AuthenticationTestFixtures.authenticatedWith;
import static com.example.nexus.common.security.AuthenticationTestFixtures.authenticationWithDetails;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

class AuthenticatedRequestDetailsTest {

  private static final String REQUIRED_PERMISSION = "user:write";

  // --- Happy path ---

  @Test
  void should_returnPopulatedRecord_when_authenticationHasValidTenantIdAndPermissions() {
    Authentication authentication =
        authenticatedWith("tenant-1", List.of("user:write", "user:read"));

    AuthenticatedRequestDetails result =
        AuthenticatedRequestDetails.fromAuthentication(authentication, REQUIRED_PERMISSION);

    assertThat(result.tenantId()).isEqualTo("tenant-1");
    assertThat(result.permissions()).containsExactlyInAnyOrder("user:write", "user:read");
  }

  @Test
  void should_returnEmptyPermissionsSet_when_permissionsListIsEmpty() {
    Authentication authentication = authenticatedWith("tenant-1", List.of());

    AuthenticatedRequestDetails result =
        AuthenticatedRequestDetails.fromAuthentication(authentication, REQUIRED_PERMISSION);

    assertThat(result.permissions()).isEmpty();
  }

  @Test
  void should_deduplicatePermissions_when_listContainsDuplicates() {
    Authentication authentication =
        authenticatedWith("tenant-1", List.of("user:write", "user:write", "user:read"));

    AuthenticatedRequestDetails result =
        AuthenticatedRequestDetails.fromAuthentication(authentication, REQUIRED_PERMISSION);

    assertThat(result.permissions()).containsExactlyInAnyOrder("user:write", "user:read");
  }

  @Test
  void should_notReflectMutationsToSourceList_when_originalListIsModifiedAfterConstruction() {
    List<String> mutablePermissions = new ArrayList<>(List.of("user:write"));
    Authentication authentication = authenticatedWith("tenant-1", mutablePermissions);

    AuthenticatedRequestDetails result =
        AuthenticatedRequestDetails.fromAuthentication(authentication, REQUIRED_PERMISSION);
    mutablePermissions.add("user:delete");

    assertThat(result.permissions()).containsExactly("user:write");
  }

  @Test
  void should_returnUnmodifiableSet_when_permissionsAccessed() {
    Authentication authentication = authenticatedWith("tenant-1", List.of("user:write"));

    AuthenticatedRequestDetails result =
        AuthenticatedRequestDetails.fromAuthentication(authentication, REQUIRED_PERMISSION);

    assertThatThrownBy(() -> result.permissions().add("user:delete"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void should_treatTenantIdAsOpaqueString_when_valuePreservedVerbatim() {
    Authentication authentication = authenticatedWith("  Tenant-Mixed-CASE  ", List.of());

    AuthenticatedRequestDetails result =
        AuthenticatedRequestDetails.fromAuthentication(authentication, REQUIRED_PERMISSION);

    assertThat(result.tenantId()).isEqualTo("  Tenant-Mixed-CASE  ");
  }

  // --- Authentication malformed ---

  @Test
  void should_throwInsufficientPermissionException_when_authenticationIsNull() {
    assertThatThrownBy(
            () -> AuthenticatedRequestDetails.fromAuthentication(null, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION));
  }

  @Test
  void should_throwInsufficientPermissionException_when_authenticationIsNotAuthenticated() {
    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken("user-1", "credentials");
    authentication.setAuthenticated(false);

    assertThatThrownBy(
            () ->
                AuthenticatedRequestDetails.fromAuthentication(
                    authentication, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION));
  }

  // --- getDetails() malformed ---

  @Test
  void should_throwInsufficientPermissionException_when_detailsIsNull() {
    Authentication authentication = authenticationWithDetails(null);

    assertThatThrownBy(
            () ->
                AuthenticatedRequestDetails.fromAuthentication(
                    authentication, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION));
  }

  @Test
  void should_throwInsufficientPermissionException_when_detailsIsNotAMap() {
    Authentication authentication = authenticationWithDetails("not-a-map");

    assertThatThrownBy(
            () ->
                AuthenticatedRequestDetails.fromAuthentication(
                    authentication, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION));
  }

  // --- tenantId malformed ---

  @Test
  void should_throwInsufficientPermissionException_when_tenantIdKeyAbsent() {
    Map<String, Object> details = new HashMap<>();
    details.put("permissions", List.of("user:write"));
    Authentication authentication = authenticationWithDetails(details);

    assertThatThrownBy(
            () ->
                AuthenticatedRequestDetails.fromAuthentication(
                    authentication, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MISSING_TENANT));
  }

  @Test
  void should_throwInsufficientPermissionException_when_tenantIdIsNotAString() {
    Map<String, Object> details = new HashMap<>();
    details.put("tenantId", 12345);
    details.put("permissions", List.of("user:write"));
    Authentication authentication = authenticationWithDetails(details);

    assertThatThrownBy(
            () ->
                AuthenticatedRequestDetails.fromAuthentication(
                    authentication, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MISSING_TENANT));
  }

  @Test
  void should_throwInsufficientPermissionException_when_tenantIdIsBlank() {
    Authentication emptyTenantId = authenticatedWith("", List.of("user:write"));
    Authentication whitespaceTenantId = authenticatedWith("   ", List.of("user:write"));

    assertThatThrownBy(
            () -> AuthenticatedRequestDetails.fromAuthentication(emptyTenantId, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MISSING_TENANT));
    assertThatThrownBy(
            () ->
                AuthenticatedRequestDetails.fromAuthentication(
                    whitespaceTenantId, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MISSING_TENANT));
  }

  // --- permissions malformed ---

  @Test
  void should_throwInsufficientPermissionException_when_permissionsKeyAbsent() {
    Map<String, Object> details = new HashMap<>();
    details.put("tenantId", "tenant-1");
    Authentication authentication = authenticationWithDetails(details);

    assertThatThrownBy(
            () ->
                AuthenticatedRequestDetails.fromAuthentication(
                    authentication, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION));
  }

  @Test
  void should_throwInsufficientPermissionException_when_permissionsIsNotAList() {
    Map<String, Object> details = new HashMap<>();
    details.put("tenantId", "tenant-1");
    details.put("permissions", Set.of("user:write"));
    Authentication authentication = authenticationWithDetails(details);

    assertThatThrownBy(
            () ->
                AuthenticatedRequestDetails.fromAuthentication(
                    authentication, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION));
  }

  @Test
  void should_throwInsufficientPermissionException_when_permissionsListContainsNonStringElement() {
    Map<String, Object> details = new HashMap<>();
    details.put("tenantId", "tenant-1");
    details.put("permissions", List.of("user:write", 42));
    Authentication authentication = authenticationWithDetails(details);

    assertThatThrownBy(
            () ->
                AuthenticatedRequestDetails.fromAuthentication(
                    authentication, REQUIRED_PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            ex ->
                assertThat(((InsufficientPermissionException) ex).getReason())
                    .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION));
  }

  // --- hasPermission(String) ---

  @Test
  void should_returnTrue_when_permissionsContainRequiredPermission() {
    Authentication authentication = authenticatedWith("tenant-1", List.of("user:write"));
    AuthenticatedRequestDetails result =
        AuthenticatedRequestDetails.fromAuthentication(authentication, REQUIRED_PERMISSION);

    assertThat(result.hasPermission("user:write")).isTrue();
  }

  @Test
  void should_returnFalse_when_permissionsDoNotContainRequiredPermission() {
    Authentication authentication = authenticatedWith("tenant-1", List.of("user:read"));
    AuthenticatedRequestDetails result =
        AuthenticatedRequestDetails.fromAuthentication(authentication, REQUIRED_PERMISSION);

    assertThat(result.hasPermission("user:write")).isFalse();
  }

  @Test
  void should_returnFalse_when_permissionsSetIsEmpty() {
    Authentication authentication = authenticatedWith("tenant-1", List.of());
    AuthenticatedRequestDetails result =
        AuthenticatedRequestDetails.fromAuthentication(authentication, REQUIRED_PERMISSION);

    assertThat(result.hasPermission("user:write")).isFalse();
  }
}
