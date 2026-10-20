package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.example.nexus.common.security.AuthenticationDetailKeys;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.common.security.Permissions;
import com.example.nexus.identity.application.UserDirectoryService;
import com.example.nexus.identity.domain.DirectoryUserView;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.interfaces.rest.dto.UserDirectoryEntryResponse;
import com.example.nexus.identity.interfaces.rest.dto.UserLookupRequest;
import com.example.nexus.identity.interfaces.rest.dto.UserLookupResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * US-019 T-005 (design §4.2): the lookup handler maps zero or one user into {@code data}, with the
 * actor and tenant taken from the authentication only.
 */
@Tag("UnitTest")
class UserDirectoryControllerTest {

  private static final UUID ACTOR = UUID.fromString("019f6839-0000-7000-8000-0000000000a2");
  private static final UUID TENANT = UUID.fromString("019f6839-0000-7000-8000-0000000000a1");
  private static final UUID USER = UUID.fromString("019f6839-0000-7000-8000-0000000000b1");
  private static final String EMAIL = "jane.doe@example.test";

  private final UserDirectoryService service = mock(UserDirectoryService.class);
  private final UserDirectoryController controller = new UserDirectoryController(service);

  @Test
  void should_returnTheOneEntry_when_theLookupHits() {
    Instant created = Instant.parse("2026-01-01T00:00:00Z");
    when(service.lookup(TENANT, ACTOR, EMAIL))
        .thenReturn(
            Optional.of(new DirectoryUserView(USER, EMAIL, UserStatus.ACTIVE, null, created)));

    ResponseEntity<UserLookupResponse> response =
        controller.lookupUser(reader(ACTOR.toString(), TENANT.toString()), new UserLookupRequest(EMAIL));

    assertThat(response.getStatusCode().value()).isEqualTo(200);
    assertThat(response.getBody().data())
        .containsExactly(new UserDirectoryEntryResponse(USER.toString(), EMAIL, "ACTIVE", false, created));
  }

  @Test
  void should_returnEmptyData_when_theLookupMisses() {
    when(service.lookup(TENANT, ACTOR, EMAIL)).thenReturn(Optional.empty());

    ResponseEntity<UserLookupResponse> response =
        controller.lookupUser(reader(ACTOR.toString(), TENANT.toString()), new UserLookupRequest(EMAIL));

    assertThat(response.getBody().data()).isEmpty();
  }

  @Test
  void should_failClosedWithoutLookingUp_when_thePrincipalIsNotAUuid() {
    Authentication malformed = reader("not-a-uuid", TENANT.toString());

    assertThatThrownBy(() -> controller.lookupUser(malformed, new UserLookupRequest(EMAIL)))
        .isInstanceOf(InsufficientPermissionException.class);
    verifyNoInteractions(service);
  }

  @Test
  void should_failClosedWithoutLookingUp_when_theTenantIsNotAUuid() {
    Authentication noTenant = reader(ACTOR.toString(), "not-a-tenant");

    assertThatThrownBy(() -> controller.lookupUser(noTenant, new UserLookupRequest(EMAIL)))
        .isInstanceOf(InsufficientPermissionException.class);
    verifyNoInteractions(service);
  }

  @Test
  void should_trimAndRedact_when_aLookupRequestIsBuiltAndPrinted() {
    UserLookupRequest request = new UserLookupRequest("  " + EMAIL + "\t");

    assertThat(request.email()).isEqualTo(EMAIL);
    assertThat(request.toString()).doesNotContain(EMAIL, "jane");
    assertThat(new UserLookupRequest(null).email()).isNull();
  }

  private static Authentication reader(String principal, String tenantId) {
    UsernamePasswordAuthenticationToken caller =
        UsernamePasswordAuthenticationToken.authenticated(principal, null, List.of());
    caller.setDetails(
        Map.of(
            AuthenticationDetailKeys.TENANT_ID, tenantId,
            AuthenticationDetailKeys.EMAIL_VERIFIED, true,
            AuthenticationDetailKeys.TOKEN_VERSION, 2,
            AuthenticationDetailKeys.PERMISSIONS, List.of(Permissions.USER_DIRECTORY_READ)));
    return caller;
  }
}
