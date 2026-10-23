package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.example.nexus.common.security.AuthenticationDetailKeys;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.common.security.Permissions;
import com.example.nexus.identity.application.DirectoryAccessGuard;
import com.example.nexus.identity.application.UserDirectoryService;
import com.example.nexus.identity.domain.UserDirectoryCeilingExceededException;
import com.example.nexus.identity.domain.UserDirectoryThrottledException;
import com.example.nexus.identity.domain.DirectoryUserView;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.interfaces.rest.dto.UserDirectoryEntryResponse;
import com.example.nexus.identity.interfaces.rest.dto.UserLookupRequest;
import com.example.nexus.identity.interfaces.rest.dto.UserLookupResponse;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
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
  private final DirectoryAccessGuard guard = mock(DirectoryAccessGuard.class);
  private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
  private final UserDirectoryController controller =
      new UserDirectoryController(service, guard, meters);

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
  void should_consultTheCeilingThenTheLookupThrottleBeforeTheService_when_lookingUp() {
    when(service.lookup(TENANT, ACTOR, EMAIL)).thenReturn(Optional.empty());

    controller.lookupUser(reader(ACTOR.toString(), TENANT.toString()), new UserLookupRequest(EMAIL));

    InOrder order = inOrder(guard, service);
    order.verify(guard).checkCeiling(TENANT, ACTOR);
    order.verify(guard).checkLookup(TENANT, ACTOR);
    order.verify(service).lookup(TENANT, ACTOR, EMAIL);
  }

  @Test
  void should_notReachTheServiceAndCountThrottled_when_theLookupThrottleRejects() {
    doThrow(new UserDirectoryThrottledException(9)).when(guard).checkLookup(TENANT, ACTOR);
    Authentication auth = reader(ACTOR.toString(), TENANT.toString());
    UserLookupRequest request = new UserLookupRequest(EMAIL);

    assertThatThrownBy(() -> controller.lookupUser(auth, request))
        .isInstanceOf(UserDirectoryThrottledException.class);
    verify(service, never()).lookup(any(), any(), any());
    assertThat(requests("lookup", "throttled")).isEqualTo(1.0);
  }

  @Test
  void should_countThrottledOnTheCeiling_when_listingIsRejected() {
    doThrow(new UserDirectoryCeilingExceededException(9)).when(guard).checkCeiling(TENANT, ACTOR);
    Authentication auth = reader(ACTOR.toString(), TENANT.toString());

    assertThatThrownBy(() -> controller.listUsers(auth, null, null, null, null, null))
        .isInstanceOf(UserDirectoryCeilingExceededException.class);
    verifyNoInteractions(service);
    assertThat(requests("list", "throttled")).isEqualTo(1.0);
  }

  @Test
  void should_countOkAndAHitWithoutTenantUserOrEmailTags_when_theLookupHits() {
    when(service.lookup(TENANT, ACTOR, EMAIL))
        .thenReturn(
            Optional.of(
                new DirectoryUserView(USER, EMAIL, UserStatus.ACTIVE, null, Instant.EPOCH)));

    controller.lookupUser(reader(ACTOR.toString(), TENANT.toString()), new UserLookupRequest(EMAIL));

    assertThat(requests("lookup", "ok")).isEqualTo(1.0);
    assertThat(meters.get("nexus.identity.directory.lookup_result").tag("result", "hit").counter().count())
        .isEqualTo(1.0);
    assertThat(meters.get("nexus.identity.directory.duration").tag("operation", "lookup").timer().count())
        .isEqualTo(1L);
    assertThat(meters.getMeters())
        .allSatisfy(
            m ->
                assertThat(m.getId().getTags())
                    .noneMatch(
                        t ->
                            t.getValue().contains(EMAIL)
                                || t.getValue().contains(ACTOR.toString())
                                || t.getValue().contains(TENANT.toString())));
  }

  @Test
  void should_countAMiss_when_theLookupMisses() {
    when(service.lookup(TENANT, ACTOR, EMAIL)).thenReturn(Optional.empty());

    controller.lookupUser(reader(ACTOR.toString(), TENANT.toString()), new UserLookupRequest(EMAIL));

    assertThat(meters.get("nexus.identity.directory.lookup_result").tag("result", "miss").counter().count())
        .isEqualTo(1.0);
  }

  @Test
  void should_countNotFound_when_theUserIsMissing() {
    when(service.get(TENANT, ACTOR, USER))
        .thenThrow(new com.example.nexus.common.domain.ResourceNotFoundException("USER_NOT_FOUND", "x"));
    Authentication auth = reader(ACTOR.toString(), TENANT.toString());
    String id = USER.toString();

    assertThatThrownBy(() -> controller.getUser(auth, id))
        .isInstanceOf(com.example.nexus.common.domain.ResourceNotFoundException.class);
    assertThat(requests("get", "not_found")).isEqualTo(1.0);
  }

  @Test
  void should_countInvalid_when_theUserIdIsMalformed() {
    Authentication auth = reader(ACTOR.toString(), TENANT.toString());

    assertThatThrownBy(() -> controller.getUser(auth, "not-a-uuid"))
        .isInstanceOf(com.example.nexus.common.domain.FieldValidationException.class);
    assertThat(requests("get", "invalid")).isEqualTo(1.0);
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

  private double requests(String operation, String outcome) {
    var counter =
        meters
            .find("nexus.identity.directory.requests")
            .tags("operation", operation, "outcome", outcome)
            .counter();
    return counter == null ? 0.0 : counter.count();
  }
}
