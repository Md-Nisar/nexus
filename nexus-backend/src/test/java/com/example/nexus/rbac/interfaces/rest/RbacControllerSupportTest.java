package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.rbac.domain.RoleChangeActor;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Unit tests for {@link RbacControllerSupport} (T-006, threat-model.md T-S6). Every fail-closed
 * branch is asserted to <b>throw</b>, never merely to return a falsy/null value — a test asserting
 * {@code isNull()} would incorrectly pass against a fail-open rewrite.
 */
@Tag("UnitTest")
class RbacControllerSupportTest {

  private static final UUID PRINCIPAL_USER_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000002");
  private static final String PERMISSION = "role:write";

  // ── resolveActor: 3 fail-closed branches (T-S6) ────────────────────────

  @Test
  void should_throwMalformedAuthentication_when_principalIsNotAString() {
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(null, null, List.of());
    auth.setDetails(Map.of("tenantId", TENANT_ID.toString(), "permissions", List.of()));

    assertThatThrownBy(() -> RbacControllerSupport.resolveActor(auth, PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .extracting(e -> ((InsufficientPermissionException) e).getReason())
        .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION);
  }

  @Test
  void should_throwMalformedAuthentication_when_principalIsNonUuidString() {
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken("not-a-uuid", null, List.of());
    auth.setDetails(Map.of("tenantId", TENANT_ID.toString(), "permissions", List.of()));

    assertThatThrownBy(() -> RbacControllerSupport.resolveActor(auth, PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .extracting(e -> ((InsufficientPermissionException) e).getReason())
        .isEqualTo(DenialReason.MALFORMED_AUTHENTICATION);
  }

  @Test
  void should_throwMissingTenant_when_tenantIdIsUnparseable() {
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(PRINCIPAL_USER_ID.toString(), null, List.of());
    auth.setDetails(Map.of("tenantId", "not-a-uuid", "permissions", List.of()));

    assertThatThrownBy(() -> RbacControllerSupport.resolveActor(auth, PERMISSION))
        .isInstanceOf(InsufficientPermissionException.class)
        .extracting(e -> ((InsufficientPermissionException) e).getReason())
        .isEqualTo(DenialReason.MISSING_TENANT);
  }

  @Test
  void should_returnActor_when_authenticationIsWellFormed() {
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(PRINCIPAL_USER_ID.toString(), null, List.of());
    auth.setDetails(Map.of("tenantId", TENANT_ID.toString(), "permissions", List.of(PERMISSION)));

    RoleChangeActor actor = RbacControllerSupport.resolveActor(auth, PERMISSION);

    assertThat(actor.userId()).isEqualTo(PRINCIPAL_USER_ID);
    assertThat(actor.tenantId()).isEqualTo(TENANT_ID);
  }

  // ── parsePathUuid ───────────────────────────────────────────────────────

  @Test
  void should_throwFieldValidationException_when_pathUuidIsMalformed() {
    assertThatThrownBy(() -> RbacControllerSupport.parsePathUuid("not-a-uuid", "roleId"))
        .isInstanceOf(FieldValidationException.class)
        .extracting(e -> ((FieldValidationException) e).field())
        .isEqualTo("roleId");
  }

  @Test
  void should_throwFieldValidationException_when_pathUuidIsNull() {
    assertThatThrownBy(() -> RbacControllerSupport.parsePathUuid(null, "roleId"))
        .isInstanceOf(FieldValidationException.class);
  }

  @Test
  void should_returnParsedUuid_when_pathUuidIsCanonical() {
    UUID parsed = RbacControllerSupport.parsePathUuid(TENANT_ID.toString(), "roleId");

    assertThat(parsed).isEqualTo(TENANT_ID);
  }

  // ── requestContext ──────────────────────────────────────────────────────

  @Test
  void should_buildRequestContextFromHttpRequest_when_headersPresent() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRemoteAddr()).thenReturn("192.0.2.1");
    when(request.getHeader("User-Agent")).thenReturn("test-agent");

    RequestContext ctx = RbacControllerSupport.requestContext(request);

    assertThat(ctx.ipAddress()).isEqualTo("192.0.2.1");
    assertThat(ctx.userAgent()).isEqualTo("test-agent");
  }

  // ── Class shape (T-S6): final, private constructor, static-only ────────

  @Test
  void should_bePackagePrivateFinalUtilityClass_when_inspectedViaReflection() throws Exception {
    Class<RbacControllerSupport> clazz = RbacControllerSupport.class;

    assertThat(Modifier.isFinal(clazz.getModifiers())).as("class must be final").isTrue();
    assertThat(Modifier.isPublic(clazz.getModifiers()))
        .as("class must not be public")
        .isFalse();

    Constructor<?>[] constructors = clazz.getDeclaredConstructors();
    assertThat(constructors).hasSize(1);
    assertThat(Modifier.isPrivate(constructors[0].getModifiers()))
        .as("the sole constructor must be private")
        .isTrue();

    for (Method method : clazz.getDeclaredMethods()) {
      assertThat(Modifier.isStatic(method.getModifiers()))
          .as("method %s must be static", method.getName())
          .isTrue();
    }
  }
}
