package com.example.nexus.common.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.common.domain.AccountLockedException;
import com.example.nexus.common.domain.AccountNotVerifiedException;
import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.common.domain.RateLimitException;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.domain.TokenExpiredException;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.validation.ConstraintViolationException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.method.annotation.ExceptionHandlerMethodResolver;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@Tag("UnitTest")
class GlobalExceptionHandlerTest {

    private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    private final GlobalExceptionHandler handler = new GlobalExceptionHandler(meterRegistry);

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void should_return404WithCode_when_resourceNotFound() {
        ProblemDetail problem =
                handler.handleNotFound(new ResourceNotFoundException("USER_NOT_FOUND", "No such user."));

        assertThat(problem.getStatus()).isEqualTo(404);
        assertThat(problem.getProperties()).containsEntry("code", "USER_NOT_FOUND");
        assertThat(problem.getDetail()).isEqualTo("No such user.");
    }

    @Test
    void should_return409WithCode_when_conflict() {
        ProblemDetail problem =
                handler.handleConflict(new ConflictException("DUPLICATE_EMAIL", "Email already used."));

        assertThat(problem.getStatus()).isEqualTo(409);
        assertThat(problem.getProperties()).containsEntry("code", "DUPLICATE_EMAIL");
    }

    @Test
    void should_incrementDomainConflictCounterTaggedWithCode_when_lastAdminRoleConflict() {
        // RBAC_002 (US-012 LastAdminRoleException) — T-015 closes the gap that this code
        // previously logged at DEBUG with zero metric (design §9.2, threat-model T-D4/T-D5).
        handler.handleConflict(new ConflictException("RBAC_002", "Cannot revoke the last active admin."));

        double count =
                meterRegistry.find("nexus.domain.conflict").tag("code", "RBAC_002").counter().count();

        assertThat(count).isEqualTo(1.0);
    }

    @Test
    void should_incrementDomainConflictCounterTaggedWithCode_when_duplicateRoleAssignmentConflict() {
        // RBAC_004 (US-012 DuplicateRoleAssignmentException) — same gap, distinct code tag.
        handler.handleConflict(new ConflictException("RBAC_004", "Role already assigned."));

        double count =
                meterRegistry.find("nexus.domain.conflict").tag("code", "RBAC_004").counter().count();

        assertThat(count).isEqualTo(1.0);
    }

    @Test
    void should_return422_when_genericDomainRuleViolated() {
        DomainException violation = new DomainException("ORDER_NOT_CANCELLABLE", "Order shipped.") {};

        ProblemDetail problem = handler.handleDomain(violation);

        assertThat(problem.getStatus()).isEqualTo(422);
        assertThat(problem.getProperties()).containsEntry("code", "ORDER_NOT_CANCELLABLE");
    }

    @Test
    void should_return400WithFieldDetails_when_bodyValidationFails() {
        BindingResult bindingResult = mock(BindingResult.class);
        when(bindingResult.getFieldErrors())
                .thenReturn(List.of(new FieldError("user", "email", "must be a valid email")));
        MethodArgumentNotValidException exception =
                new MethodArgumentNotValidException(null, bindingResult);

        ProblemDetail problem = handler.handleBodyValidation(exception);

        assertThat(problem.getStatus()).isEqualTo(400);
        assertThat(problem.getProperties()).containsEntry("code", "VALIDATION_FAILED");
        assertThat(problem.getProperties().get("details")).asInstanceOf(
                        org.assertj.core.api.InstanceOfAssertFactories.LIST)
                .hasSize(1);
    }

    @Test
    void should_return400_when_paramValidationFails() {
        ProblemDetail problem =
                handler.handleParamValidation(new ConstraintViolationException("invalid", Set.of()));

        assertThat(problem.getStatus()).isEqualTo(400);
        assertThat(problem.getProperties()).containsEntry("code", "VALIDATION_FAILED");
    }

    @Test
    void should_return403_when_accessDenied() {
        ProblemDetail problem = handler.handleAccessDenied(new AccessDeniedException("denied"));

        assertThat(problem.getStatus()).isEqualTo(403);
        assertThat(problem.getProperties()).containsEntry("code", "ACCESS_DENIED");
        assertThat(problem.getProperties()).doesNotContainEntry("code", "RBAC_001");
    }

    @Test
    void should_return403WithRbac001CodeDetailAndRequiredPermission_when_insufficientPermissionThrown() {
        MDC.put(CorrelationIdFilter.MDC_KEY, "test-trace-id");

        ProblemDetail problem =
                handler.handleInsufficientPermission(
                        new InsufficientPermissionException("tenant:write", DenialReason.PERMISSION_ABSENT));

        assertThat(problem.getStatus()).isEqualTo(403);
        assertThat(problem.getProperties()).containsEntry("code", "RBAC_001");
        assertThat(problem.getDetail())
                .isEqualTo("You do not have permission to perform this action");
        assertThat(problem.getProperties()).containsEntry("requiredPermission", "tenant:write");
        assertThat(problem.getProperties()).containsEntry("traceId", "test-trace-id");
    }

    @Test
    void should_incrementPermissionDeniedCounterWithPermissionAndReasonTags_when_permissionAbsent() {
        handler.handleInsufficientPermission(
                new InsufficientPermissionException("tenant:write", DenialReason.PERMISSION_ABSENT));

        double count =
                meterRegistry
                        .find("nexus.rbac.permission_denied")
                        .tag("permission", "tenant:write")
                        .tag("reason", "PERMISSION_ABSENT")
                        .counter()
                        .count();

        assertThat(count).isEqualTo(1.0);
    }

    @Test
    void should_incrementPermissionDeniedCounterWithDistinctReasonTag_when_authenticationMalformed() {
        handler.handleInsufficientPermission(
                new InsufficientPermissionException(
                        "tenant:write", DenialReason.MALFORMED_AUTHENTICATION));

        double count =
                meterRegistry
                        .find("nexus.rbac.permission_denied")
                        .tag("permission", "tenant:write")
                        .tag("reason", "MALFORMED_AUTHENTICATION")
                        .counter()
                        .count();

        assertThat(count).isEqualTo(1.0);
        // Tagged by `reason` as well as `permission` (design §B7 — bounded cardinality: 7
        // permissions x 3 reasons) so a MALFORMED_AUTHENTICATION spike is independently
        // alertable from routine PERMISSION_ABSENT noise (threat-model T-08).
    }

    @Test
    void should_resolveInsufficientPermissionHandler_notGenericAccessDeniedHandler_when_dispatched() {
        var resolver = new ExceptionHandlerMethodResolver(GlobalExceptionHandler.class);

        Method resolved =
                resolver.resolveMethod(
                        new InsufficientPermissionException("tenant:write", DenialReason.PERMISSION_ABSENT));

        assertThat(resolved.getName()).isEqualTo("handleInsufficientPermission");
    }

    @Test
    void should_return500WithoutInternalDetails_when_unexpectedException() {
        ProblemDetail problem =
                handler.handleUnexpected(new IllegalStateException("secret internal state"));

        assertThat(problem.getStatus()).isEqualTo(500);
        assertThat(problem.getProperties()).containsEntry("code", "INTERNAL_ERROR");
        assertThat(problem.getDetail()).doesNotContain("secret internal state");
    }

    @Test
    @SuppressWarnings("unchecked")
    void should_return400WithFieldDetail_when_fieldValidationFails() {
        ProblemDetail problem = handler.handleFieldValidation(
                new FieldValidationException("AUTH_PWD_001", "password", "Password is too common."));

        assertThat(problem.getStatus()).isEqualTo(400);
        assertThat(problem.getProperties()).containsEntry("code", "AUTH_PWD_001");
        assertThat(problem.getDetail()).isEqualTo("Password is too common.");
        List<Map<String, String>> details =
                (List<Map<String, String>>) problem.getProperties().get("details");
        assertThat(details).hasSize(1);
        assertThat(details.get(0)).containsEntry("field", "password")
                .containsEntry("message", "Password is too common.");
    }

    @Test
    void should_return410WithCode_when_tokenExpired() {
        ProblemDetail problem = handler.handleTokenExpired(
                new TokenExpiredException("AUTH_VRF_002", "Verification link is invalid or has expired."));

        assertThat(problem.getStatus()).isEqualTo(410);
        assertThat(problem.getProperties()).containsEntry("code", "AUTH_VRF_002");
        assertThat(problem.getDetail()).isEqualTo("Verification link is invalid or has expired.");
    }

    @Test
    void should_return429WithRetryAfterHeader_when_rateLimited() {
        ResponseEntity<ProblemDetail> response = handler.handleRateLimit(
                new RateLimitException("AUTH_RES_001", "Too many requests. Try again later.", 60L));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("60");
        ProblemDetail problem = response.getBody();
        assertThat(problem).isNotNull();
        assertThat(problem.getProperties()).containsEntry("code", "AUTH_RES_001");
        assertThat(problem.getDetail()).isEqualTo("Too many requests. Try again later.");
    }

    @Test
    void should_return401WithCode_when_authenticationFails() {
        ResponseEntity<ProblemDetail> response = handler.handleAuthentication(
                new AuthenticationException("AUTH_001", "Invalid email or password"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(401);
        assertThat(response.getBody().getProperties()).containsEntry("code", "AUTH_001");
        assertThat(response.getBody().getDetail()).isEqualTo("Invalid email or password");
    }

    @Test
    void should_return403WithCode_when_accountNotVerified() {
        ProblemDetail problem = handler.handleAccountNotVerified(
                new AccountNotVerifiedException("AUTH_002", "Account not verified."));

        assertThat(problem.getStatus()).isEqualTo(403);
        assertThat(problem.getProperties()).containsEntry("code", "AUTH_002");
        assertThat(problem.getDetail()).isEqualTo("Account not verified.");
    }

    @Test
    void should_return404WithResourceNotFoundCode_when_noResourceFound() throws Exception {
        ProblemDetail problem = handler.handleNoResource(
                new NoResourceFoundException(HttpMethod.GET, "/nonexistent/path", "No resource found"));

        assertThat(problem.getStatus()).isEqualTo(404);
        assertThat(problem.getProperties()).containsEntry("code", "RESOURCE_NOT_FOUND");
    }

    @Test
    void should_return429WithRetryAfterOf3600_when_dailyRateLimitExceeded() {
        ResponseEntity<ProblemDetail> response = handler.handleRateLimit(
                new RateLimitException("AUTH_RES_001", "Daily limit exceeded.", 3600L));

        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("3600");
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(429);
    }

    @Test
    void should_return423WithRetryAfterHeader_when_accountLocked() {
        ResponseEntity<ProblemDetail> response = handler.handleAccountLocked(
                new AccountLockedException("AUTH_LCK_001",
                        "Account locked. Try again later or reset your password.", 873L));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.LOCKED);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("873");
        ProblemDetail problem = response.getBody();
        assertThat(problem).isNotNull();
        assertThat(problem.getStatus()).isEqualTo(423);
        assertThat(problem.getProperties()).containsEntry("code", "AUTH_LCK_001");
        assertThat(problem.getProperties()).containsEntry("retryAfterSeconds", 873L);
        assertThat(problem.getDetail())
                .isEqualTo("Account locked. Try again later or reset your password.");
    }

    @Test
    void should_return423WithZeroRetryAfter_when_accountLockedOnBoundary() {
        // retryAfterSeconds = 0 when lockedUntil == now (lock expires at this exact instant)
        ResponseEntity<ProblemDetail> response = handler.handleAccountLocked(
                new AccountLockedException("AUTH_LCK_001",
                        "Account locked. Try again later or reset your password.", 0L));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.LOCKED);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("0");
        ProblemDetail problem = response.getBody();
        assertThat(problem).isNotNull();
        assertThat(problem.getProperties()).containsEntry("retryAfterSeconds", 0L);
    }

    // --- Structured log fields on permission denial ---
    //
    // src/test/resources/logback-test.xml sets the GlobalExceptionHandler logger to OFF so that
    // should_return500WithoutInternalDetails_when_unexpectedException doesn't spam test output
    // with an ERROR stack trace. These tests need WARN-level output captured instead, so they
    // raise the level for their own duration and restore it to OFF afterward.

    @Test
    void should_logStructuredFieldsWithPermissionAbsentReason_when_insufficientPermissionThrown() {
        Logger logger = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.WARN);
        try {
            MDC.put("userId", "u-1");
            MDC.put("tenantId", "t-1");
            MDC.put(CorrelationIdFilter.MDC_CORRELATION_ID_KEY, "corr-1");

            handler.handleInsufficientPermission(
                    new InsufficientPermissionException("tenant:write", DenialReason.PERMISSION_ABSENT));

            ILoggingEvent event = appender.list.get(0);
            Map<String, Object> keyValues = keyValueMap(event);
            assertThat(keyValues)
                    .containsEntry("reason", "PERMISSION_ABSENT")
                    .containsEntry("userId", "u-1")
                    .containsEntry("tenantId", "t-1")
                    .containsEntry("requiredPermission", "tenant:write")
                    .containsEntry("correlationId", "corr-1");
        } finally {
            logger.detachAppender(appender);
            appender.stop();
            logger.setLevel(Level.OFF);
        }
    }

    @Test
    void should_logStructuredFieldsWithMalformedAuthenticationReason_when_insufficientPermissionThrown() {
        Logger logger = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.WARN);
        try {
            MDC.put("userId", "u-1");
            MDC.put("tenantId", "t-1");
            MDC.put(CorrelationIdFilter.MDC_CORRELATION_ID_KEY, "corr-1");

            handler.handleInsufficientPermission(
                    new InsufficientPermissionException(
                            "tenant:write", DenialReason.MALFORMED_AUTHENTICATION));

            ILoggingEvent event = appender.list.get(0);
            Map<String, Object> keyValues = keyValueMap(event);
            assertThat(keyValues)
                    .containsEntry("reason", "MALFORMED_AUTHENTICATION")
                    .containsEntry("userId", "u-1")
                    .containsEntry("tenantId", "t-1")
                    .containsEntry("requiredPermission", "tenant:write")
                    .containsEntry("correlationId", "corr-1");
        } finally {
            logger.detachAppender(appender);
            appender.stop();
            logger.setLevel(Level.OFF);
        }
    }

    private static Map<String, Object> keyValueMap(ILoggingEvent event) {
        Map<String, Object> map = new HashMap<>();
        event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
        return map;
    }
}
