package com.example.nexus.common.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import com.example.nexus.common.domain.ResourceNotFoundException;
import jakarta.validation.ConstraintViolationException;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

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
    }

    @Test
    void should_return500WithoutInternalDetails_when_unexpectedException() {
        ProblemDetail problem =
                handler.handleUnexpected(new IllegalStateException("secret internal state"));

        assertThat(problem.getStatus()).isEqualTo(500);
        assertThat(problem.getProperties()).containsEntry("code", "INTERNAL_ERROR");
        assertThat(problem.getDetail()).doesNotContain("secret internal state");
    }
}
