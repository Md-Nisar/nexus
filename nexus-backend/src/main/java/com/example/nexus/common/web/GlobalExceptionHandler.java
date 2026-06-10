package com.example.nexus.common.web;

import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import com.example.nexus.common.domain.ResourceNotFoundException;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.List;
import java.util.Map;

/**
 * Maps every exception to an RFC 7807 Problem Details response with the Nexus extensions
 * {@code code} (stable machine-readable identifier) and {@code traceId} (correlates with server
 * logs via {@link CorrelationIdFilter}). Validation failures additionally carry a {@code details}
 * list of per-field errors.
 *
 * <p>No internal information — stack traces, SQL, class names — ever leaves this handler.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

  private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

  @ExceptionHandler(ResourceNotFoundException.class)
  ProblemDetail handleNotFound(ResourceNotFoundException e) {
    return problem(HttpStatus.NOT_FOUND, e.code(), e.getMessage());
  }

  @ExceptionHandler(ConflictException.class)
  ProblemDetail handleConflict(ConflictException e) {
    return problem(HttpStatus.CONFLICT, e.code(), e.getMessage());
  }

  @ExceptionHandler(DomainException.class)
  ProblemDetail handleDomain(DomainException e) {
    return problem(HttpStatus.UNPROCESSABLE_ENTITY, e.code(), e.getMessage());
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  ProblemDetail handleBodyValidation(MethodArgumentNotValidException e) {
    ProblemDetail problem =
        problem(HttpStatus.BAD_REQUEST, "VALIDATION_FAILED", "Request validation failed.");
    problem.setProperty(
        "details",
        e.getBindingResult().getFieldErrors().stream()
            .map(f -> Map.of(
                "field", f.getField(),
                "message", String.valueOf(f.getDefaultMessage())))
            .toList());
    return problem;
  }

  @ExceptionHandler(ConstraintViolationException.class)
  ProblemDetail handleParamValidation(ConstraintViolationException e) {
    ProblemDetail problem =
        problem(HttpStatus.BAD_REQUEST, "VALIDATION_FAILED", "Request validation failed.");
    List<Map<String, String>> details = e.getConstraintViolations().stream()
        .map(v -> Map.of(
            "field", String.valueOf(v.getPropertyPath()),
            "message", v.getMessage()))
        .toList();
    problem.setProperty("details", details);
    return problem;
  }

  @ExceptionHandler(AccessDeniedException.class)
  ProblemDetail handleAccessDenied(AccessDeniedException e) {
    return problem(
        HttpStatus.FORBIDDEN, "ACCESS_DENIED", "You do not have access to this resource.");
  }

  @ExceptionHandler(NoResourceFoundException.class)
  ProblemDetail handleNoResource(NoResourceFoundException e) {
    return problem(HttpStatus.NOT_FOUND, "RESOURCE_NOT_FOUND", "Resource not found.");
  }

  @ExceptionHandler(Exception.class)
  ProblemDetail handleUnexpected(Exception e) {
    log.error("unhandled exception traceId={}", MDC.get(CorrelationIdFilter.MDC_KEY), e);
    return problem(
        HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An unexpected error occurred.");
  }

  private ProblemDetail problem(HttpStatus status, String code, String message) {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, message);
    problem.setProperty("code", code);
    problem.setProperty("traceId", MDC.get(CorrelationIdFilter.MDC_KEY));
    return problem;
  }
}
