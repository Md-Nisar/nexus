package com.example.nexus.common.web;

import com.example.nexus.common.domain.AccountLockedException;
import com.example.nexus.common.domain.AccountNotVerifiedException;
import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.common.domain.RateLimitException;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.domain.TokenExpiredException;
import jakarta.validation.ConstraintViolationException;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

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
    logHandledException(e, "DEBUG", e.code());
    return problem(HttpStatus.NOT_FOUND, e.code(), e.getMessage());
  }

  @ExceptionHandler(ConflictException.class)
  ProblemDetail handleConflict(ConflictException e) {
    logHandledException(e, "DEBUG", e.code());
    return problem(HttpStatus.CONFLICT, e.code(), e.getMessage());
  }

  @ExceptionHandler(FieldValidationException.class)
  ProblemDetail handleFieldValidation(FieldValidationException e) {
    logHandledException(e, "DEBUG", e.code());
    ProblemDetail problem = problem(HttpStatus.BAD_REQUEST, e.code(), e.getMessage());
    problem.setProperty("details", List.of(Map.of("field", e.field(), "message", e.getMessage())));
    return problem;
  }

  @ExceptionHandler(TokenExpiredException.class)
  ProblemDetail handleTokenExpired(TokenExpiredException e) {
    logHandledException(e, "DEBUG", e.code());
    return problem(HttpStatus.GONE, e.code(), e.getMessage());
  }

  @ExceptionHandler(RateLimitException.class)
  ResponseEntity<ProblemDetail> handleRateLimit(RateLimitException e) {
    logHandledException(e, "WARN", e.code());
    ProblemDetail problem = problem(HttpStatus.TOO_MANY_REQUESTS, e.code(), e.getMessage());
    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.RETRY_AFTER, String.valueOf(e.retryAfterSeconds()));
    return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).headers(headers).body(problem);
  }

  @ExceptionHandler(AccountLockedException.class)
  ResponseEntity<ProblemDetail> handleAccountLocked(AccountLockedException e) {
    logHandledException(e, "WARN", e.code());
    ProblemDetail problem = problem(HttpStatus.LOCKED, e.code(), e.getMessage());
    problem.setProperty("retryAfterSeconds", e.retryAfterSeconds());
    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.RETRY_AFTER, String.valueOf(e.retryAfterSeconds()));
    return ResponseEntity.status(HttpStatus.LOCKED).headers(headers).body(problem);
  }

  @ExceptionHandler(AuthenticationException.class)
  ResponseEntity<ProblemDetail> handleAuthentication(AuthenticationException e) {
    logHandledException(e, "WARN", e.code());
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .body(problem(HttpStatus.UNAUTHORIZED, e.code(), e.getMessage()));
  }

  @ExceptionHandler(AccountNotVerifiedException.class)
  ProblemDetail handleAccountNotVerified(AccountNotVerifiedException e) {
    logHandledException(e, "WARN", e.code());
    return problem(HttpStatus.FORBIDDEN, e.code(), e.getMessage());
  }

  @ExceptionHandler(DomainException.class)
  ProblemDetail handleDomain(DomainException e) {
    logHandledException(e, "DEBUG", e.code());
    return problem(HttpStatus.UNPROCESSABLE_CONTENT, e.code(), e.getMessage());
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  ProblemDetail handleBodyValidation(MethodArgumentNotValidException e) {
    logHandledException(e, "DEBUG", "VALIDATION_FAILED");
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
    logHandledException(e, "DEBUG", "VALIDATION_FAILED");
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
    logHandledException(e, "WARN", "ACCESS_DENIED");
    return problem(
        HttpStatus.FORBIDDEN, "ACCESS_DENIED", "You do not have access to this resource.");
  }

  @ExceptionHandler(NoResourceFoundException.class)
  ProblemDetail handleNoResource(NoResourceFoundException e) {
    logHandledException(e, "DEBUG", "RESOURCE_NOT_FOUND");
    return problem(HttpStatus.NOT_FOUND, "RESOURCE_NOT_FOUND", "Resource not found.");
  }

  @ExceptionHandler(Exception.class)
  ProblemDetail handleUnexpected(Exception e) {
    String correlationId = MDC.get(CorrelationIdFilter.MDC_CORRELATION_ID_KEY);
    log.atError()
        .addKeyValue("event", "api_request")
        .addKeyValue("correlationId", correlationId)
        .addKeyValue("outcome", "FAILURE")
        .addKeyValue("errorType", e.getClass().getSimpleName())
        .addKeyValue("errorCode", "INTERNAL_ERROR")
        .log("Unhandled exception traceId=" + correlationId, e);
    return problem(
        HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An unexpected error occurred.");
  }

  private void logHandledException(Exception e, String level, String errorCode) {
    String correlationId = MDC.get(CorrelationIdFilter.MDC_CORRELATION_ID_KEY);
    String errorType = e.getClass().getSimpleName();
    if ("WARN".equals(level)) {
      log.atWarn()
          .addKeyValue("event", "api_request")
          .addKeyValue("correlationId", correlationId)
          .addKeyValue("outcome", "FAILURE")
          .addKeyValue("errorType", errorType)
          .addKeyValue("errorCode", errorCode)
          .log("Handled operational error: errorType={} errorCode={} correlationId={}",
              errorType, errorCode, correlationId);
    } else if ("DEBUG".equals(level)) {
      log.atDebug()
          .addKeyValue("event", "api_request")
          .addKeyValue("correlationId", correlationId)
          .addKeyValue("outcome", "FAILURE")
          .addKeyValue("errorType", errorType)
          .addKeyValue("errorCode", errorCode)
          .log("Handled validation/domain error: errorType={} errorCode={} correlationId={}",
              errorType, errorCode, correlationId);
    }
  }

  private ProblemDetail problem(HttpStatus status, String code, String message) {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, message);
    problem.setProperty("code", code);
    problem.setProperty("traceId", MDC.get(CorrelationIdFilter.MDC_KEY));
    return problem;
  }
}
