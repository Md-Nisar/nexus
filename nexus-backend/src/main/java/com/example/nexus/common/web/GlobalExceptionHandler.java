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
import com.example.nexus.common.security.AuthenticationDetailKeys;
import com.example.nexus.common.security.InsufficientPermissionException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.validation.ConstraintViolationException;
import java.util.LinkedHashMap;
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

  private static final String KEY_ERROR_CODE = "errorCode";
  private static final String LEVEL_DEBUG = "DEBUG";
  private static final String CODE_VALIDATION_FAILED = "VALIDATION_FAILED";
  private static final String EVENT_API_REQUEST = "api_request";
  private static final String KEY_EVENT = "event";
  private static final String KEY_CORRELATION_ID = "correlationId";
  private static final String KEY_OUTCOME = "outcome";
  private static final String OUTCOME_FAILURE = "FAILURE";
  private static final String KEY_ERROR_TYPE = "errorType";
  private static final String KEY_DETAILS = "details";
  private static final String KEY_MESSAGE = "message";
  private static final String KEY_FIELD = "field";

  private final MeterRegistry meterRegistry;

  public GlobalExceptionHandler(MeterRegistry meterRegistry) {
    this.meterRegistry = meterRegistry;
  }

  @ExceptionHandler(ResourceNotFoundException.class)
  ProblemDetail handleNotFound(ResourceNotFoundException e) {
    logHandledException(e, LEVEL_DEBUG, e.code());
    return problem(HttpStatus.NOT_FOUND, e.code(), e.getMessage());
  }

  @ExceptionHandler(ConflictException.class)
  ProblemDetail handleConflict(ConflictException e) {
    logHandledException(e, LEVEL_DEBUG, e.code());
    Counter.builder("nexus.domain.conflict").tag("code", e.code()).register(meterRegistry).increment();
    return problem(HttpStatus.CONFLICT, e.code(), e.getMessage());
  }

  @ExceptionHandler(FieldValidationException.class)
  ProblemDetail handleFieldValidation(FieldValidationException e) {
    logHandledException(e, LEVEL_DEBUG, e.code());
    ProblemDetail problem = problem(HttpStatus.BAD_REQUEST, e.code(), e.getMessage());
    problem.setProperty(KEY_DETAILS, List.of(Map.of(KEY_FIELD, e.field(), KEY_MESSAGE, e.getMessage())));
    return problem;
  }

  @ExceptionHandler(TokenExpiredException.class)
  ProblemDetail handleTokenExpired(TokenExpiredException e) {
    logHandledException(e, LEVEL_DEBUG, e.code());
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
    logHandledException(e, LEVEL_DEBUG, e.code());
    return problem(HttpStatus.UNPROCESSABLE_CONTENT, e.code(), e.getMessage());
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  ProblemDetail handleBodyValidation(MethodArgumentNotValidException e) {
    logHandledException(e, LEVEL_DEBUG, CODE_VALIDATION_FAILED);
    ProblemDetail problem =
        problem(HttpStatus.BAD_REQUEST, CODE_VALIDATION_FAILED, "Request validation failed.");
    problem.setProperty(
        KEY_DETAILS,
        e.getBindingResult().getFieldErrors().stream()
            .map(f -> Map.of(
                KEY_FIELD, f.getField(),
                KEY_MESSAGE, String.valueOf(f.getDefaultMessage())))
            .toList());
    return problem;
  }

  @ExceptionHandler(ConstraintViolationException.class)
  ProblemDetail handleParamValidation(ConstraintViolationException e) {
    logHandledException(e, LEVEL_DEBUG, CODE_VALIDATION_FAILED);
    ProblemDetail problem =
        problem(HttpStatus.BAD_REQUEST, CODE_VALIDATION_FAILED, "Request validation failed.");
    List<Map<String, String>> details = e.getConstraintViolations().stream()
        .map(v -> Map.of(
            KEY_FIELD, String.valueOf(v.getPropertyPath()),
            KEY_MESSAGE, v.getMessage()))
        .toList();
    problem.setProperty(KEY_DETAILS, details);
    return problem;
  }

  @ExceptionHandler(InsufficientPermissionException.class)
  ProblemDetail handleInsufficientPermission(InsufficientPermissionException e) {
    Map<String, Object> extraFields = new LinkedHashMap<>();
    extraFields.put("reason", e.getReason().name());
    extraFields.put("requiredPermission", e.getRequiredPermission());
    extraFields.put("userId", MDC.get(AuthenticationDetailKeys.MDC_USER_ID));
    extraFields.put("tenantId", MDC.get(AuthenticationDetailKeys.MDC_TENANT_ID));
    logHandledException(e, "WARN", "RBAC_001", extraFields);
    Counter.builder("nexus.rbac.permission_denied")
        .tag("permission", e.getRequiredPermission())
        .tag("reason", e.getReason().name())
        .register(meterRegistry)
        .increment();
    ProblemDetail problem =
        problem(HttpStatus.FORBIDDEN, "RBAC_001", "You do not have permission to perform this action");
    problem.setProperty("requiredPermission", e.getRequiredPermission());
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
    logHandledException(e, LEVEL_DEBUG, "RESOURCE_NOT_FOUND");
    return problem(HttpStatus.NOT_FOUND, "RESOURCE_NOT_FOUND", "Resource not found.");
  }

  @ExceptionHandler(Exception.class)
  ProblemDetail handleUnexpected(Exception e) {
    String correlationId = MDC.get(CorrelationIdFilter.MDC_CORRELATION_ID_KEY);
    log.atError()
        .addKeyValue(KEY_EVENT, EVENT_API_REQUEST)
        .addKeyValue(KEY_CORRELATION_ID, correlationId)
        .addKeyValue(KEY_OUTCOME, OUTCOME_FAILURE)
        .addKeyValue(KEY_ERROR_TYPE, e.getClass().getSimpleName())
        .addKeyValue(KEY_ERROR_CODE, "INTERNAL_ERROR")
        .log("Unhandled exception traceId=" + correlationId, e);
    return problem(
        HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An unexpected error occurred.");
  }

  private void logHandledException(Exception e, String level, String errorCode) {
    logHandledException(e, level, errorCode, Map.of());
  }

  /**
   * Same base behavior as {@link #logHandledException(Exception, String, String)}, plus any
   * additional structured key-value pairs a specific handler needs (e.g. RBAC denial reason,
   * required permission, userId/tenantId) without duplicating the correlationId lookup and
   * WARN/DEBUG structured-log scaffolding.
   */
  private void logHandledException(
      Exception e, String level, String errorCode, Map<String, Object> extraFields) {
    String correlationId = MDC.get(CorrelationIdFilter.MDC_CORRELATION_ID_KEY);
    String errorType = e.getClass().getSimpleName();
    if ("WARN".equals(level)) {
      var builder = log.atWarn()
          .addKeyValue(KEY_EVENT, EVENT_API_REQUEST)
          .addKeyValue(KEY_CORRELATION_ID, correlationId)
          .addKeyValue(KEY_OUTCOME, OUTCOME_FAILURE)
          .addKeyValue(KEY_ERROR_TYPE, errorType)
          .addKeyValue(KEY_ERROR_CODE, errorCode);
      extraFields.forEach(builder::addKeyValue);
      builder.log("Handled operational error: errorType={} errorCode={} correlationId={}",
          errorType, errorCode, correlationId);
    } else if (LEVEL_DEBUG.equals(level)) {
      var builder = log.atDebug()
          .addKeyValue(KEY_EVENT, EVENT_API_REQUEST)
          .addKeyValue(KEY_CORRELATION_ID, correlationId)
          .addKeyValue(KEY_OUTCOME, OUTCOME_FAILURE)
          .addKeyValue(KEY_ERROR_TYPE, errorType)
          .addKeyValue(KEY_ERROR_CODE, errorCode);
      extraFields.forEach(builder::addKeyValue);
      builder.log("Handled validation/domain error: errorType={} errorCode={} correlationId={}",
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
