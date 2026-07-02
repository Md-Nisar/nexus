package com.example.nexus.identity.interfaces.rest;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.RegisterUserUseCase;
import com.example.nexus.identity.application.ResendVerificationUseCase;
import com.example.nexus.identity.application.VerifyEmailUseCase;
import com.example.nexus.identity.interfaces.rest.dto.RegisterRequest;
import com.example.nexus.identity.interfaces.rest.dto.RegisterResponse;
import com.example.nexus.identity.interfaces.rest.dto.ResendVerificationRequest;
import com.example.nexus.identity.interfaces.rest.dto.ResendVerificationResponse;
import com.example.nexus.identity.interfaces.rest.dto.VerifyEmailRequest;
import com.example.nexus.identity.interfaces.rest.dto.VerifyEmailResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.Locale;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP interface for self-service registration and email verification (US-002).
 *
 * <p>Active only when {@code feature.nexus-us002-auth-registration.enabled=true}; absent bean
 * causes Spring MVC to return 404, consistent with the {@code SecurityConfig} permit-all rules.
 */
@RestController
@RequestMapping("/api/v1/auth")
@ConditionalOnProperty(
    name = "feature.nexus-us002-auth-registration.enabled",
    havingValue = "true")
@Tag(name = "Authentication", description = "Self-service registration and email verification")
public class RegistrationController {

  private final RegisterUserUseCase registerUseCase;
  private final VerifyEmailUseCase verifyEmailUseCase;
  private final ResendVerificationUseCase resendVerificationUseCase;
  private final UUID defaultTenantId;

  /** Constructs the controller with its required use-cases and tenant configuration. */
  public RegistrationController(
      RegisterUserUseCase registerUseCase,
      VerifyEmailUseCase verifyEmailUseCase,
      ResendVerificationUseCase resendVerificationUseCase,
      @Value("${nexus.identity.default-tenant-id}") UUID defaultTenantId) {
    this.registerUseCase = registerUseCase;
    this.verifyEmailUseCase = verifyEmailUseCase;
    this.resendVerificationUseCase = resendVerificationUseCase;
    this.defaultTenantId = defaultTenantId;
  }

  /** Registers a new user account or silently acknowledges a duplicate (anti-enumeration). */
  @PostMapping("/register")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(summary = "Register a new user account")
  @ApiResponse(
      responseCode = "201",
      description = "Registration accepted (new or duplicate — identical response)")
  @ApiResponse(responseCode = "400", description = "Validation or password policy failure")
  public RegisterResponse register(
      @Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
    registerUseCase.register(
        defaultTenantId,
        request.email().toLowerCase(Locale.ROOT).strip(),
        request.password(),
        requestContext(httpRequest));
    return new RegisterResponse(
        "Registration successful. Please check your email to verify your account.");
  }

  /** Verifies an email address using the one-time token sent during registration. */
  @PostMapping("/verify-email")
  @Operation(summary = "Verify an email address using the one-time token")
  @ApiResponse(responseCode = "200", description = "Email verified successfully")
  @ApiResponse(
      responseCode = "410",
      description = "Token expired, already used, or not found")
  public VerifyEmailResponse verifyEmail(
      @Valid @RequestBody VerifyEmailRequest request, HttpServletRequest httpRequest) {
    verifyEmailUseCase.verify(request.token(), requestContext(httpRequest));
    return new VerifyEmailResponse("Email verified successfully. You can now log in.");
  }

  /** Sends a new verification email; returns the same response regardless of account state. */
  @PostMapping("/resend-verification")
  @Operation(summary = "Request a new verification email")
  @ApiResponse(
      responseCode = "200",
      description = "Request accepted (anti-enumeration: same response whether account exists)")
  @ApiResponse(responseCode = "429", description = "Rate limit exceeded")
  public ResendVerificationResponse resendVerification(
      @Valid @RequestBody ResendVerificationRequest request, HttpServletRequest httpRequest) {
    resendVerificationUseCase.resend(
        defaultTenantId,
        request.email().toLowerCase(Locale.ROOT).strip(),
        requestContext(httpRequest));
    return new ResendVerificationResponse(
        "If your account is pending verification, a new link has been sent.");
  }

  private RequestContext requestContext(HttpServletRequest req) {
    // user_agent is advisory forensic context only, never an authorization input -- captured
    // verbatim; RequestContext.of(...) caps and escapes it before it reaches storage.
    return RequestContext.of(
        req.getRemoteAddr(), MDC.get("traceId"), req.getHeader("User-Agent"));
  }
}
