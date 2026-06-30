package com.example.nexus.identity.interfaces.rest;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.ForgotPasswordUseCase;
import com.example.nexus.identity.application.ResetPasswordUseCase;
import com.example.nexus.identity.interfaces.rest.dto.ForgotPasswordRequest;
import com.example.nexus.identity.interfaces.rest.dto.ForgotPasswordResponse;
import com.example.nexus.identity.interfaces.rest.dto.ResetPasswordRequest;
import com.example.nexus.identity.interfaces.rest.dto.ResetPasswordResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.Locale;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP interface for self-service password reset (US-007).
 *
 * <p>Both endpoints are {@code permitAll} — no authentication header required. No
 * {@code @ConditionalOnProperty}: this feature has no feature flag (US-007 technical notes).
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Self-service password reset")
public class PasswordResetController {

  private final ForgotPasswordUseCase forgotPasswordUseCase;
  private final ResetPasswordUseCase resetPasswordUseCase;
  private final UUID defaultTenantId;

  /** Constructs the controller with its required use-cases and tenant configuration. */
  public PasswordResetController(
      ForgotPasswordUseCase forgotPasswordUseCase,
      ResetPasswordUseCase resetPasswordUseCase,
      @Value("${nexus.identity.default-tenant-id}") UUID defaultTenantId) {
    this.forgotPasswordUseCase = forgotPasswordUseCase;
    this.resetPasswordUseCase = resetPasswordUseCase;
    this.defaultTenantId = defaultTenantId;
  }

  /**
   * Accepts a password-reset request. Always returns 202 regardless of account existence
   * (anti-enumeration, AC-1).
   */
  @PostMapping("/password/forgot")
  @ResponseStatus(HttpStatus.ACCEPTED)
  @Operation(summary = "Request a password-reset link via email")
  @ApiResponse(responseCode = "202", description = "Request accepted (anti-enumeration: same response whether account exists)")
  @ApiResponse(responseCode = "400", description = "Structurally invalid request (blank or malformed email)")
  public ForgotPasswordResponse forgotPassword(
      @Valid @RequestBody ForgotPasswordRequest request,
      HttpServletRequest httpRequest) {
    forgotPasswordUseCase.execute(
        defaultTenantId,
        request.email().toLowerCase(Locale.ROOT).strip(),
        requestContext(httpRequest));
    return new ForgotPasswordResponse(
        "If an account with that email exists, a reset link has been sent.");
  }

  /**
   * Redeems a password-reset token and sets a new password.
   */
  @PostMapping("/password/reset")
  @Operation(summary = "Reset password using the one-time reset token")
  @ApiResponse(responseCode = "200", description = "Password reset successfully")
  @ApiResponse(responseCode = "410", description = "Token expired, already used, or not found")
  @ApiResponse(responseCode = "400", description = "Password policy violation or same-as-current password")
  public ResetPasswordResponse resetPassword(
      @Valid @RequestBody ResetPasswordRequest request,
      HttpServletRequest httpRequest) {
    resetPasswordUseCase.execute(
        request.token(),
        request.newPassword(),
        requestContext(httpRequest));
    return new ResetPasswordResponse("Password reset successfully. Please sign in.");
  }

  private RequestContext requestContext(HttpServletRequest req) {
    return new RequestContext(req.getRemoteAddr(), MDC.get("traceId"));
  }
}
