package com.example.nexus.identity.interfaces.rest.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request body for {@code POST /api/v1/auth/register}.
 *
 * <p>Bean Validation fires before the use-case is called. The password size cap prevents
 * denial-of-service via extremely long inputs; the policy minimum is enforced in the service.
 */
public record RegisterRequest(
    @NotBlank @Email @Size(max = 254) String email,
    @NotBlank @Size(max = 1024) String password,
    @AssertTrue(message = "Consent is required to register.") boolean consentAccepted
) {}
