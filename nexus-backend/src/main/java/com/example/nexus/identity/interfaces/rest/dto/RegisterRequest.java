package com.example.nexus.identity.interfaces.rest.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request body for {@code POST /api/v1/auth/register}.
 *
 * <p>Bean Validation fires before the use-case is called. The password size cap prevents
 * denial-of-service via extremely long inputs; the policy minimum is enforced in the service.
 *
 * <p>The address may not contain a format, space-separator or invisible filler character
 * ({@code Cf}, {@code Zs}, {@code Zl}, {@code Zp} and the Hangul/combining fillers): a bidi override
 * or a zero-width character lets a stored address display as a different one in the admin console
 * and in audit surfaces (US-020 F-5, D-1).
 */
public record RegisterRequest(
    @NotBlank
        @Email
        @Size(max = 254)
        @Pattern(
            regexp = "[^\\p{Cf}\\p{Zs}\\p{Zl}\\p{Zp}\\u034F\\u115F\\u1160\\u3164\\uFFA0]*",
            message = "must not contain hidden or direction-control characters")
        String email,
    @NotBlank @Size(max = 1024) String password,
    @AssertTrue(message = "Consent is required to register.") boolean consentAccepted
) {}
