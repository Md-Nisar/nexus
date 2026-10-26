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
 * <p>The address may not contain a control, format, private-use, unassigned or surrogate character
 * ({@code C}), a space separator ({@code Zs}, {@code Zl}, {@code Zp}), or an invisible filler
 * (Hangul and combining fillers, braille blank, variation selectors): a bidi override
 * or a zero-width character lets a stored address display as a different one in the admin console
 * and in audit surfaces (US-020 F-5, D-1).
 */
public record RegisterRequest(
    @NotBlank
        @Email
        @Size(max = 254)
        @Pattern(
            regexp = "[^\\p{C}\\p{Zs}\\p{Zl}\\p{Zp}\\u034F\\u115F\\u1160\\u3164\\uFFA0\\u2800\\uFFFC\\uFFFD\\uFE00-\\uFE0F\\x{E0100}-\\x{E01EF}]*",
            message = "must not contain hidden or direction-control characters")
        String email,
    @NotBlank @Size(max = 1024) String password,
    @AssertTrue(message = "Consent is required to register.") boolean consentAccepted
) {}
