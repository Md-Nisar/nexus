package com.example.nexus.identity.interfaces.rest.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for {@code POST /api/v1/auth/resend-verification}. */
public record ResendVerificationRequest(
    @NotBlank @Email @Size(max = 254) String email
) {}
