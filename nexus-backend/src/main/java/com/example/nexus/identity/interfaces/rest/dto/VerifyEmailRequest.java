package com.example.nexus.identity.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/** Request body for {@code POST /api/v1/auth/verify-email}. */
public record VerifyEmailRequest(
    @NotBlank @Pattern(regexp = "[0-9a-f]{64}") String token
) {}
