package com.example.nexus.identity.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for {@code POST /api/v1/auth/password/reset}. */
public record ResetPasswordRequest(
    @NotBlank @Size(min = 64, max = 64) String token,
    @NotBlank @Size(max = 256) String newPassword) {}
