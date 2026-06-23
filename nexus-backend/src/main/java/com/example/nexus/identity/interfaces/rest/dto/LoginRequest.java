package com.example.nexus.identity.interfaces.rest.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
    @Email @NotBlank @Size(max = 254) String email,
    @NotBlank @Size(max = 256) String password) {}
