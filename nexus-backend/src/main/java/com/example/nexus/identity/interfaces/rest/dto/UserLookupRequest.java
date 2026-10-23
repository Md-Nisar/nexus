package com.example.nexus.identity.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request body of {@code POST /api/v1/users/lookup} (US-019 B1, design §4.3): the email travels in
 * the body so it never reaches a URL, an access log or a link.
 *
 * <p>Surrounding whitespace is removed before validation, so the format check sees the address
 * itself; case and Unicode normalisation remain {@code EmailBlindIndexService}'s alone. None of
 * the constraint messages echo the value, and {@link #toString()} redacts it.
 */
public record UserLookupRequest(
    @Schema(description = "Exact email address to look up", example = "jane.doe@example.com")
        @NotBlank
        @Size(max = 320)
        @Email
        String email) {

  public UserLookupRequest {
    email = email == null ? null : email.trim();
  }

  @Override
  public String toString() {
    return "UserLookupRequest[email=<redacted>]";
  }
}
