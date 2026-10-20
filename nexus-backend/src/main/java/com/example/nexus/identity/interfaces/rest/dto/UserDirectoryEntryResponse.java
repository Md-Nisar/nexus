package com.example.nexus.identity.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;

/**
 * One user of the directory (US-019 B1, design §4.2): exactly these five fields, never the tenant,
 * blind index, password hash, counters or lock expiry.
 */
public record UserDirectoryEntryResponse(
    @Schema(example = "019f6839-1808-7000-8000-000000000009") String userId,
    @Schema(example = "ada@example.com") String email,
    @Schema(
            description =
                "Stored status. A LOCKED user whose lock has expired stays LOCKED until their next"
                    + " login.",
            allowableValues = {"PENDING", "ACTIVE", "LOCKED", "DISABLED"})
        String status,
    @Schema(description = "Whether the email has been verified; emails are self-asserted until then")
        boolean emailVerified,
    @Schema(example = "2026-01-01T00:00:00Z") Instant createdAt) {}
