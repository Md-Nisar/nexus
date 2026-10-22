package com.example.nexus.rbac.domain;

import java.util.UUID;

/**
 * One active holder of a role together with the user who assigned them (US-018 T-017, 03-design.md
 * §5.1 rows 13 and 14, §5.6). Ids only. {@code assignedBy} is {@code NOT NULL} in {@code
 * user_roles}; for a break-glass grant it equals {@code userId}.
 */
public record HolderProvenance(UUID userId, UUID assignedBy) {}
