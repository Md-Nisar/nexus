package com.example.nexus.rbac.application.port.out;

import java.util.UUID;

/**
 * The minimal view of a user that {@code rbac} needs for the break-glass precondition (US-018 A7,
 * 03-design.md §7.1): its tenant and whether it is {@code ACTIVE}. Port-local so {@code rbac}
 * never imports {@code identity.domain.UserStatus}.
 */
public record DirectoryUser(UUID tenantId, boolean active) {}
