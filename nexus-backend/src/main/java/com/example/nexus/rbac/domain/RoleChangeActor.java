package com.example.nexus.rbac.domain;

import java.util.UUID;

/**
 * The authenticated caller performing a role assignment/revocation, deliberately free of any
 * {@code org.springframework.security} type (ArchUnit-enforced — {@code rbac.application} must
 * never depend on Spring Security, per 03-design.md §4.6/T-E10).
 */
public record RoleChangeActor(UUID userId, UUID tenantId) {}
