package com.example.nexus.rbac.domain;

import java.util.UUID;

/** Projection row: a user and one live role through which they hold something (US-018 C3). */
public record UserViaRole(UUID userId, UUID roleId) {}
