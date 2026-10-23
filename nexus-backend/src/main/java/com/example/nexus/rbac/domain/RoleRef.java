package com.example.nexus.rbac.domain;

import java.util.UUID;

/** Projection row: a live role a user actively holds, by id and name (US-019 B4). */
public record RoleRef(UUID roleId, String name) {}
