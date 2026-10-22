package com.example.nexus.rbac.domain;

import java.util.UUID;

/** Projection row: a permission name and one live role through which a user holds it (C3). */
public record PermissionViaRole(String permissionName, UUID roleId) {}
