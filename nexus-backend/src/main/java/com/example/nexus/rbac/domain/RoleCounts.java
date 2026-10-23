package com.example.nexus.rbac.domain;

import java.util.UUID;

/**
 * The B6 counts of one role (US-019 03-design.md §8): its active holders and its attached
 * permissions. A projection built from two grouped queries per page; it carries no tenant id
 * because both queries are tenant-predicated.
 */
public record RoleCounts(UUID roleId, long memberCount, int permissionCount) {}
