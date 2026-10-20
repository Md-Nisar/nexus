package com.example.nexus.rbac.domain;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.UUID;

/**
 * The version of a role's permission set, served as its strong {@code ETag} (US-019 design §10.2,
 * ADR-0027): {@code "rp1-"} followed by the unpadded base64url SHA-256 of the role id's 16 bytes
 * and then each distinct permission id's 16 bytes, ascending as unsigned bytes (the order of their
 * {@code BINARY(16)} column). It is order-independent and role-bound, so ETags are not
 * interchangeable between roles.
 *
 * <p>It is a concurrency validator, not a secret or a capability: anyone who knows the ids can
 * compute it, and no authorization decision depends on knowing it (RC-55.5).
 */
public final class RolePermissionSetVersion {

  private static final String PREFIX = "rp1-";
  private static final int UUID_BYTES = 16;

  private RolePermissionSetVersion() {}

  /** The version of {@code permissionIds} on {@code roleId}; repeated ids count once. */
  public static String of(UUID roleId, Collection<UUID> permissionIds) {
    byte[][] sorted =
        permissionIds.stream()
            .distinct()
            .map(RolePermissionSetVersion::toBytes)
            .sorted(Arrays::compareUnsigned)
            .toArray(byte[][]::new);
    MessageDigest digest = sha256();
    digest.update(toBytes(roleId));
    for (byte[] id : sorted) {
      digest.update(id);
    }
    return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
  }

  private static byte[] toBytes(UUID id) {
    return ByteBuffer.allocate(UUID_BYTES)
        .putLong(id.getMostSignificantBits())
        .putLong(id.getLeastSignificantBits())
        .array();
  }

  private static MessageDigest sha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      // Every Java SE platform must provide SHA-256 (MessageDigest Javadoc).
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }
}
