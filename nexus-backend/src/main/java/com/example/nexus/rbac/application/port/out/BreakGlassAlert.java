package com.example.nexus.rbac.application.port.out;

import java.util.UUID;

/**
 * Payload of the {@code RBAC_BREAK_GLASS_USED} page (US-018 A7, 03-design.md §7.2). Every field
 * may be {@code null}; a {@code null} field is omitted from the emitted log line.
 *
 * <p>On {@code INVALID_ARGUMENT} (RC-54(a), L-6) {@code tenantId}, {@code targetUserId} and
 * {@code changeRef} are all {@code null}: no rejected argument value is ever paged.
 *
 * @param tenantId the target user's tenant; {@code null} when the target user does not exist,
 *     on {@code CHANGE_REF_REUSED} (checked before the user lookup) and on {@code
 *     INVALID_ARGUMENT}
 * @param targetUserId the target user; {@code null} on {@code INVALID_ARGUMENT}
 * @param outcome whether the invocation granted or was refused
 * @param reason the refusal reason name, {@code null} on a grant
 * @param changeRef the operator-supplied change reference; {@code null} on {@code
 *     INVALID_ARGUMENT}
 */
public record BreakGlassAlert(
    UUID tenantId, UUID targetUserId, Outcome outcome, String reason, String changeRef) {

  /** The two outcomes of a break-glass invocation; the constant name is the logged value. */
  public enum Outcome {
    GRANTED,
    REFUSED
  }
}
