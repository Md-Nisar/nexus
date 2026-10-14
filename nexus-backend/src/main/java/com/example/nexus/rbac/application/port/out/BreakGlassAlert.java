package com.example.nexus.rbac.application.port.out;

import java.util.UUID;

/**
 * The payload of the {@code RBAC_BREAK_GLASS_USED} page (US-018 A7, 03-design.md §7.2). Every
 * field except {@code outcome} may be {@code null} and is then <b>omitted</b> from the page: an
 * argument-validation refusal never carries {@code targetUserId} or {@code changeRef} (L-6,
 * RC-54(a)).
 *
 * @param outcome {@code GRANTED} or {@code REFUSED}
 * @param reason the refusal reason; {@code null} on a grant
 */
public record BreakGlassAlert(
    UUID tenantId, UUID targetUserId, String outcome, String reason, String changeRef) {

  public static final String OUTCOME_GRANTED = "GRANTED";
  public static final String OUTCOME_REFUSED = "REFUSED";
}
