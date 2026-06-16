package com.example.nexus.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Append-only audit record for identity-related events (logins, token operations, etc.).
 *
 * <p>Immutability is enforced at the database level via BEFORE UPDATE/DELETE triggers.
 */
@Entity
@Table(name = "auth_events")
@Getter
@NoArgsConstructor(access = lombok.AccessLevel.PROTECTED)
public class AuthEvent {

  @Id
  @Column(name = "id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID id;

  @Column(name = "user_id", columnDefinition = "BINARY(16)")
  private UUID userId; // nullable — unknown-email attacks

  @Column(name = "tenant_id", columnDefinition = "BINARY(16)")
  private UUID tenantId; // nullable — pre-auth events

  @Column(name = "event_type", length = 64, nullable = false)
  private String eventType;

  @Column(name = "outcome", length = 20, nullable = false)
  private String outcome;

  @Column(name = "ip_address", length = 45)
  private String ipAddress;

  @Column(name = "metadata", columnDefinition = "JSON")
  private String metadata; // stored as JSON string; no updated_at (append-only)

  @Column(name = "created_at", insertable = false, updatable = false)
  private Instant createdAt;

  // NO @Version, NO updated_at — append-only (enforced by DB trigger)

  /**
   * Creates an auth event with the minimum required fields; optional fields default to {@code
   * null}.
   */
  public AuthEvent(UUID id, String eventType, String outcome) {
    this.id = id;
    this.eventType = eventType;
    this.outcome = outcome;
  }
}
