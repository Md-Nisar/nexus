package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.AuthEvent;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface JpaAuthEventRepository extends JpaRepository<AuthEvent, UUID> {

  /**
   * US-018 A7 (RC-37.2, RC-47): {@code 1} when a SUCCESS {@code ROLE_BREAK_GLASS_GRANT} row in
   * <b>any</b> tenant carries exactly this change reference, else {@code 0}.
   *
   * <p>Deliberately <b>global</b> (no tenant predicate; allowlisted in {@code
   * TenantIsolationArchitectureTest}): a reference approves one grant anywhere. Non-locking, and
   * bounded by {@code idx_auth_events_event_type_created_at} on {@code event_type}. {@code
   * changeRef} is a bound parameter, never concatenated; the comparison is on the unquoted JSON
   * string, so it is exact (the canonical pattern admits no padded variants).
   */
  @Query(
      value =
          "SELECT EXISTS (SELECT 1 FROM auth_events"
              + " WHERE event_type = 'ROLE_BREAK_GLASS_GRANT' AND outcome = 'SUCCESS'"
              + " AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.changeRef')) = :changeRef)",
      nativeQuery = true)
  long existsSuccessfulBreakGlassGrant(@Param("changeRef") String changeRef);
}
