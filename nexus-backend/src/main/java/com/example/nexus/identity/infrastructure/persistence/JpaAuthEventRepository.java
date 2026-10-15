package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.AuthEvent;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface JpaAuthEventRepository extends JpaRepository<AuthEvent, UUID> {

  /**
   * US-018 T-008 (RC-37.2, RC-47; 03-design.md §7.2): {@code 1} if a {@code
   * ROLE_BREAK_GLASS_GRANT} SUCCESS row in ANY tenant carries exactly {@code changeRef} as its
   * unquoted {@code metadata.changeRef}, else {@code 0}. Global by design (a reference approves one
   * grant anywhere), non-locking, and bound, never concatenated. Bounded by {@code
   * idx_auth_events_event_type_created_at}.
   */
  @Query(
      value =
          "SELECT EXISTS(SELECT 1 FROM auth_events"
              + " WHERE event_type = 'ROLE_BREAK_GLASS_GRANT' AND outcome = 'SUCCESS'"
              + " AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.changeRef')) = :changeRef)",
      nativeQuery = true)
  long existsSuccessfulBreakGlassGrantWithChangeRef(@Param("changeRef") String changeRef);
}
