package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import org.springframework.stereotype.Component;

/**
 * US-018 T-008 (RC-37.2, RC-47): the global, non-locking change-reference replay lookup over
 * {@code auth_events}. A database failure propagates, so the break-glass run fails closed.
 */
@Component
public class BreakGlassGrantLookupAdapter implements BreakGlassGrantLookupPort {

  private final JpaAuthEventRepository authEventRepository;

  public BreakGlassGrantLookupAdapter(JpaAuthEventRepository authEventRepository) {
    this.authEventRepository = authEventRepository;
  }

  @Override
  public boolean existsSuccessfulGrantWithChangeRef(String changeRef) {
    return authEventRepository.existsSuccessfulBreakGlassGrantWithChangeRef(changeRef) != 0;
  }
}
