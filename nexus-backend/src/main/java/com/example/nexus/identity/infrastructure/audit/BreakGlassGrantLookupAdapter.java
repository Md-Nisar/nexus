package com.example.nexus.identity.infrastructure.audit;

import com.example.nexus.common.Profiles;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * US-018 A7 (RC-37.2, RC-47): the break-glass replay check over {@code auth_events}, delegating to
 * the one global, parameter-bound query on {@link JpaAuthEventRepository}.
 */
@Component
@Profile(Profiles.BREAK_GLASS)
public class BreakGlassGrantLookupAdapter implements BreakGlassGrantLookupPort {

  private final JpaAuthEventRepository authEventRepository;

  public BreakGlassGrantLookupAdapter(JpaAuthEventRepository authEventRepository) {
    this.authEventRepository = authEventRepository;
  }

  @Override
  public boolean existsSuccessfulGrantWithChangeRef(String changeRef) {
    return authEventRepository.existsSuccessfulBreakGlassGrant(changeRef) > 0;
  }
}
