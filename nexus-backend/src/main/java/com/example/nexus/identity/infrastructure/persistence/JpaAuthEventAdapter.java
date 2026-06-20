package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.domain.AuthEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;

/**
 * JPA-backed {@link AuthEventPort}. Persistence failures are swallowed and logged at WARN —
 * a failed audit write must never roll back or block the primary user flow.
 */
@Component
public class JpaAuthEventAdapter implements AuthEventPort {

  private static final Logger log = LoggerFactory.getLogger(JpaAuthEventAdapter.class);

  private final JpaAuthEventRepository authEventRepository;

  public JpaAuthEventAdapter(JpaAuthEventRepository authEventRepository) {
    this.authEventRepository = authEventRepository;
  }

  @Override
  public void record(AuthEvent event) {
    try {
      authEventRepository.save(event);
    } catch (DataAccessException e) {
      log.warn("Failed to persist auth event [type={}]: {}",
          event.getEventType(), e.getMessage());
    }
  }
}
