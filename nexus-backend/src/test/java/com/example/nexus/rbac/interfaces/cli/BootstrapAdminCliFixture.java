package com.example.nexus.rbac.interfaces.cli;

import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.BreakGlassOutcome;
import java.util.UUID;

/**
 * Test-only ArchUnit fixture (US-018 T-007, EC2): a caller of {@link BootstrapAdminService} in
 * {@code rbac.interfaces.cli}, the one package the containment rule admits. Not a Spring bean.
 */
public class BootstrapAdminCliFixture {

  private final BootstrapAdminService bootstrapAdminService;

  public BootstrapAdminCliFixture(BootstrapAdminService bootstrapAdminService) {
    this.bootstrapAdminService = bootstrapAdminService;
  }

  public BreakGlassOutcome run(UUID targetUserId, String changeRef) {
    return bootstrapAdminService.grantFirstAdmin(targetUserId, changeRef);
  }
}
