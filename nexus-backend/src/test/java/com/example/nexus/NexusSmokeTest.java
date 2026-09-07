package com.example.nexus;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.Profiles;
import com.example.nexus.rbac.interfaces.rest.PermissionController;
import com.example.nexus.rbac.interfaces.rest.RoleController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

// Deliberately untagged: exempt from the Unit/WebSlice/DataSlice/IT classification
// (docs/TESTING.md) — the one H2, no-Docker, full-context boot check that must always
// run under Surefire regardless of tag-based filtering.
@SpringBootTest
@ActiveProfiles(Profiles.SMOKE)
class NexusSmokeTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    void contextLoads() {
        // Context loads successfully if this block executes.
    }

    // US-015 T-008: application-smoke.yml carries no
    // feature.nexus-us015-rbac-role-management entry, so it must inherit application.yml's
    // default-off value — confirmed here against the real smoke-profile context rather than a
    // simulated one.
    @Test
    void should_notRegisterRbacRoleManagementControllers_when_smokeProfileActive() {
        assertThat(applicationContext.getBeansOfType(RoleController.class)).isEmpty();
        assertThat(applicationContext.getBeansOfType(PermissionController.class)).isEmpty();
    }
}