package com.example.nexus;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * Boots the full application against a real MySQL (Testcontainers), including Flyway migrations.
 * Runs in the failsafe phase ({@code mvn verify}); requires Docker. Skip locally with
 * {@code -DskipITs} when Docker is unavailable.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class NexusApplicationIT {

    @Test
    void contextLoads_withRealDatabase_andMigrationsApplied() {
        // Context startup validates: Flyway baseline applies, JPA schema validation passes,
        // security filter chain builds.
    }
}
