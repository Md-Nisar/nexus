package com.example.nexus;

import com.example.nexus.common.Profiles;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

// Deliberately untagged: exempt from the Unit/WebSlice/DataSlice/IT classification
// (docs/TESTING.md) — the one H2, no-Docker, full-context boot check that must always
// run under Surefire regardless of tag-based filtering.
@SpringBootTest
@ActiveProfiles(Profiles.SMOKE)
class NexusSmokeTest {

    @Test
    void contextLoads() {
    }
}