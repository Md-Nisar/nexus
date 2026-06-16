package com.example.nexus;

import com.example.nexus.common.Profiles;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles(Profiles.SMOKE)
class NexusSmokeTest {

    @Test
    void contextLoads() {
    }
}