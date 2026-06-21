package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.AuthEvent;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JpaAuthEventRepository extends JpaRepository<AuthEvent, UUID> {}
