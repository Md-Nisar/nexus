package com.example.nexus.rbac.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.persistence.QueryHint;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import org.junit.jupiter.api.Test;
import org.springframework.data.jpa.repository.QueryHints;

class JpaUserRoleRepositoryTest {

  @Test
  void should_enforce_query_timeout_on_locking_reads() throws Exception {
    Method method =
        JpaUserRoleRepository.class.getMethod(
            "lockActiveAssignmentHoldersByRoles", Collection.class, byte[].class);

    QueryHints queryHints = method.getAnnotation(QueryHints.class);
    assertThat(queryHints)
        .as("QueryHints annotation must be present on lockActiveAssignmentHoldersByRoles")
        .isNotNull();

    boolean hasTimeoutHint =
        Arrays.stream(queryHints.value())
            .anyMatch(
                hint ->
                    "jakarta.persistence.query.timeout".equals(hint.name())
                        && "5000".equals(hint.value()));

    assertThat(hasTimeoutHint)
        .as("Locking read must specify jakarta.persistence.query.timeout of 5000ms")
        .isTrue();
  }
}
