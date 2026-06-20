package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import com.example.nexus.identity.domain.AuthEvent;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

@ExtendWith(MockitoExtension.class)
class JpaAuthEventAdapterTest {

  @Mock
  private JpaAuthEventRepository authEventRepository;

  @InjectMocks
  private JpaAuthEventAdapter adapter;

  @Test
  void record_savesEvent_onSuccess() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), "REGISTRATION_SUCCESS", "SUCCESS");

    adapter.record(event);

    verify(authEventRepository).save(event);
  }

  @Test
  void record_swallowsDataAccessException_andDoesNotRethrow() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), "REGISTRATION_FAILED", "FAILURE");
    doThrow(new DataIntegrityViolationException("DB error"))
        .when(authEventRepository).save(event);

    assertThatCode(() -> adapter.record(event)).doesNotThrowAnyException();
  }
}
