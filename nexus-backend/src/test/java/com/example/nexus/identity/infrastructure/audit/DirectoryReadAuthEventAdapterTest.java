package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.service.SecureEventService;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.UuidGenerator;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataAccessResourceFailureException;
import tools.jackson.databind.json.JsonMapper;

/** US-019 T-006 (design §4.5): the best-effort directory read audit row. */
@Tag("UnitTest")
class DirectoryReadAuthEventAdapterTest {

  private static final UUID TENANT = UUID.fromString("019f6839-0000-7000-8000-0000000000a1");
  private static final UUID ACTOR = UUID.fromString("019f6839-0000-7000-8000-0000000000a2");
  private static final UUID EVENT_ID = UUID.fromString("019f6839-0000-7000-8000-0000000000e1");
  private static final String FAILED = "nexus.identity.directory.audit_write_failed";

  private final SecureEventService events = mock(SecureEventService.class);
  private final UuidGenerator ids = mock(UuidGenerator.class);
  private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
  private final DirectoryReadAuthEventAdapter adapter =
      new DirectoryReadAuthEventAdapter(events, ids, JsonMapper.builder().build(), meters);

  @Test
  void should_writeTheRowThroughTheBestEffortPathWithTheMetadataAsJson_when_recording() {
    when(ids.newId()).thenReturn(EVENT_ID);
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("operation", "LIST");
    metadata.put("resultCount", 3);
    metadata.put("statusFilter", null);

    adapter.recordDirectoryRead(TENANT, ACTOR, metadata);

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(events).recordEvent(captor.capture());
    AuthEvent event = captor.getValue();
    assertThat(event.getEventType()).isEqualTo("USER_DIRECTORY_READ");
    assertThat(event.getOutcome()).isEqualTo("SUCCESS");
    assertThat(event.getTenantId()).isEqualTo(TENANT);
    assertThat(event.getUserId()).isEqualTo(ACTOR);
    assertThat(event.getMetadata())
        .isEqualTo("{\"operation\":\"LIST\",\"resultCount\":3,\"statusFilter\":null}");
  }

  @Test
  void should_swallowAndCount_when_theAuditWriteFails() {
    when(ids.newId()).thenReturn(EVENT_ID);
    doThrow(new DataAccessResourceFailureException("secret@example.test"))
        .when(events)
        .recordEvent(any());

    assertThatCode(() -> adapter.recordDirectoryRead(TENANT, ACTOR, Map.of("operation", "GET")))
        .doesNotThrowAnyException();
    assertThat(meters.get(FAILED).counter().count()).isEqualTo(1.0);
  }
}
