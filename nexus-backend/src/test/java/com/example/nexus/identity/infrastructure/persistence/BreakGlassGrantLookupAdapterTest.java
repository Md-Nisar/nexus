package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

/** US-018 T-008 (RC-37.2, RC-47): the global, non-locking change-reference replay lookup. */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class BreakGlassGrantLookupAdapterTest {

  @Mock private JpaAuthEventRepository authEventRepository;

  @InjectMocks private BreakGlassGrantLookupAdapter adapter;

  @Test
  void should_returnTrue_when_aSuccessfulGrantCarriesTheReference() {
    when(authEventRepository.existsSuccessfulBreakGlassGrantWithChangeRef("OPS-42")).thenReturn(1L);

    assertThat(adapter.existsSuccessfulGrantWithChangeRef("OPS-42")).isTrue();
  }

  @Test
  void should_returnFalse_when_noSuccessfulGrantCarriesTheReference() {
    when(authEventRepository.existsSuccessfulBreakGlassGrantWithChangeRef("OPS-42")).thenReturn(0L);

    assertThat(adapter.existsSuccessfulGrantWithChangeRef("OPS-42")).isFalse();
  }

  @Test
  void should_passTheReferenceVerbatim() {
    when(authEventRepository.existsSuccessfulBreakGlassGrantWithChangeRef("ABCDEFGHIJ-12345678"))
        .thenReturn(0L);

    adapter.existsSuccessfulGrantWithChangeRef("ABCDEFGHIJ-12345678");

    verify(authEventRepository).existsSuccessfulBreakGlassGrantWithChangeRef("ABCDEFGHIJ-12345678");
    verifyNoMoreInteractions(authEventRepository);
  }

  /**
   * T-S11: global (no tenant predicate), SUCCESS grants only, unquoted {@code changeRef} against
   * a bound parameter, and never a locking read.
   */
  @Test
  void should_queryGloballyWithABoundParameter_andNeverLock() throws Exception {
    Method method =
        JpaAuthEventRepository.class.getMethod(
            "existsSuccessfulBreakGlassGrantWithChangeRef", String.class);
    Query query = method.getAnnotation(Query.class);

    assertThat(method.getAnnotation(Lock.class)).isNull();
    assertThat(query.nativeQuery()).isTrue();
    assertThat(query.value())
        .contains("event_type = 'ROLE_BREAK_GLASS_GRANT'")
        .contains("outcome = 'SUCCESS'")
        .contains("JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.changeRef')) = :changeRef")
        .doesNotContainIgnoringCase("tenant_id")
        .doesNotContainIgnoringCase("FOR UPDATE")
        .doesNotContainIgnoringCase("FOR SHARE");
  }
}
