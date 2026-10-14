package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Unit tests for {@link BreakGlassGrantLookupAdapter} (US-018 A7, RC-37.2, RC-47). */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class BreakGlassGrantLookupAdapterTest {

  @Mock private JpaAuthEventRepository repository;
  @InjectMocks private BreakGlassGrantLookupAdapter adapter;

  @Test
  void should_returnTrue_when_aSuccessfulGrantCarriesTheChangeRef() {
    when(repository.existsSuccessfulBreakGlassGrant("OPS-1")).thenReturn(1L);

    assertThat(adapter.existsSuccessfulGrantWithChangeRef("OPS-1")).isTrue();
  }

  @Test
  void should_returnFalse_when_noSuccessfulGrantCarriesTheChangeRef() {
    when(repository.existsSuccessfulBreakGlassGrant("OPS-1")).thenReturn(0L);

    assertThat(adapter.existsSuccessfulGrantWithChangeRef("OPS-1")).isFalse();
  }

  @Test
  void should_passTheExactChangeRefAsTheBoundParameter() {
    when(repository.existsSuccessfulBreakGlassGrant("ABC-1")).thenReturn(0L);

    adapter.existsSuccessfulGrantWithChangeRef("ABC-1");

    verify(repository).existsSuccessfulBreakGlassGrant("ABC-1");
  }
}
