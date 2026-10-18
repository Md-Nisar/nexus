package com.example.nexus.rbac.interfaces.rest.dto;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.rbac.domain.PageResult;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class PageLinksTest {

  private static PageResult<String> page(long total, int page, int size) {
    return new PageResult<>(List.of(), total, page, size);
  }

  @Test
  void should_haveNoLinks_when_theOnlyPage() {
    PageLinks links = PageLinks.of("/api/v1/roles", page(3, 0, 20));

    assertThat(links.next()).isNull();
    assertThat(links.prev()).isNull();
  }

  @Test
  void should_haveNoLinks_when_thereAreNoRows() {
    PageLinks links = PageLinks.of("/api/v1/roles", page(0, 0, 20));

    assertThat(links.next()).isNull();
    assertThat(links.prev()).isNull();
  }

  @Test
  void should_linkNextAndCarryTheSize_when_first() {
    PageLinks links = PageLinks.of("/api/v1/roles", page(41, 0, 20));

    assertThat(links.next()).isEqualTo("/api/v1/roles?page=1&size=20");
    assertThat(links.prev()).isNull();
  }

  @Test
  void should_linkBothWays_when_middle() {
    PageLinks links = PageLinks.of("/api/v1/roles", page(41, 1, 20));

    assertThat(links.next()).isEqualTo("/api/v1/roles?page=2&size=20");
    assertThat(links.prev()).isEqualTo("/api/v1/roles?page=0&size=20");
  }

  @Test
  void should_linkOnlyPrev_when_last() {
    PageLinks links = PageLinks.of("/api/v1/roles", page(41, 2, 20));

    assertThat(links.next()).isNull();
    assertThat(links.prev()).isEqualTo("/api/v1/roles?page=1&size=20");
  }

  /** A page past the end links back to the last real page, not to another empty one. */
  @Test
  void should_linkBackToTheLastRealPage_when_pastTheEnd() {
    PageLinks links = PageLinks.of("/api/v1/roles", page(41, 50, 20));

    assertThat(links.next()).isNull();
    assertThat(links.prev()).isEqualTo("/api/v1/roles?page=2&size=20");
  }

  @Test
  void should_linkBackToPageZero_when_pastTheEndOfAnEmptyCollection() {
    PageLinks links = PageLinks.of("/api/v1/roles", page(0, 3, 20));

    assertThat(links.prev()).isEqualTo("/api/v1/roles?page=0&size=20");
  }

  @Test
  void should_mapMetadataFromTheResult() {
    PageMetadata metadata = PageMetadata.of(page(142, 3, 20));

    assertThat(metadata).isEqualTo(new PageMetadata(20, 3, 142, 8));
  }
}
