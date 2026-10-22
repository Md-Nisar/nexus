package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@Tag("UnitTest")
class PageResultTest {

  @ParameterizedTest
  @CsvSource({"0,20,0", "1,20,1", "20,20,1", "21,20,2", "100,100,1", "101,100,2", "142,20,8"})
  void should_computeCeilOfTotalOverSize_when_totalPagesAsked(long total, int size, int expected) {
    assertThat(new PageResult<>(List.of(), total, 0, size).totalPages()).isEqualTo(expected);
  }

  @Test
  void should_haveNoPages_when_sizeIsNotPositive() {
    assertThat(new PageResult<>(List.of(), 5, 0, 0).totalPages()).isZero();
  }

  @Test
  void should_copyTheItemsDefensively_when_constructed() {
    List<String> source = new ArrayList<>(List.of("a"));
    PageResult<String> result = new PageResult<>(source, 1, 0, 20);

    source.add("b");

    assertThat(result.items()).containsExactly("a");
    assertThatThrownBy(() -> result.items().add("c")).isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void should_mapItemsAndKeepThePagingFacts_when_mapped() {
    PageResult<Integer> mapped = new PageResult<>(List.of("a", "bb"), 9, 3, 2).map(String::length);

    assertThat(mapped.items()).containsExactly(1, 2);
    assertThat(mapped.totalElements()).isEqualTo(9);
    assertThat(mapped.page()).isEqualTo(3);
    assertThat(mapped.size()).isEqualTo(2);
  }
}
