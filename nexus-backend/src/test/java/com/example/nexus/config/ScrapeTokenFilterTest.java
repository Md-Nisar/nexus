package com.example.nexus.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.example.nexus.identity.infrastructure.web.ScrapeTokenFilter;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;

/** Unit tests for {@link ScrapeTokenFilter} (pre-PR security re-review RR-M2). */
@Tag("UnitTest")
class ScrapeTokenFilterTest {

  private static final String TOKEN = "unit-test-scrape-token-0123456789-abcdef";
  private static final RequestMatcher METRICS =
      request -> request.getRequestURI().startsWith("/actuator/");

  @AfterEach
  void clearContext() {
    SecurityContextHolder.clearContext();
  }

  private static MockHttpServletRequest request(String path, String authorization) {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    if (authorization != null) {
      request.addHeader("Authorization", authorization);
    }
    return request;
  }

  @Test
  void should_closeTheEndpoints_when_noTokenConfigured() throws Exception {
    ScrapeTokenFilter filter = new ScrapeTokenFilter(METRICS, "");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request("/actuator/prometheus", "Bearer anything"), response, chain);

    assertThat(response.getStatus()).isEqualTo(403);
    verify(chain, never()).doFilter(org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.any());
  }

  @Test
  void should_reject_when_tokenMissingWrongOrNotBearer() throws Exception {
    ScrapeTokenFilter filter = new ScrapeTokenFilter(METRICS, TOKEN);
    for (String header : new String[] {null, "Bearer " + TOKEN + "x", "Bearer ", TOKEN,
        "Basic " + TOKEN}) {
      MockHttpServletResponse response = new MockHttpServletResponse();
      FilterChain chain = mock(FilterChain.class);

      filter.doFilter(request("/actuator/prometheus", header), response, chain);

      assertThat(response.getStatus()).as("header=%s", header).isEqualTo(401);
      verify(chain, never()).doFilter(org.mockito.ArgumentMatchers.any(),
          org.mockito.ArgumentMatchers.any());
    }
  }

  @Test
  void should_authenticateAndMarkTheRequest_when_tokenMatches() throws Exception {
    ScrapeTokenFilter filter = new ScrapeTokenFilter(METRICS, TOKEN);
    MockHttpServletRequest request = request("/actuator/prometheus", "Bearer " + TOKEN);
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
    assertThat(request.getAttribute(ScrapeTokenFilter.AUTHENTICATED_ATTRIBUTE)).isEqualTo(true);
    assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
        .extracting(Object::toString)
        .containsExactly(ScrapeTokenFilter.AUTHORITY);
  }

  @Test
  void should_passOtherRequestsThroughUntouched() throws Exception {
    ScrapeTokenFilter filter = new ScrapeTokenFilter(METRICS, TOKEN);
    MockHttpServletRequest request = request("/api/v1/users/me", null);
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
    assertThat(request.getAttribute(ScrapeTokenFilter.AUTHENTICATED_ATTRIBUTE)).isNull();
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  @Test
  void should_refuseAShortToken_atStartup() {
    assertThatThrownBy(() -> new ScrapeTokenFilter(METRICS, "too-short"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageNotContaining("too-short");
  }
}
