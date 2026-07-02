package com.example.nexus.identity.infrastructure.audit;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * US-008 T-08-20 (design §4.1, Test Scenario 5) — shared load-generation mechanics for {@link
 * AuthEventLoadSmokeIT} (Tier 2, default gate) and {@link AuthEventLoadIT} (Tier 1, {@code
 * @Tag("perf")}, manual-only). Both tests exercise the identical harness at different {@code
 * ratePerSecond}/{@code duration} parameters so the mechanics themselves are proven cheaply by the
 * smoke tier before the expensive 10-minute tier is ever run.
 *
 * <p><b>Client concurrency model:</b> offered requests are submitted onto a virtual-thread-per-
 * task {@link ExecutorService} ({@link Executors#newVirtualThreadPerTaskExecutor()}) — matching
 * this codebase's own server-side {@code spring.threads.virtual.enabled=true} posture
 * (application.yml) applied symmetrically to the load-generating client, not just noted as a
 * server property. Each submitted task performs one blocking {@link RestTemplate} call; virtual
 * threads mean the harness never has to hand-tune a fixed platform-thread pool size to keep pace
 * with Argon2's deliberately expensive, largely serialized per-request hashing cost (~30-80ms/call
 * at the OWASP-2023 production parameters this test suite runs under — see class Javadoc on the
 * two IT classes for why Argon2 is NOT reduced for this scenario).
 *
 * <p><b>Rate shaping:</b> {@link #run(RestTemplate, String, String, String, int, Duration)} submits
 * {@code ratePerSecond} new tasks per second for {@code duration}, spread evenly across each
 * second (submissions paced at {@code 1s / ratePerSecond} intervals, not fired in one
 * instantaneous per-second burst) using {@code System.nanoTime()}-based pacing rather than {@code
 * Thread.sleep} per request. Submission is decoupled from completion, so a slow individual
 * response never throttles the *offered* load, which is what "N RPS sustained" means for this
 * scenario (in-flight backlog, not completed-transaction rate) — but smoothing submission within
 * each second avoids an artificial instantaneous-concurrency spike (e.g. all 100 of a second's
 * requests landing on the connection pool within the same millisecond) that would not reflect
 * real-world arrival patterns and would understate the pool sizing a genuinely smooth 100 RPS
 * needs. See each IT's {@code hikari.maximum-pool-size} override for the corresponding
 * server-side connection budget.
 */
final class LoadTestHarness {

  private LoadTestHarness() {}

  record Result(int offered, int succeeded, int failed, int serverErrors) {}

  /**
   * KNOWN FINDING, addressed here (zero new dependency): plain {@code new RestTemplate()} uses
   * {@link SimpleClientHttpRequestFactory}, backed by the JDK's built-in {@code
   * HttpURLConnection}, whose connection reuse relies on the JVM-global {@code
   * sun.net.www.http.KeepAliveCache}. Under high concurrent connection churn (100 RPS x hundreds
   * of virtual threads against one host:port) that cache's small default capacity leads to
   * "Unexpected end of file from server" (a pooled connection reused after the peer half-closed
   * it) — confirmed by stack trace during the first Tier 1 run, not a server-side or
   * audit-pipeline defect (Tier 2 at 10 RPS never hit this; embedded Tomcat's own defaults,
   * {@code max-connections=8192} + the virtual-thread request executor, are nowhere near capacity
   * at this concurrency). This codebase has no HTTP client library already on the classpath
   * (verified: no Apache HttpClient, OkHttp, or reactor-netty in the dependency tree) and adding
   * one is a bigger decision than this QA-scoped harness warrants ("no new deps without
   * justification"). Fix: raise the JDK KeepAlive cache's effective ceiling via {@code
   * http.maxConnections} (JVM-wide, set once, harness-only — never touches a production file) and
   * set explicit connect/read timeouts so a genuinely stuck request fails visibly within a bounded
   * time instead of hanging indefinitely (the previous unset-timeout default was itself a latent
   * harness bug).
   */
  static RestTemplate newRestTemplate() {
    // JVM-wide constant; must be set before the first connection is opened. Idempotent/no-op if
    // already set by a prior test in the same JVM (Surefire/Failsafe fork).
    System.setProperty("http.maxConnections", "200");

    SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(Duration.ofSeconds(10));
    factory.setReadTimeout(Duration.ofSeconds(30));

    RestTemplate restTemplate = new RestTemplate(factory);
    // Suppress RestTemplate's default throw-on-4xx/5xx so status codes can be tallied directly —
    // matches the established convention in AuthAuditIT/AuditStoreDownIT/RegistrationControllerIT.
    restTemplate.setErrorHandler(
        new DefaultResponseErrorHandler() {
          @Override
          public boolean hasError(ClientHttpResponse response) {
            return false;
          }
        });
    return restTemplate;
  }

  /**
   * Drives {@code ratePerSecond} login POSTs per second against {@code loginUrl} for {@code
   * duration}, using valid credentials on every request (100% success traffic — Clarification #2:
   * this scenario proves the audit pipeline's zero-loss/latency invariants under healthy-DB
   * sustained load, not lockout/failure-branch behaviour, which is covered elsewhere). Every
   * offered request results in exactly one primary {@code AuthEvent} (LOGIN_SUCCESS) — see
   * {@code LoginUseCase.execute} Step 9 — keeping the row-count-equals-request-count invariant
   * exactly 1:1.
   *
   * @return tallies of offered/succeeded/failed/serverError responses; the caller cross-checks
   *     these against the DB row count and Micrometer counters
   */
  static Result run(
      RestTemplate restTemplate,
      String loginUrl,
      String email,
      String password,
      int ratePerSecond,
      Duration duration) {
    ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    AtomicInteger succeeded = new AtomicInteger();
    AtomicInteger failed = new AtomicInteger();
    AtomicInteger serverErrors = new AtomicInteger();
    CopyOnWriteArrayList<Throwable> unexpectedErrors = new CopyOnWriteArrayList<>();

    long totalRequests = ratePerSecond * duration.toSeconds();
    CountDownLatch completionLatch = new CountDownLatch((int) totalRequests);

    try {
      // Submissions are spaced at a constant interval across the whole run (duration / total
      // requests) rather than bursting ratePerSecond requests once per second — this smooths
      // instantaneous concurrency to reflect a genuinely sustained rate rather than a sawtooth of
      // per-second spikes, while still offering load independently of completion (a slow
      // response never delays the next submission).
      long intervalNanos = duration.toNanos() / totalRequests;
      long nextSubmitAt = System.nanoTime();

      for (long i = 0; i < totalRequests; i++) {
        executor.submit(
            () -> {
              try {
                ResponseEntity<Map> resp =
                    doLoginPost(restTemplate, loginUrl, email, password);
                int status = resp.getStatusCode().value();
                if (status >= 500) {
                  serverErrors.incrementAndGet();
                } else if (status == 200) {
                  succeeded.incrementAndGet();
                } else {
                  failed.incrementAndGet();
                }
              } catch (RuntimeException e) {
                unexpectedErrors.add(e);
                failed.incrementAndGet();
              } finally {
                completionLatch.countDown();
              }
            });
        nextSubmitAt += intervalNanos;
        long sleepNanos = nextSubmitAt - System.nanoTime();
        if (sleepNanos > 0) {
          parkNanos(sleepNanos);
        }
        // If offered load has already fallen behind (sleepNanos <= 0), proceed immediately —
        // submission never blocks waiting for prior submissions' completions (decoupled, per
        // class doc).
      }

      // Grace period for in-flight virtual-thread tasks to complete after the last tick's
      // submissions — generous enough for Argon2's worst-case per-call latency plus network/JPA
      // overhead without being unbounded (a genuine hang still fails the test via the assertion
      // on final tallies rather than blocking forever).
      boolean completedInTime =
          awaitLatch(completionLatch, Duration.ofSeconds(60).plus(duration.dividedBy(4)));
      if (!completedInTime) {
        throw new IllegalStateException(
            "Load test harness: in-flight requests did not complete within the grace period — "
                + "offered="
                + totalRequests
                + ", completed="
                + (succeeded.get() + failed.get() + serverErrors.get()));
      }
    } finally {
      executor.shutdown();
      awaitTermination(executor);
    }

    if (!unexpectedErrors.isEmpty()) {
      // Surface the first unexpected client-side exception (e.g. connection refused) rather than
      // silently folding it into the "failed" tally — a network-level error during a healthy-DB
      // load test indicates a harness/environment problem, not a genuine audit-pipeline finding.
      throw new IllegalStateException(
          "Load test harness observed "
              + unexpectedErrors.size()
              + " unexpected client-side exception(s); first: "
              + unexpectedErrors.get(0),
          unexpectedErrors.get(0));
    }

    return new Result((int) totalRequests, succeeded.get(), failed.get(), serverErrors.get());
  }

  @SuppressWarnings("rawtypes")
  private static ResponseEntity<Map> doLoginPost(
      RestTemplate restTemplate, String loginUrl, String email, String password) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    return restTemplate.exchange(
        loginUrl,
        HttpMethod.POST,
        new HttpEntity<>(Map.of("email", email, "password", password), headers),
        Map.class);
  }

  private static void parkNanos(long nanos) {
    try {
      TimeUnit.NANOSECONDS.sleep(nanos);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("interrupted while pacing offered load", e);
    }
  }

  private static boolean awaitLatch(CountDownLatch latch, Duration timeout) {
    try {
      return latch.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("interrupted while awaiting load-test completion", e);
    }
  }

  private static void awaitTermination(ExecutorService executor) {
    try {
      if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
        executor.shutdownNow();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      executor.shutdownNow();
    }
  }
}
