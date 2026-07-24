package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.testcontainers.containers.MySQLContainer;

/**
 * US-008 T-08-12 (ADR 0012 §5, closes threat-model T-E2/T-T4) — proves the runtime self-check
 * correctly distinguishes a properly-scoped {@code nexus_app} connection (UP) from a {@code root}
 * connection and an arbitrary over-privileged connection (both DOWN, with a WARN log line).
 *
 * <p>Connects via raw JDBC {@link Connection}s against the shared {@link MySQLContainer} bean
 * (autowired from {@link TestcontainersConfiguration}) using different credentials per test,
 * mirroring {@code AuthEventsPrivilegeAppendOnlyIT}'s established pattern. Each connection is
 * wrapped in its own throwaway {@link DataSource} and handed directly to a fresh {@link
 * AuthEventDbPrivilegeHealthIndicator} instance — the indicator under test is never wired to the
 * Spring context's own {@code DataSource} bean (which uses the container's default
 * {@code @ServiceConnection} user, "test", not {@code nexus_app} or {@code root}), and {@code
 * TestcontainersConfiguration} itself is not modified.
 *
 * <p>The over-privileged test user is created and dropped entirely within its own test method,
 * using the container's {@code root} credential already available via {@link
 * MySQLContainer#getPassword()} (T-08-10's {@code nexusAppGrantsCallback} establishes that the
 * container's root password equals {@link MySQLContainer#getPassword()} whenever the configured
 * application user is not itself root — the same fact this test relies on).
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class AuthEventDbPrivilegeHealthIndicatorIT {

  private static final String NEXUS_APP_USER = "nexus_app";
  private static final String NEXUS_APP_PASSWORD = "nexus_app_test_only";
  private static final String OVER_PRIVILEGED_USER = "it_over_privileged_user";
  private static final String OVER_PRIVILEGED_PASSWORD = "it_over_privileged_pw";

  @Autowired private MySQLContainer<?> mysqlContainer;

  private Connection rootConnectionForCleanup;

  @AfterEach
  void dropOverPrivilegedUserIfCreated() throws SQLException {
    if (rootConnectionForCleanup != null) {
      try (Statement statement = rootConnectionForCleanup.createStatement()) {
        statement.execute("DROP USER IF EXISTS '" + OVER_PRIVILEGED_USER + "'@'%'");
      } finally {
        rootConnectionForCleanup.close();
        rootConnectionForCleanup = null;
      }
    }
  }

  @Test
  void should_report_up_when_connected_as_provisioned_nexus_app() throws SQLException {
    DataSource nexusAppDataSource = dataSourceFor(NEXUS_APP_USER, NEXUS_APP_PASSWORD);
    var indicator = new AuthEventDbPrivilegeHealthIndicator(nexusAppDataSource);
    ListAppender<ILoggingEvent> appender = startLogCapture();

    try {
      var health = indicator.health();

      assertThat(health.getStatus()).isEqualTo(Status.UP);
      assertThat(warnMessages(appender)).isEmpty();
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_report_down_and_log_warn_when_connected_as_root() throws SQLException {
    DataSource rootDataSource = dataSourceFor("root", mysqlContainer.getPassword());
    var indicator = new AuthEventDbPrivilegeHealthIndicator(rootDataSource);
    ListAppender<ILoggingEvent> appender = startLogCapture();

    try {
      var health = indicator.health();

      assertThat(health.getStatus()).isEqualTo(Status.DOWN);
      assertThat(health.getDetails()).containsEntry("isRoot", true);
      assertThat(warnMessages(appender))
          .anyMatch(message -> message.contains("auth_events DB privilege drift detected"));
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_report_down_when_connected_as_throwaway_over_privileged_user() throws SQLException {
    createOverPrivilegedUser();
    DataSource overPrivilegedDataSource =
        dataSourceFor(OVER_PRIVILEGED_USER, OVER_PRIVILEGED_PASSWORD);
    var indicator = new AuthEventDbPrivilegeHealthIndicator(overPrivilegedDataSource);
    ListAppender<ILoggingEvent> appender = startLogCapture();

    try {
      var health = indicator.health();

      assertThat(health.getStatus()).isEqualTo(Status.DOWN);
      assertThat(health.getDetails()).containsEntry("isRoot", false);
      assertThat(health.getDetails()).containsEntry("hasTableUpdateOrDeleteGrant", true);
      assertThat(warnMessages(appender))
          .anyMatch(message -> message.contains("auth_events DB privilege drift detected"));
    } finally {
      stopLogCapture(appender);
    }
  }

  private void createOverPrivilegedUser() throws SQLException {
    rootConnectionForCleanup =
        DriverManager.getConnection(
            mysqlContainer.getJdbcUrl(), "root", mysqlContainer.getPassword());
    try (Statement statement = rootConnectionForCleanup.createStatement()) {
      statement.execute(
          "CREATE USER '"
              + OVER_PRIVILEGED_USER
              + "'@'%' IDENTIFIED BY '"
              + OVER_PRIVILEGED_PASSWORD
              + "'");
      // Only auth_events UPDATE/DELETE matters for this test — the indicator's detection query
      // is scoped to that table, so the grant here is scoped to it too.
      statement.execute(
          "GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.auth_events TO '"
              + OVER_PRIVILEGED_USER
              + "'@'%'");
      statement.execute("FLUSH PRIVILEGES");
    }
  }

  private DataSource dataSourceFor(String username, String password) {
    SimpleDriverDataSource dataSource = new SimpleDriverDataSource();
    dataSource.setDriverClass(com.mysql.cj.jdbc.Driver.class);
    dataSource.setUrl(mysqlContainer.getJdbcUrl());
    dataSource.setUsername(username);
    dataSource.setPassword(password);
    return dataSource;
  }

  private ListAppender<ILoggingEvent> startLogCapture() {
    Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    root.addAppender(appender);
    return appender;
  }

  private void stopLogCapture(ListAppender<ILoggingEvent> appender) {
    Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.detachAppender(appender);
    appender.stop();
  }

  private List<String> warnMessages(ListAppender<ILoggingEvent> appender) {
    return appender.list.stream()
        .filter(event -> event.getLevel() == ch.qos.logback.classic.Level.WARN)
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
  }
}
