package com.example.nexus.rbac.infrastructure.health;

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
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.testcontainers.containers.MySQLContainer;

/**
 * US-010 AC10 (forward-tracked from US-009's Gate-2 threat model T-E3) — proves the runtime
 * self-check correctly distinguishes a properly-scoped {@code nexus_app} connection (UP, no
 * {@code DELETE} on {@code user_roles}) from a {@code root} connection and an arbitrary
 * over-privileged connection (both DOWN, with a WARN log line), mirroring {@code
 * AuthEventDbPrivilegeHealthIndicatorIT}'s established pattern.
 *
 * <p>Connects via raw JDBC {@link Connection}s against the shared {@link MySQLContainer} bean
 * (autowired from {@link TestcontainersConfiguration}) using different credentials per test. The
 * indicator under test is never wired to the Spring context's own {@code DataSource} bean (which
 * uses the container's default {@code @ServiceConnection} user, "test", not {@code nexus_app} or
 * {@code root}), and {@code TestcontainersConfiguration} itself is not modified.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class RbacDbPrivilegeHealthIndicatorIT {

  private static final String NEXUS_APP_USER = "nexus_app";
  private static final String NEXUS_APP_PASSWORD = "nexus_app_test_only";
  private static final String OVER_PRIVILEGED_USER = "it_rbac_over_privileged_user";
  private static final String OVER_PRIVILEGED_PASSWORD = "it_rbac_over_privileged_pw";

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
    var indicator = new RbacDbPrivilegeHealthIndicator(nexusAppDataSource);
    ListAppender<ILoggingEvent> appender = startLogCapture();

    try {
      var health = indicator.health();

      // nexus_app holds only UPDATE(revoked_at)/SELECT/INSERT on user_roles — no DELETE — per
      // ADR-0014/ADR-0015, so this must be UP.
      assertThat(health.getStatus()).isEqualTo(Status.UP);
      assertThat(warnMessages(appender)).isEmpty();
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_report_down_and_log_warn_when_connected_as_root() throws SQLException {
    DataSource rootDataSource = dataSourceFor("root", mysqlContainer.getPassword());
    var indicator = new RbacDbPrivilegeHealthIndicator(rootDataSource);
    ListAppender<ILoggingEvent> appender = startLogCapture();

    try {
      var health = indicator.health();

      assertThat(health.getStatus()).isEqualTo(Status.DOWN);
      assertThat(health.getDetails()).containsEntry("isRoot", true);
      assertThat(warnMessages(appender))
          .anyMatch(message -> message.contains("user_roles DB privilege drift detected"));
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_report_down_when_connected_as_throwaway_user_with_delete_grant()
      throws SQLException {
    createOverPrivilegedUser();
    DataSource overPrivilegedDataSource =
        dataSourceFor(OVER_PRIVILEGED_USER, OVER_PRIVILEGED_PASSWORD);
    var indicator = new RbacDbPrivilegeHealthIndicator(overPrivilegedDataSource);
    ListAppender<ILoggingEvent> appender = startLogCapture();

    try {
      var health = indicator.health();

      assertThat(health.getStatus()).isEqualTo(Status.DOWN);
      assertThat(health.getDetails()).containsEntry("isRoot", false);
      assertThat(health.getDetails()).containsEntry("hasTableDeleteGrant", true);
      assertThat(warnMessages(appender))
          .anyMatch(message -> message.contains("user_roles DB privilege drift detected"));
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
      // Only user_roles DELETE matters for this test — the indicator's detection query is
      // scoped to that table, so the grant here is scoped to it too.
      statement.execute(
          "GRANT SELECT, INSERT, DELETE ON nexus.user_roles TO '"
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
