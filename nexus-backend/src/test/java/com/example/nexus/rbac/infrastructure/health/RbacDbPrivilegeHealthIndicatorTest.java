package com.example.nexus.rbac.infrastructure.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.health.contributor.Status;

/**
 * Unit coverage for the US-010 AC10 runtime self-check's detection logic, in isolation from a
 * real database (Mockito {@link DataSource}/{@link Connection} stack; no Spring context).
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class RbacDbPrivilegeHealthIndicatorTest {

  @Mock private DataSource dataSource;
  @Mock private Connection connection;
  @Mock private Statement currentUserStatement;
  @Mock private ResultSet currentUserResultSet;
  @Mock private PreparedStatement tablePrivilegeStatement;
  @Mock private ResultSet tablePrivilegeResultSet;
  @Mock private PreparedStatement globalPrivilegeStatement;
  @Mock private ResultSet globalPrivilegeResultSet;
  @Mock private PreparedStatement bareTableUpdatePrivilegeStatement;
  @Mock private ResultSet bareTableUpdatePrivilegeResultSet;

  private RbacDbPrivilegeHealthIndicator indicator() {
    return new RbacDbPrivilegeHealthIndicator(dataSource);
  }

  private void givenConnectedAs(String currentUser) throws SQLException {
    when(dataSource.getConnection()).thenReturn(connection);
    when(connection.createStatement()).thenReturn(currentUserStatement);
    when(currentUserStatement.executeQuery("SELECT CURRENT_USER()"))
        .thenReturn(currentUserResultSet);
    when(currentUserResultSet.next()).thenReturn(true);
    when(currentUserResultSet.getString(1)).thenReturn(currentUser);
  }

  private void givenTablePrivilegeCount(int count) throws SQLException {
    when(connection.prepareStatement(contains("PRIVILEGE_TYPE IN ('DELETE', 'ALL PRIVILEGES')")))
        .thenReturn(tablePrivilegeStatement);
    when(tablePrivilegeStatement.executeQuery()).thenReturn(tablePrivilegeResultSet);
    when(tablePrivilegeResultSet.next()).thenReturn(true);
    when(tablePrivilegeResultSet.getInt(1)).thenReturn(count);
  }

  private void givenGlobalPrivilegeCount(int count) throws SQLException {
    when(connection.prepareStatement(contains("USER_PRIVILEGES")))
        .thenReturn(globalPrivilegeStatement);
    when(globalPrivilegeStatement.executeQuery()).thenReturn(globalPrivilegeResultSet);
    when(globalPrivilegeResultSet.next()).thenReturn(true);
    when(globalPrivilegeResultSet.getInt(1)).thenReturn(count);
  }

  /** Column-scoped grants (the intended {@code UPDATE (revoked_at)}) never match this — that is
   *  the point of the check: a nonzero count here means a bare table-scoped {@code UPDATE} grant
   *  exists (T-015 / T-E12). */
  private void givenBareTableUpdatePrivilegeCount(int count) throws SQLException {
    when(connection.prepareStatement(contains("PRIVILEGE_TYPE = 'UPDATE'")))
        .thenReturn(bareTableUpdatePrivilegeStatement);
    when(bareTableUpdatePrivilegeStatement.executeQuery())
        .thenReturn(bareTableUpdatePrivilegeResultSet);
    when(bareTableUpdatePrivilegeResultSet.next()).thenReturn(true);
    when(bareTableUpdatePrivilegeResultSet.getInt(1)).thenReturn(count);
  }

  @Test
  void should_report_up_when_connected_as_nexus_app_with_no_delete_grant() throws SQLException {
    givenConnectedAs("nexus_app@%");
    givenTablePrivilegeCount(0);
    givenGlobalPrivilegeCount(0);
    givenBareTableUpdatePrivilegeCount(0);

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.UP);
    assertThat(health.getDetails()).containsEntry("dbUser", "nexus_app@%");
  }

  @Test
  void should_report_down_and_log_warn_when_connected_as_root() throws SQLException {
    givenConnectedAs("root@localhost");
    givenTablePrivilegeCount(0);
    givenGlobalPrivilegeCount(0);
    givenBareTableUpdatePrivilegeCount(0);

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsEntry("isRoot", true);
    assertThat(health.getDetails()).containsEntry("dbUser", "root@localhost");
  }

  @Test
  void should_report_down_when_connected_user_has_explicit_delete_grant_on_user_roles()
      throws SQLException {
    givenConnectedAs("over_privileged@%");
    givenTablePrivilegeCount(1);
    givenGlobalPrivilegeCount(0);
    givenBareTableUpdatePrivilegeCount(0);

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsEntry("hasTableDeleteGrant", true);
    assertThat(health.getDetails()).containsEntry("isRoot", false);
  }

  @Test
  void should_report_down_when_connected_user_has_global_all_privileges_grant()
      throws SQLException {
    givenConnectedAs("superuser_like@%");
    givenTablePrivilegeCount(0);
    givenGlobalPrivilegeCount(1);
    givenBareTableUpdatePrivilegeCount(0);

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsEntry("hasGlobalDeleteGrant", true);
    assertThat(health.getDetails()).containsEntry("hasTableDeleteGrant", false);
  }

  @Test
  void should_report_unknown_not_throw_when_privilege_query_itself_fails() throws SQLException {
    when(dataSource.getConnection()).thenThrow(new SQLException("connection refused"));

    var indicator = indicator();

    assertThatCode(indicator::health).doesNotThrowAnyException();
    assertThat(indicator.health().getStatus()).isEqualTo(Status.UNKNOWN);
  }

  // --- T-015 / T-E12 positive grant-scope check: bare table-scoped UPDATE vs column-scoped ---

  @Test
  void should_report_down_when_update_grant_is_table_scoped_not_column_scoped()
      throws SQLException {
    givenConnectedAs("widened_grant_user@%");
    givenTablePrivilegeCount(0);
    givenGlobalPrivilegeCount(0);
    givenBareTableUpdatePrivilegeCount(1);

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsEntry("hasTableScopedUpdateGrant", true);
    assertThat(health.getDetails()).containsEntry("isRoot", false);
    assertThat(health.getDetails()).containsEntry("hasTableDeleteGrant", false);
    assertThat(health.getDetails()).containsEntry("hasGlobalDeleteGrant", false);
  }

  @Test
  void should_report_up_when_update_grant_is_column_scoped_only() throws SQLException {
    givenConnectedAs("nexus_app@%");
    givenTablePrivilegeCount(0);
    givenGlobalPrivilegeCount(0);
    givenBareTableUpdatePrivilegeCount(0);

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.UP);
  }

  @Test
  void should_never_attempt_delete_against_user_roles() throws SQLException {
    givenConnectedAs("nexus_app@%");
    givenTablePrivilegeCount(0);
    givenGlobalPrivilegeCount(0);
    givenBareTableUpdatePrivilegeCount(0);

    indicator().health();

    verify(currentUserStatement, never()).executeUpdate(anyString());
    verify(tablePrivilegeStatement, never()).executeUpdate();
    verify(globalPrivilegeStatement, never()).executeUpdate();
    verify(currentUserStatement, never()).execute(anyString());
  }
}
