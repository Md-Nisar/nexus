package com.example.nexus.common.security;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Utility for extracting the current database user from a live connection.
 * Centralised to prevent code duplication across module-specific health indicators.
 */
public final class DbUserUtil {

  private DbUserUtil() {
    // Utility class
  }

  /**
   * Reads the CURRENT_USER() string from the active database session.
   */
  public static String readCurrentUser(Connection connection) throws SQLException {
    try (Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery("SELECT CURRENT_USER()")) {
      if (resultSet.next()) {
        return resultSet.getString(1);
      }
      throw new SQLException("SELECT CURRENT_USER() returned no rows");
    }
  }

  /**
   * Extracts the username part from a 'user@host' DB user string.
   */
  public static String usernamePart(String currentUser) {
    if (currentUser == null) {
      return "";
    }
    int at = currentUser.indexOf('@');
    return at >= 0 ? currentUser.substring(0, at) : currentUser;
  }
}
