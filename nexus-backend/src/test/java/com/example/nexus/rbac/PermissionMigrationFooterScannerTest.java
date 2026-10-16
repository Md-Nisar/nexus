package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

/**
 * B7 scanner (US-018 T-021, FR-B7.a; 03-design.md 10.7; RC-40.3, RC-48.1; threat T-T21). Every
 * migration under {@code db/migration} that inserts into {@code permissions} must carry both footer
 * statements of {@code db/templates/permission-migration-footer.sql}, with statement (a)'s
 * exclusion list equal to exactly the ids that file inserts, and, from V9, with (a) filtering
 * {@code deleted_at IS NULL}. A footer copied verbatim from an earlier migration fails the build
 * instead of silently attaching nothing and demoting every custom administrator.
 *
 * <p>Scope and limits. Detection covers {@code INSERT [IGNORE] [INTO]} and {@code REPLACE [INTO]},
 * case-insensitive, with a backticked or schema-qualified table name, after SQL comments are
 * stripped. Migrations before {@link #FIRST_FOOTER_VERSION} predate the rule: V5 creates the
 * catalogue itself and seeds the first system roles in the same file. A migration that adds
 * permissions by other means (for example {@code INSERT ... SELECT} from another table, or dynamic
 * SQL) is not detected; ids are read from {@code VALUES (UUID_TO_BIN('...'), ...)} tuples, and a
 * detected insert whose ids cannot be read is itself a violation.
 */
@Tag("UnitTest")
class PermissionMigrationFooterScannerTest {

  private static final int FIRST_FOOTER_VERSION = 6;
  private static final int FIRST_DELETED_AT_VERSION = 9;
  private static final String PLACEHOLDER = "{{INSERTED_PERMISSION_IDS}}";

  private static final Pattern VERSION = Pattern.compile("^V(\\d+)__.*\\.sql$");
  private static final Pattern PERMISSIONS_INSERT =
      Pattern.compile(
          "\\b(?:INSERT\\s+(?:(?:LOW_PRIORITY|DELAYED|HIGH_PRIORITY)\\s+)?(?:IGNORE\\s+)?(?:INTO\\s+)?"
              + "|REPLACE\\s+(?:(?:LOW_PRIORITY|DELAYED)\\s+)?(?:INTO\\s+)?)"
              + "(?:`?\\w+`?\\s*\\.\\s*)?`?permissions`?(?![\\w`])",
          Pattern.CASE_INSENSITIVE);
  private static final Pattern INSERTED_ID_TUPLE =
      Pattern.compile("\\(\\s*UUID_TO_BIN\\(\\s*'([0-9a-fA-F-]{36})'\\s*\\)", Pattern.CASE_INSENSITIVE);
  private static final Pattern ID_LIST =
      Pattern.compile("(NOT IN|IN)\\(((?:UUID_TO_BIN\\('[0-9a-fA-F-]{36}'\\),?)+)\\)");
  private static final Pattern ID_LITERAL = Pattern.compile("UUID_TO_BIN\\('([0-9a-fA-F-]{36})'\\)");

  private static final PathMatchingResourcePatternResolver RESOLVER =
      new PathMatchingResourcePatternResolver();

  // ── The real migrations ──────────────────────────────────────────────

  @Test
  void should_passEveryMigration_when_scanningDbMigration() throws IOException {
    Map<String, String> migrations = readAll("classpath*:db/migration/V*.sql");

    assertThat(migrations).as("migrations found on the classpath").isNotEmpty();
    migrations.forEach(
        (name, sql) ->
            assertThat(scan(name, sql)).as("footer violations in %s", name).isEmpty());
  }

  @Test
  void should_haveV6AsAPositiveCase_when_scanningDbMigration() throws IOException {
    String v6 =
        readAll("classpath*:db/migration/V6__*.sql").values().stream().findFirst().orElseThrow();

    assertThat(PERMISSIONS_INSERT.matcher(stripComments(v6)).find())
        .as("V6 inserts into permissions, so the scan above is not vacuous")
        .isTrue();
    assertThat(scan("V6__rbac_user_role_assign_permission.sql", v6)).isEmpty();
  }

  // ── Negative fixtures (each is rejected, with the stated reason) ─────

  @Test
  void should_fail_when_lowercaseInsertHasNoFooter() throws IOException {
    assertThat(scanFixture("V50__lowercase_insert_without_footer.sql"))
        .anyMatch(v -> v.contains("statement (a) is missing"))
        .anyMatch(v -> v.contains("statement (b) is missing"));
  }

  @Test
  void should_fail_when_replaceIntoHasNoFooter() throws IOException {
    assertThat(scanFixture("V51__replace_into_without_footer.sql"))
        .anyMatch(v -> v.contains("statement (a) is missing"));
  }

  @Test
  void should_fail_when_backtickedSchemaQualifiedInsertHasNoFooter() throws IOException {
    assertThat(scanFixture("V52__backticked_schema_qualified_without_footer.sql"))
        .anyMatch(v -> v.contains("statement (a) is missing"));
  }

  @Test
  void should_fail_when_insertIgnoreHasNoFooter() throws IOException {
    assertThat(scanFixture("V53__insert_ignore_without_footer.sql"))
        .anyMatch(v -> v.contains("statement (a) is missing"));
  }

  @Test
  void should_fail_when_footerIsCopiedFromV6IntoAFileThatInsertsADifferentId() throws IOException {
    assertThat(scanFixture("V54__footer_copied_from_v6.sql"))
        .anyMatch(v -> v.contains("exclusion list does not equal the ids this file inserts"));
  }

  @Test
  void should_fail_when_exclusionListHasAnExtraId() throws IOException {
    assertThat(scanFixture("V55__exclusion_list_has_extra_id.sql"))
        .anyMatch(v -> v.contains("exclusion list does not equal the ids this file inserts"));
  }

  @Test
  void should_fail_when_systemResyncStatementIsMissing() throws IOException {
    assertThat(scanFixture("V8__missing_system_resync.sql"))
        .containsExactly(
            "V8__missing_system_resync.sql: statement (b) is missing or differs from the template");
  }

  @Test
  void should_fail_when_v9OrLaterStatementAHasNoDeletedAtFilter() throws IOException {
    assertThat(scanFixture("V60__v9_footer_without_deleted_at.sql"))
        .anyMatch(v -> v.contains("deleted_at IS NULL"));
  }

  // ── Positive fixtures ────────────────────────────────────────────────

  @Test
  void should_pass_when_v9FooterBindsTwoIdsInAnyOrder() throws IOException {
    assertThat(scanFixture("V61__valid_v9_footer_two_ids.sql")).isEmpty();
  }

  @Test
  void should_pass_when_lowercaseInsertIgnoreCarriesAValidPreV9Footer() throws IOException {
    assertThat(scanFixture("V7__valid_pre_v9_footer_lowercase_insert.sql")).isEmpty();
  }

  @Test
  void should_notRequireAFooter_when_permissionsInsertAppearsOnlyInAComment() throws IOException {
    assertThat(scanFixture("V63__no_permission_insert.sql")).isEmpty();
  }

  // ── Scanner ──────────────────────────────────────────────────────────

  private static List<String> scanFixture(String name) throws IOException {
    Resource resource = RESOLVER.getResource("classpath:db/footer-fixtures/" + name);
    return scan(name, read(resource));
  }

  /** Returns the violations of one migration file; empty when it conforms. */
  static List<String> scan(String fileName, String rawSql) {
    Matcher version = VERSION.matcher(fileName);
    if (!version.matches()) {
      return List.of(fileName + ": not a versioned migration name");
    }
    int number = Integer.parseInt(version.group(1));
    String sql = stripComments(rawSql);
    if (number < FIRST_FOOTER_VERSION || !PERMISSIONS_INSERT.matcher(sql).find()) {
      return List.of();
    }

    List<String> statements =
        Arrays.stream(sql.split(";")).map(String::strip).filter(s -> !s.isEmpty()).toList();
    TreeSet<String> insertedIds = new TreeSet<>();
    for (String statement : statements) {
      if (PERMISSIONS_INSERT.matcher(statement).find()) {
        Matcher tuple = INSERTED_ID_TUPLE.matcher(statement);
        while (tuple.find()) {
          insertedIds.add(tuple.group(1).toLowerCase(Locale.ROOT));
        }
      }
    }
    List<String> violations = new ArrayList<>();
    if (insertedIds.isEmpty()) {
      violations.add(
          fileName + ": inserts into permissions but the inserted ids cannot be read from"
              + " VALUES (UUID_TO_BIN('...'), ...) tuples");
      return violations;
    }

    List<String> normalised = statements.stream().map(PermissionMigrationFooterScannerTest::normalise).toList();
    boolean deletedAtVariant = number >= FIRST_DELETED_AT_VERSION;
    String expectedA =
        normalise(bind(template(deletedAtVariant ? "A-V9" : "A-PRE-V9"), insertedIds));
    String expectedB = normalise(template("B"));

    List<String> candidatesA =
        normalised.stream()
            .filter(s -> s.startsWith("INSERT INTO role_permissions") && s.contains("JOIN permissions p"))
            .toList();
    if (candidatesA.isEmpty()) {
      violations.add(fileName + ": statement (a) is missing (admin-defining preservation)");
    } else if (candidatesA.stream().noneMatch(s -> s.equals(expectedA))) {
      String candidate = candidatesA.get(0);
      if (!excludedIds(candidate).equals(insertedIds)) {
        violations.add(
            fileName + ": statement (a) exclusion list does not equal the ids this file inserts "
                + "(excludes " + excludedIds(candidate) + ", inserts " + insertedIds + ")");
      } else if (deletedAtVariant && !candidate.contains("r.deleted_at IS NULL")) {
        violations.add(fileName + ": from V9 statement (a) must filter r.deleted_at IS NULL");
      } else {
        violations.add(fileName + ": statement (a) differs from the template");
      }
    }
    if (!normalised.contains(expectedB)) {
      violations.add(fileName + ": statement (b) is missing or differs from the template");
    }
    return violations;
  }

  /** The ids in statement (a)'s {@code NOT IN (...)} lists, which must equal the inserted ids. */
  private static TreeSet<String> excludedIds(String statementA) {
    TreeSet<String> ids = new TreeSet<>();
    Matcher list = ID_LIST.matcher(statementA);
    while (list.find()) {
      if (list.group(1).equals("NOT IN")) {
        Matcher id = ID_LITERAL.matcher(list.group(2));
        while (id.find()) {
          ids.add(id.group(1).toLowerCase(Locale.ROOT));
        }
      }
    }
    return ids;
  }

  private static String bind(String templateStatement, TreeSet<String> ids) {
    String literal =
        ids.stream().map(id -> "UUID_TO_BIN('" + id + "')").collect(Collectors.joining(", "));
    return templateStatement.replace(PLACEHOLDER, literal);
  }

  /** One template statement, found between its BEGIN/END markers in the template file. */
  private static String template(String name) {
    try {
      String text = read(RESOLVER.getResource("classpath:db/templates/permission-migration-footer.sql"));
      String begin = "-- B7-TEMPLATE-" + name + "-BEGIN";
      String end = "-- B7-TEMPLATE-" + name + "-END";
      int from = text.indexOf(begin);
      int to = text.indexOf(end);
      assertThat(from).as("template marker %s", begin).isNotNegative();
      assertThat(to).as("template marker %s", end).isGreaterThan(from);
      return stripComments(text.substring(from + begin.length(), to)).replace(";", "").strip();
    } catch (IOException e) {
      throw new IllegalStateException("cannot read the footer template", e);
    }
  }

  /** Drops {@code --} line comments and block comments. */
  static String stripComments(String sql) {
    return sql.replaceAll("(?s)/\\*.*?\\*/", " ").replaceAll("(?m)--.*$", "");
  }

  /**
   * Collapses whitespace, removes it around parentheses and commas, and puts the id lists in
   * statement (a) in sorted lower-case order, so layout and id order do not matter.
   */
  static String normalise(String statement) {
    String compact = statement.strip().replaceAll("\\s+", " ").replaceAll("\\s*([(),])\\s*", "$1");
    Matcher list = ID_LIST.matcher(compact);
    StringBuilder out = new StringBuilder();
    while (list.find()) {
      TreeSet<String> ids = new TreeSet<>();
      Matcher id = ID_LITERAL.matcher(list.group(2));
      while (id.find()) {
        ids.add(id.group(1).toLowerCase(Locale.ROOT));
      }
      String sorted =
          ids.stream().map(i -> "UUID_TO_BIN('" + i + "')").collect(Collectors.joining(","));
      list.appendReplacement(out, Matcher.quoteReplacement(list.group(1) + "(" + sorted + ")"));
    }
    list.appendTail(out);
    return out.toString();
  }

  private static Map<String, String> readAll(String pattern) throws IOException {
    Map<String, String> files = new java.util.TreeMap<>(Comparator.naturalOrder());
    for (Resource resource : RESOLVER.getResources(pattern)) {
      files.put(resource.getFilename(), read(resource));
    }
    return files;
  }

  private static String read(Resource resource) throws IOException {
    try (InputStream in = resource.getInputStream()) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }
}
