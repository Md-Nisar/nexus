package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * US-019 T-001 (03-design.md §3.5, control 2): no test source outside an allow-list hand-lists a
 * seeded permission id. A fixture that builds "an administrator" from listed ids silently stops
 * being one when a migration grows the catalogue (V11), so fixtures use {@link RbacTestCatalogue}
 * for administrators and {@code RbacSeededPermissionIds} for one specific permission.
 *
 * <p>Seeded permission ids are {@code 019f6839-180x-...} (V5, V6, V11); seeded role ids are {@code
 * 019f6839-181x-...} and are not permission literals.
 *
 * <p>Allow-list: the migration ITs, which must name the migrations' own literals; the footer
 * scanner's SQL fixtures; and this test's own negative fixtures.
 */
class SeededPermissionLiteralScanTest {

  private static final Pattern PERMISSION_LITERAL = Pattern.compile("019f6839-180\\p{XDigit}-");

  private static final Path TEST_SOURCES = Path.of("src", "test");
  private static final Path NEGATIVE_FIXTURES =
      TEST_SOURCES.resolve(Path.of("resources", "rbac", "literal-scan-fixtures"));

  private static final List<String> ALLOWED_FILES =
      List.of(
          "java/com/example/nexus/rbac/RbacSchemaMigrationIT.java",
          "java/com/example/nexus/rbac/V11AdministratorPreservationIT.java");
  private static final List<String> ALLOWED_DIRECTORIES =
      List.of("resources/db/footer-fixtures/", "resources/rbac/literal-scan-fixtures/");

  @Test
  void should_findNoPermissionLiteral_when_scanningTestSourcesOutsideTheAllowList() {
    assertThat(TEST_SOURCES).isDirectory();

    assertThat(violations(TEST_SOURCES, SeededPermissionLiteralScanTest::isAllowed)).isEmpty();
  }

  @Test
  void should_reportFile_when_itHandListsAPermissionIdOutsideTheAllowList() {
    assertThat(violations(NEGATIVE_FIXTURES, path -> false))
        .containsExactly("HandListedPermissionFixture.java.txt");
  }

  private static boolean isAllowed(String relativePath) {
    return ALLOWED_FILES.contains(relativePath)
        || ALLOWED_DIRECTORIES.stream().anyMatch(relativePath::startsWith);
  }

  /** Files under {@code root} that contain a permission literal and are not allowed. */
  private static List<String> violations(Path root, Predicate<String> allowed) {
    try (Stream<Path> files = Files.walk(root)) {
      return files
          .filter(Files::isRegularFile)
          .filter(file -> !allowed.test(relative(root, file)))
          .filter(SeededPermissionLiteralScanTest::containsPermissionLiteral)
          .map(file -> relative(root, file))
          .sorted()
          .toList();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static String relative(Path root, Path file) {
    return root.relativize(file).toString().replace('\\', '/');
  }

  private static boolean containsPermissionLiteral(Path file) {
    try {
      return PERMISSION_LITERAL.matcher(Files.readString(file, StandardCharsets.UTF_8)).find();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
