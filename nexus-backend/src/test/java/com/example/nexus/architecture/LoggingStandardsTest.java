package com.example.nexus.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.library.GeneralCodingRules;
import org.junit.jupiter.api.Tag;

/**
 * Enforces logging standards such as preventing direct stack trace printing, standard streams,
 * and ensuring only SLF4J is used for application code.
 */
@AnalyzeClasses(
    packages = "com.example.nexus",
    importOptions = ImportOption.DoNotIncludeTests.class)
@Tag("UnitTest")
class LoggingStandardsTest {

  @ArchTest
  static final ArchRule no_standard_streams =
      GeneralCodingRules.NO_CLASSES_SHOULD_ACCESS_STANDARD_STREAMS;

  @ArchTest
  static final ArchRule no_java_util_logging =
      GeneralCodingRules.NO_CLASSES_SHOULD_USE_JAVA_UTIL_LOGGING;

  @ArchTest
  static final ArchRule no_log4j_logging =
      noClasses()
          .should().dependOnClassesThat().resideInAPackage("org.apache.log4j..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule no_jcl_logging =
      noClasses()
          .should().dependOnClassesThat().resideInAPackage("org.apache.commons.logging..")
          .allowEmptyShould(true);
}
