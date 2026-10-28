package com.example.nexus.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Tag;
import org.springframework.data.repository.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Architectural rules governing RBAC infrastructure persistence and repositories.
 */
@AnalyzeClasses(
    packages = "com.example.nexus.rbac",
    importOptions = ImportOption.DoNotIncludeTests.class)
@Tag("UnitTest")
class RbacArchitecturalRulesTest {

  @ArchTest
  static final ArchRule repositories_should_not_declare_transactional =
      noMethods()
          .that()
          .areDeclaredInClassesThat()
          .areAssignableTo(Repository.class)
          .should()
          .beAnnotatedWith(Transactional.class)
          .because(
              "Repository query interfaces should not declare @Transactional; transaction"
                  + " boundaries are managed at the application service layer");
}
