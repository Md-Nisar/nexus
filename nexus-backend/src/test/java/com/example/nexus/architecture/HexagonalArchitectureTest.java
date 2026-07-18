package com.example.nexus.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.library.GeneralCodingRules;

/**
 * Enforces the hexagonal dependency rule from ADR 0002 (follow-on NEXUS-0042): inner layers
 * (domain, application) must never depend on outer layers (infrastructure, interfaces).
 *
 * <p>Rules use {@code allowEmptyShould} so they pass while no bounded context exists yet and
 * activate automatically as soon as the first one is created.
 */
@AnalyzeClasses(
        packages = "com.example.nexus",
        importOptions = ImportOption.DoNotIncludeTests.class)
class HexagonalArchitectureTest {

    @ArchTest
    static final ArchRule domain_must_not_depend_on_outer_layers =
            noClasses()
                    .that().resideInAPackage("..domain..")
                    .should().dependOnClassesThat()
                    .resideInAnyPackage("..application..", "..infrastructure..", "..interfaces..")
                    .allowEmptyShould(true);

    @ArchTest
    static final ArchRule application_must_not_depend_on_adapters =
            noClasses()
                    .that().resideInAPackage("..application..")
                    .should().dependOnClassesThat()
                    .resideInAnyPackage("..infrastructure..", "..interfaces..")
                    .allowEmptyShould(true);

    @ArchTest
    static final ArchRule domain_must_not_use_spring_web =
            noClasses()
                    .that().resideInAPackage("..domain..")
                    .should().dependOnClassesThat()
                    .resideInAnyPackage("org.springframework.web..", "jakarta.servlet..")
                    .allowEmptyShould(true);

    // ADR 0016 D6: Redis client types are confined to infrastructure/ adapters — domain and
    // application must consume Redis-backed capabilities only through a hexagonal port
    // (e.g. RateLimitStore), never by importing the client library directly.
    @ArchTest
    static final ArchRule domain_and_application_must_not_depend_on_redis =
            noClasses()
                    .that().resideInAnyPackage("..domain..", "..application..")
                    .should().dependOnClassesThat()
                    .resideInAnyPackage(
                            "org.springframework.data.redis..", "io.lettuce..", "org.redisson..")
                    .allowEmptyShould(true);

    @ArchTest
    static final ArchRule no_field_injection =
            GeneralCodingRules.NO_CLASSES_SHOULD_USE_FIELD_INJECTION;

    @ArchTest
    static final ArchRule no_standard_streams =
            GeneralCodingRules.NO_CLASSES_SHOULD_ACCESS_STANDARD_STREAMS;

    @ArchTest
    static final ArchRule no_java_util_logging =
            GeneralCodingRules.NO_CLASSES_SHOULD_USE_JAVA_UTIL_LOGGING;
}
