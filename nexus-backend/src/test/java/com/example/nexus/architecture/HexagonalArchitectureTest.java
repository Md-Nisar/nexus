package com.example.nexus.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.example.nexus.identity.infrastructure.web.JwtAuthenticationFilter;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.library.GeneralCodingRules;
import org.springframework.security.core.Authentication;

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

    // ADR 0016 D6 (mirrored): Spring Security types must be confined to infrastructure/
    // interfaces adapters and cross-cutting common.security — domain and application must
    // consume authentication/authorization capabilities only through a hexagonal port, never
    // by importing Spring Security classes (e.g. Authentication, @PreAuthorize) directly.
    @ArchTest
    static final ArchRule domain_and_application_must_not_depend_on_spring_security =
            noClasses()
                    .that().resideInAnyPackage("..domain..", "..application..")
                    .should().dependOnClassesThat()
                    .resideInAnyPackage("org.springframework.security..")
                    .allowEmptyShould(true);

    // ADR 0013 amendment (US-011 threat-model T-02): only JwtAuthenticationFilter may attach
    // RBAC-bearing details (permissions/tenantId) to an authenticated Authentication. A second
    // producer would break the tenant-provenance invariant that TenantAwarePermissionEvaluator
    // relies on but cannot itself verify.
    @ArchTest
    static final ArchRule only_jwtAuthenticationFilter_sets_authentication_details =
            noClasses()
                    .that().areNotAssignableTo(JwtAuthenticationFilter.class)
                    .should().callMethodWhere(
                            DescribedPredicate.describe(
                                    "call Authentication.setDetails(Object)",
                                    call -> call.getTarget().getName().equals("setDetails")
                                            && call.getTarget().getOwner()
                                                    .isAssignableTo(Authentication.class)))
                    .because("only JwtAuthenticationFilter may attach RBAC-bearing details "
                            + "(permissions/tenantId) to an authenticated Authentication — a second "
                            + "producer breaks the tenant-provenance invariant (ADR-0013 amendment, "
                            + "threat-model T-02) and needs an explicit re-review before it can be "
                            + "added")
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
