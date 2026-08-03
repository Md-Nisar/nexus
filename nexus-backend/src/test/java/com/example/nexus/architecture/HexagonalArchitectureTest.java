package com.example.nexus.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

import com.example.nexus.identity.infrastructure.web.JwtAuthenticationFilter;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.library.GeneralCodingRules;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.junit.jupiter.api.Tag;

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
@Tag("UnitTest")
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

    // US-012 Gate 1 Resolutions 1 and 4: rbac declares outbound ports (UserDirectoryPort,
    // RbacAuditPort) that identity.infrastructure implements — the dependency direction is
    // identity -> rbac, never the reverse. This converts that agreed direction from
    // documentation (03-design.md §7.4) into a build failure.
    @ArchTest
    static final ArchRule rbac_must_not_depend_on_identity =
            noClasses()
                    .that().resideInAPackage("..rbac..")
                    .should().dependOnClassesThat().resideInAPackage("..identity..")
                    .because("rbac declares outbound ports (UserDirectoryPort, RbacAuditPort) that "
                            + "identity.infrastructure implements; a direct rbac -> identity import "
                            + "inverts the agreed direction (US-012 Gate 1 Resolutions 1 and 4) and "
                            + "needs explicit re-review. Note: this rule cannot catch a shared helper "
                            + "placed in a neutral `common.*` package and consumed by both contexts, "
                            + "which would recreate the same coupling with this rule green — that "
                            + "class of regression needs human review, not ArchUnit.")
                    .allowEmptyShould(true);

    // US-012 threat-model T-E10: the existing domain_and_application_must_not_depend_on_spring_
    // security rule is structural (it forbids importing org.springframework.security..) but does
    // not catch java.security.Principal or java.util.Map parameters, which live outside that
    // package and would still let raw authentication data (Principal, or authentication.get
    // Details()'s Map) reach the application layer. RoleAssignmentService's own hard-enforced
    // invariant is that its public methods accept only RoleChangeActor/UUID/RequestContext.
    @ArchTest
    static final ArchRule rbac_application_methods_must_not_accept_principal_or_map =
            noMethods()
                    .that().areDeclaredInClassesThat().resideInAPackage("..rbac.application..")
                    .should().haveRawParameterTypes(
                            DescribedPredicate.describe(
                                    "java.security.Principal or java.util.Map",
                                    (List<JavaClass> types) -> types.stream()
                                            .anyMatch(t -> t.isEquivalentTo(Principal.class)
                                                    || t.isEquivalentTo(Map.class))))
                    .because("RoleAssignmentService's own hard-enforced invariant (T-E10) is that its "
                            + "methods accept only RoleChangeActor/UUID/RequestContext; Principal and "
                            + "Map both stay outside the existing Spring-Security-package ArchUnit "
                            + "rule while reintroducing raw authentication data into this layer")
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
