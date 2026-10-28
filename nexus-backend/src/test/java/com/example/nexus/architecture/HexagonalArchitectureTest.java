package com.example.nexus.architecture;

import static com.tngtech.archunit.core.domain.properties.CanBeAnnotated.Predicates.annotatedWith;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

import com.example.nexus.common.security.AuthenticatedEndpoint;
import com.example.nexus.common.security.PublicEndpoint;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.identity.infrastructure.web.JwtAuthenticationFilter;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaCodeUnit;
import com.tngtech.archunit.core.domain.JavaCodeUnitAccess;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.domain.JavaParameter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.library.GeneralCodingRules;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.lang.annotation.Annotation;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.HttpRequestHandler;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.MatrixVariable;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.HttpExchange;
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

    // US-015 D8: @RequiresPermission is enforced via Spring AOP/CGLIB proxying, which silently
    // no-ops on a non-public or final method/declaring-class — no error, no log, no failing test
    // (SECURITY.md §3.1). US-015 quadruples this context's annotated-handler count and its
    // handlers guard the platform's role-definition surface. A static method is never called
    // through the proxy either: MVC registers a static handler method and invokes it directly
    // (US-018 M1 security review F-2).
    @ArchTest
    static final ArchRule requires_permission_methods_must_be_public_and_non_final =
            methods().that().areAnnotatedWith(RequiresPermission.class)
                    .should().bePublic()
                    .andShould().notHaveModifier(JavaModifier.FINAL)
                    .andShould().notHaveModifier(JavaModifier.STATIC)
                    .because("Spring AOP cannot proxy a non-public, final or static method, so "
                            + "@RequiresPermission is SILENTLY never enforced on one — no error, "
                            + "no log, no failing test (SECURITY.md §3.1). US-015 quadruples this "
                            + "context's annotated-handler count and its handlers guard the "
                            + "platform's role-definition surface.")
                    .allowEmptyShould(true);

    // [OR-24]: Ensure @RequiresPermission is strictly placed on public methods only.
    @ArchTest
    static final ArchRule requires_permission_must_only_be_placed_on_public_methods =
            methods().that().areAnnotatedWith(RequiresPermission.class)
                    .should().bePublic()
                    .because("Spring AOP cannot intercept private or protected methods (OR-24)")
                    .allowEmptyShould(true);

    @ArchTest
    static final ArchRule requires_permission_declaring_classes_must_not_be_final =
            classes().that().containAnyMethodsThat(annotatedWith(RequiresPermission.class))
                    .should().notHaveModifier(JavaModifier.FINAL)
                    .because("CGLIB cannot subclass a final class, so every @RequiresPermission "
                            + "on it is silently unenforced for the same reason as the "
                            + "method-level rule above.")
                    .allowEmptyShould(true);

    // US-018 M1 security review F-3: Spring Security resolves @RequiresPermission through the
    // type hierarchy, and the marker rule below counts an interface or base-class placement as
    // "classified" (code review M-1). The two rules above check only the method that carries the
    // annotation, so a public final implementation of an annotated interface method passed every
    // rule while the CGLIB proxy could not override it: the guard never ran and Spring logged
    // only a startup WARN. The method that actually runs must be proxyable too.
    @ArchTest
    static final ArchRule requires_permission_overrides_must_be_proxyable =
            classes()
                    .should(overrideRequiresPermissionMethodsOnlyProxyably())
                    .because("US-018 M1 security review F-3: a method that overrides or implements "
                            + "a @RequiresPermission supertype or interface method is the one the "
                            + "proxy must intercept. If it is non-public, final or static, or its "
                            + "class is final, @RequiresPermission is SILENTLY never enforced "
                            + "(SECURITY.md §3.1).");

    // US-018 M3 (ledger row 17, FR-A5.c proxy; T-019(e)): "RoleAssignmentService shrinks materially"
    // is measured, not asserted. After M3 no symbol of the retired machinery appears anywhere in
    // rbac.application: the name- and permission-list predicates, the second caller gate (M5, M5b),
    // the non-locking name read the canary used (M12) and its helper, and the D23 / canary meter
    // and event names. A source scan, not a bytecode rule, because the meter and event names are
    // string constants that ArchUnit cannot see once compiled. The two former ArchUnit rules that
    // kept RoleManagementService off the non-locking admin read and M12 off decision paths (row 18)
    // are removed with the methods they guarded: that is now a compile-time fact.
    private static final List<String> RETIRED_SYMBOLS =
            List.of(
                    "RbacDangerousPermissions",
                    "RbacAdminEquivalence",
                    "hasActiveAdminAssignment",
                    "hasActiveAssignmentOfAnyRole",
                    "findPermissionNamesForActiveAssignmentsOfUser",
                    "findPermissionNamesForTenantRoles",
                    "findPermissionNamesForRole",
                    "callerHoldsActiveAdminEquivalentRole",
                    "admin_minted_by_non_named_admin",
                    "ADMIN_MINTED_BY_NON_NAMED_ADMIN",
                    "privileged_role_change_allowed",
                    "self_role_assignment");

    @ArchTest
    static void rbac_application_must_not_reference_the_retired_authorization_machinery(
            JavaClasses classes) throws IOException {
        Path applicationSources = Path.of("src/main/java/com/example/nexus/rbac/application");
        List<Path> sources;
        try (Stream<Path> walk = Files.walk(applicationSources)) {
            sources = walk.filter(path -> path.toString().endsWith(".java")).toList();
        }
        // Zero files found means the path broke, not that the package is clean.
        org.assertj.core.api.Assertions.assertThat(sources)
                .as("rbac.application sources found under " + applicationSources.toAbsolutePath())
                .hasSizeGreaterThan(5);
        List<String> offences = new ArrayList<>();
        for (Path source : sources) {
            String text = Files.readString(source);
            for (String symbol : RETIRED_SYMBOLS) {
                if (text.contains(symbol)) {
                    offences.add(source.getFileName() + " references " + symbol);
                }
            }
        }
        org.assertj.core.api.Assertions.assertThat(offences)
                .as("US-018 FR-A5.c proxy (design §5.1 row 17): no symbol of the retired machinery"
                        + " may be referenced from rbac.application")
                .isEmpty();
    }

    private static final List<Class<? extends Annotation>> ACCESS_MARKERS =
            List.of(RequiresPermission.class, AuthenticatedEndpoint.class, PublicEndpoint.class);

    /** Method annotations (meta-annotations included) that make MVC register a handler. */
    private static final List<Class<? extends Annotation>> MAPPING_ANNOTATIONS =
            List.of(RequestMapping.class, HttpExchange.class);

    /**
     * Parameter annotations that bind a caller-chosen value of the request (URI, query, headers,
     * cookies) into the handler.
     */
    private static final List<Class<? extends Annotation>> REQUEST_BOUND_IDENTIFIER_ANNOTATIONS =
            List.of(PathVariable.class, RequestParam.class, ModelAttribute.class,
                    MatrixVariable.class, RequestHeader.class, CookieValue.class);

    /**
     * Parameter types MVC resolves from the security context or the servlet, never by binding,
     * and that carry no caller-chosen value. {@code ServletRequest} is not one of them: it exposes
     * every header, cookie and parameter (security review F-4).
     */
    private static final List<Class<?>> FRAMEWORK_PARAMETER_TYPES =
            List.of(Principal.class, ServletResponse.class);

    /**
     * Production classes allowed to declare or use a handler type that {@code
     * RequestMappingHandlerMapping} does not serve. Empty: every production handler is an
     * annotated controller, so the marker rules and the web sweeps see it. Add an entry only with
     * a reason and security-reviewer sign-off, together with a sweep that classifies the new
     * handler type.
     */
    private static final Set<String> NON_ANNOTATED_HANDLER_ALLOWLIST = Set.of();

    private static final String WEB_BIND_ANNOTATION_PACKAGE =
            "org.springframework.web.bind.annotation";

    // US-018 A8 (03-design.md §3.1, FR-A8.a): deny-by-default is only as good as the
    // classification of every handler. Each one states its access requirement with exactly one
    // marker, so a new handler cannot silently inherit "authenticated, no permission" from
    // anyRequest().authenticated(). Empty is not allowed: zero handlers found means the predicate
    // broke, not that the application has no REST API.
    //
    // The selection follows what Spring MVC registers, not only what is declared in a
    // @RestController (code review M-1): every concrete class that is, or has a superclass or
    // interface that is, meta-annotated with @Controller (so @Controller + @ResponseBody too), and
    // every method of it whose signature carries a @RequestMapping or an @HttpExchange (each
    // meta-annotations included) on the class itself, a superclass or an interface (so inherited
    // and interface-declared mappings too). Markers are resolved through the same hierarchy, as
    // AnnotatedElementUtils and Spring Security do. A static method that carries a mapping fails
    // whatever its markers (security review F-2): MVC registers and invokes it, but the
    // method-security proxy never intercepts a static method, so a marker on it means nothing.
    @ArchTest
    static final ArchRule rest_handlers_must_carry_exactly_one_access_marker =
            classes()
                    .that(areConcreteMvcHandlerClasses())
                    .should(declareOnlyHandlersWithExactlyOneAccessMarker())
                    .because("US-018 A8 (FR-A8.a): every REST handler declares whether it is "
                            + "permission-guarded (@RequiresPermission), authenticated-only "
                            + "(@AuthenticatedEndpoint) or anonymous (@PublicEndpoint). An unmarked "
                            + "handler is reachable by any signed-in caller with no permission check "
                            + "and nobody decided that.");

    // US-018 M1 security review F-1: the marker rule above and EndpointClassificationWebTest see
    // only annotated controllers. A functional endpoint (RouterFunction, served by
    // RouterFunctionMapping) or an HttpRequestHandler / mvc.Controller bean (served by
    // BeanNameUrlHandlerMapping or a SimpleUrlHandlerMapping) carries no access marker and is
    // invisible to both, so production code may not declare or use one outside the allowlist.
    @ArchTest
    static final ArchRule no_handlers_outside_annotated_controllers =
            noClasses()
                    .that(DescribedPredicate.describe(
                            "are not in NON_ANNOTATED_HANDLER_ALLOWLIST",
                            (JavaClass javaClass) ->
                                    !NON_ANNOTATED_HANDLER_ALLOWLIST.contains(javaClass.getName())))
                    .should().dependOnClassesThat(DescribedPredicate.describe(
                            "are functional-endpoint types (org.springframework.web.servlet."
                                    + "function..), HttpRequestHandler or org.springframework.web."
                                    + "servlet.mvc.Controller",
                            (JavaClass type) -> type.getPackageName()
                                            .startsWith("org.springframework.web.servlet.function")
                                    || type.isAssignableTo(HttpRequestHandler.class)
                                    || type.isAssignableTo(
                                            org.springframework.web.servlet.mvc.Controller.class)))
                    .because("US-018 M1 security review F-1 (FR-A8.a): a handler that "
                            + "RequestMappingHandlerMapping does not serve escapes the access-marker "
                            + "rule and every EndpointClassificationWebTest sweep, so nobody decides "
                            + "its access requirement. Use an annotated @RestController with an "
                            + "access marker, or allowlist the class with a reason and "
                            + "security-reviewer sign-off.");

    // US-018 A8 (03-design.md §3.1, FR-A8.b): Spring AOP does not intercept a call a bean makes
    // to itself, so a @RequiresPermission method reached that way runs unguarded (SECURITY.md
    // §3.1). "Itself" covers a plain call, a this::method reference, a call from a nested, inner,
    // anonymous or lambda body of the class, and a call to an inherited annotated method. A target
    // also counts as annotated when the class overrides a superclass or interface method that
    // carries @RequiresPermission, because Spring Security finds the annotation there on proxied
    // calls (code review L-1). The check is deliberately conservative: a class calling the
    // annotated method of a different instance of its own type (or a supertype) is also flagged;
    // route such a call through the injected bean of another class instead.
    @ArchTest
    static final ArchRule no_self_invocation_of_requires_permission_methods =
            classes()
                    .should(notInvokeOwnRequiresPermissionMethods())
                    .because("US-018 A8 (FR-A8.b): Spring AOP does not intercept self-invocation, "
                            + "so @RequiresPermission is SILENTLY not enforced on a call a bean makes "
                            + "to itself — no error, no log, no failing test (SECURITY.md §3.1).");

    /**
     * US-018 A8 (03-design.md §3.1, RC-40.2, FR-A8.c), deliberately strengthened beyond the design:
     * an {@code @AuthenticatedEndpoint} handler takes <b>no request-bound identifier of any
     * type</b>. The constant keeps its original name for traceability; it no longer bans UUIDs
     * only.
     *
     * <p>The design bans only {@code UUID}-typed {@code @PathVariable} / {@code @RequestParam}. The
     * house style, however, declares identifiers as {@code String} and parses them after
     * validation (D15, {@code RoleController}), and MVC binds an unannotated simple-type parameter
     * as an implicit {@code @RequestParam}, so a UUID-only ban is bypassed by following the
     * convention or by leaving the annotation off. With the story owner's approval (US-018 T-004,
     * Option B, extended after code review M1 to {@code String}, {@code @ModelAttribute} and
     * implicit binding, and after security review M1 (F-4) to headers, cookies and the raw
     * request; recorded as D-8 in 09-technical.md §6) the rule fails on any parameter that:
     *
     * <ul>
     *   <li>carries {@code @PathVariable}, {@code @RequestParam}, {@code @ModelAttribute}, {@code
     *       @MatrixVariable}, {@code @RequestHeader} or {@code @CookieValue}, whatever its type;
     *   <li>has the raw type {@code UUID}, whatever its annotations;
     *   <li>is a {@code ServletRequest} ({@code HttpServletRequest} included), which hands the
     *       handler every header, cookie and parameter of the request;
     *   <li>carries no {@code org.springframework.web.bind.annotation} annotation and is not a
     *       framework or principal type: MVC would bind it from the request, a simple type (as
     *       {@code BeanUtils.isSimpleProperty} defines it: {@code String}, primitives and
     *       wrappers, enums, {@code Number}, {@code CharSequence}, dates and temporals, {@code
     *       UUID}, ...) as an implicit {@code @RequestParam} and any other type as an implicit
     *       {@code @ModelAttribute}. This is fail-closed: an unannotated type the rule does not
     *       know is flagged, not allowed.
     * </ul>
     *
     * <p>Allowed: {@code Authentication}, {@code Principal}, {@code HttpServletResponse} (any
     * {@code Principal} or {@code ServletResponse}), a parameter carrying {@code
     * @AuthenticationPrincipal} (directly or as a meta-annotation), and {@code @RequestBody}. If a
     * handler ever needs a specific header, allowlist that header by name with a reason rather
     * than allowing {@code @RequestHeader} in general. An identifier inside a {@code
     * @RequestBody} is <b>out of scope</b> for this rule: the body is not addressed by the URI and needs review, not
     * ArchUnit. An authenticated-only handler addresses the caller through the principal; an
     * endpoint that takes another resource's identifier must be permission-guarded.
     *
     * <p>Zero {@code @AuthenticatedEndpoint} handlers is a legitimate state, hence {@code
     * allowEmptyShould(true)}.
     */
    @ArchTest
    static final ArchRule authenticated_endpoints_take_no_uuid_identifier =
            methods()
                    .that().areAnnotatedWith(AuthenticatedEndpoint.class)
                    .should(takeNoRequestBoundIdentifier())
                    .because("US-018 RC-40.2 (design §3: UUID-only), strengthened with the story "
                            + "owner's approval (T-004 Option B, extended after code review M1 and "
                            + "security review M1 F-4; D-8): an @AuthenticatedEndpoint handler has "
                            + "no permission check, so it may only address the caller's own data "
                            + "through the principal. It takes no request-bound identifier of ANY "
                            + "type: no @PathVariable, @RequestParam, @ModelAttribute, "
                            + "@MatrixVariable, @RequestHeader or @CookieValue parameter, no UUID "
                            + "parameter, no ServletRequest parameter, and no unannotated parameter "
                            + "that MVC would bind from the request as an implicit @RequestParam or "
                            + "@ModelAttribute. Identifiers in a @RequestBody are out of scope. An "
                            + "endpoint that takes an identifier must use @RequiresPermission.")
                    .allowEmptyShould(true);

    // US-019 T-008 (design §6.2 "Must not", T-S13): the caller authorization profile is read live.
    // A dependency on the permission cache, the token-time resolution or the JWT claim keys would
    // turn it into an echo of what the token or the cache last saw, misguiding every UI affordance.
    @ArchTest
    static final ArchRule caller_authorization_reads_neither_cache_nor_token_claims =
            noClasses()
                    .that().haveSimpleNameStartingWith("CallerAuthorization")
                    .and().resideInAPackage("..rbac..")
                    .should().dependOnClassesThat().haveFullyQualifiedName(
                            "com.example.nexus.rbac.application.port.out.PermissionCachePort")
                    .orShould().dependOnClassesThat().haveFullyQualifiedName(
                            "com.example.nexus.rbac.application.RoleResolutionService")
                    .orShould().dependOnClassesThat().haveFullyQualifiedName(
                            "com.example.nexus.common.security.AuthenticationDetailKeys")
                    .because("US-019 design §6.2 and threat T-S13: B4 makes live reads in one "
                            + "snapshot; it never reads the permission cache, the token-time role "
                            + "resolution or JWT claims beyond the principal and tenant.");

    // US-018 T-007 (03-design.md §7.2, EC2). Defined in ArchitectureRules so the fixture tests
    // that prove each rule fires can reach them while this class stays package-private.
    @ArchTest
    static final ArchRule bootstrap_admin_service_is_reachable_only_from_the_cli =
            ArchitectureRules.BOOTSTRAP_ADMIN_SERVICE_IS_REACHABLE_ONLY_FROM_THE_CLI;

    @ArchTest
    static final ArchRule break_glass_never_calls_role_assignment_assign_or_revoke =
            ArchitectureRules.BREAK_GLASS_NEVER_CALLS_ROLE_ASSIGNMENT_ASSIGN_OR_REVOKE;

    // US-018 T-008 (03-design.md §7.2 Containment): every CLI bean loads only under break-glass.
    @ArchTest
    static final ArchRule cli_beans_are_break_glass_profile_only =
            ArchitectureRules.CLI_BEANS_ARE_BREAK_GLASS_PROFILE_ONLY;

    // US-018 M5 security review L-3: the allowlisted global replay lookup stays break-glass-only.
    @ArchTest
    static final ArchRule break_glass_grant_lookup_port_is_contained =
            ArchitectureRules.BREAK_GLASS_GRANT_LOOKUP_PORT_IS_CONTAINED;

    @ArchTest
    static final ArchRule global_break_glass_replay_query_is_called_only_by_its_adapter =
            ArchitectureRules.GLOBAL_BREAK_GLASS_REPLAY_QUERY_IS_CALLED_ONLY_BY_ITS_ADAPTER;

    // US-019 RC-61.2: the allowlisted unscoped user count stays inside the directory adapter.
    @ArchTest
    static final ArchRule unscoped_user_count_is_called_only_by_the_directory_adapter =
            ArchitectureRules.UNSCOPED_USER_COUNT_IS_CALLED_ONLY_BY_THE_DIRECTORY_ADAPTER;

    // US-019 review R2-3: the unscoped existsById probes stay inside the directory service/adapter.
    @ArchTest
    static final ArchRule unscoped_user_existence_probe_is_called_only_by_the_directory_service =
            ArchitectureRules.UNSCOPED_USER_EXISTENCE_PROBE_IS_CALLED_ONLY_BY_THE_DIRECTORY_SERVICE;

    @ArchTest
    static final ArchRule unscoped_user_exists_by_id_is_called_only_by_the_directory_adapter =
            ArchitectureRules.UNSCOPED_USER_EXISTS_BY_ID_IS_CALLED_ONLY_BY_THE_DIRECTORY_ADAPTER;

    // US-019 RC-63(k): isSensitive is UX only; only the response mapper reads the sets.
    @ArchTest
    static final ArchRule sensitivity_sets_are_read_only_by_the_response_mapper =
            ArchitectureRules.SENSITIVITY_SETS_ARE_READ_ONLY_BY_THE_RESPONSE_MAPPER;

    @ArchTest
    static final ArchRule no_field_injection =
            GeneralCodingRules.NO_CLASSES_SHOULD_USE_FIELD_INJECTION;

    @ArchTest
    static final ArchRule no_standard_streams =
            GeneralCodingRules.NO_CLASSES_SHOULD_ACCESS_STANDARD_STREAMS;

    @ArchTest
    static final ArchRule no_java_util_logging =
            GeneralCodingRules.NO_CLASSES_SHOULD_USE_JAVA_UTIL_LOGGING;

    private static DescribedPredicate<JavaClass> areConcreteMvcHandlerClasses() {
        return DescribedPredicate.describe(
                "are concrete classes meta-annotated with @Controller on themselves, a superclass "
                        + "or an interface",
                javaClass -> !javaClass.isInterface()
                        && !javaClass.getModifiers().contains(JavaModifier.ABSTRACT)
                        && typeHierarchy(javaClass)
                                .anyMatch(type -> type.isMetaAnnotatedWith(Controller.class)));
    }

    private static ArchCondition<JavaClass> declareOnlyHandlersWithExactlyOneAccessMarker() {
        return new ArchCondition<>("have handler methods (own, inherited or interface-declared "
                + "mappings) that each carry exactly one of @RequiresPermission, "
                + "@AuthenticatedEndpoint, @PublicEndpoint") {
            @Override
            public void check(JavaClass handlerClass, ConditionEvents events) {
                List<JavaMethod> hierarchyMethods = typeHierarchy(handlerClass)
                        .flatMap(type -> type.getMethods().stream())
                        .toList();
                hierarchyMethods.stream()
                        .filter(method -> method.getModifiers().contains(JavaModifier.STATIC)
                                && carriesMapping(method))
                        .forEach(method -> events.add(SimpleConditionEvent.violated(handlerClass,
                                handlerLocation(handlerClass, method) + " is a static handler "
                                        + "method: MVC invokes it directly and method security "
                                        + "never intercepts it; make it an instance method")));
                Map<String, List<JavaMethod>> methodsBySignature = hierarchyMethods.stream()
                        .filter(method -> !method.getModifiers().contains(JavaModifier.STATIC))
                        .collect(Collectors.groupingBy(HexagonalArchitectureTest::signature,
                                LinkedHashMap::new, Collectors.toList()));
                for (List<JavaMethod> sameSignature : methodsBySignature.values()) {
                    if (sameSignature.stream()
                            .noneMatch(HexagonalArchitectureTest::carriesMapping)) {
                        continue;
                    }
                    List<String> markers = ACCESS_MARKERS.stream()
                            .filter(marker -> sameSignature.stream()
                                    .anyMatch(method -> method.isAnnotatedWith(marker)))
                            .map(Class::getSimpleName)
                            .toList();
                    if (markers.size() != 1) {
                        // Nearest declaration first: the class itself, then superclasses, then
                        // interfaces, so a directly declared handler is named as before.
                        String location = handlerLocation(handlerClass, sameSignature.get(0));
                        String problem = markers.isEmpty()
                                ? "carries no access marker"
                                : "carries more than one access marker " + markers;
                        events.add(SimpleConditionEvent.violated(
                                handlerClass, location + " " + problem));
                    }
                }
            }
        };
    }

    private static boolean carriesMapping(JavaMethod method) {
        return MAPPING_ANNOTATIONS.stream().anyMatch(method::isMetaAnnotatedWith);
    }

    private static String handlerLocation(JavaClass handlerClass, JavaMethod handler) {
        return handler.getOwner().equals(handlerClass)
                ? handler.getFullName()
                : handlerClass.getName() + " handler " + handler.getFullName();
    }

    private static ArchCondition<JavaClass> overrideRequiresPermissionMethodsOnlyProxyably() {
        return new ArchCondition<>("override @RequiresPermission supertype or interface methods "
                + "only with public, non-final, non-static methods in a non-final class") {
            @Override
            public void check(JavaClass javaClass, ConditionEvents events) {
                for (JavaMethod method : javaClass.getMethods()) {
                    if (method.getModifiers().contains(JavaModifier.ABSTRACT)
                            || !overridesRequiresPermissionMethod(method)) {
                        continue;
                    }
                    List<String> problems = new ArrayList<>();
                    if (!method.getModifiers().contains(JavaModifier.PUBLIC)) {
                        problems.add("is not public");
                    }
                    if (method.getModifiers().contains(JavaModifier.FINAL)) {
                        problems.add("is final");
                    }
                    if (method.getModifiers().contains(JavaModifier.STATIC)) {
                        problems.add("is static");
                    }
                    if (javaClass.getModifiers().contains(JavaModifier.FINAL)) {
                        problems.add("is declared in a final class");
                    }
                    if (!problems.isEmpty()) {
                        events.add(SimpleConditionEvent.violated(method, method.getFullName()
                                + " overrides a @RequiresPermission method but "
                                + String.join(" and ", problems)
                                + ", so the proxy never enforces the permission"));
                    }
                }
            }
        };
    }

    private static ArchCondition<JavaClass> notInvokeOwnRequiresPermissionMethods() {
        return new ArchCondition<>(
                "not call or reference a @RequiresPermission method of their own instance") {
            @Override
            public void check(JavaClass origin, ConditionEvents events) {
                for (JavaCodeUnitAccess<?> access : origin.getCodeUnitAccessesFromSelf()) {
                    if (isOwnOrEnclosingType(origin, access.getTargetOwner())
                            && access.getTarget().resolveMember()
                                    .map(HexagonalArchitectureTest::carriesRequiresPermission)
                                    .orElse(false)) {
                        events.add(SimpleConditionEvent.violated(access, access.getDescription()));
                    }
                }
            }
        };
    }

    /**
     * True when {@code target} carries {@code @RequiresPermission} itself or is a method that
     * overrides a superclass or interface method carrying it (Spring Security resolves the
     * annotation through that hierarchy).
     */
    private static boolean carriesRequiresPermission(JavaCodeUnit target) {
        return target.isAnnotatedWith(RequiresPermission.class)
                || target instanceof JavaMethod method && overridesRequiresPermissionMethod(method);
    }

    /** True when a same-signature superclass or interface method carries the annotation. */
    private static boolean overridesRequiresPermissionMethod(JavaMethod method) {
        JavaClass owner = method.getOwner();
        String signature = signature(method);
        return Stream.concat(
                        owner.getAllRawSuperclasses().stream(),
                        owner.getAllRawInterfaces().stream())
                .flatMap(type -> type.getMethods().stream())
                .anyMatch(candidate -> signature(candidate).equals(signature)
                        && candidate.isAnnotatedWith(RequiresPermission.class));
    }

    /** The class itself, then its superclasses nearest first, then all of its interfaces. */
    private static Stream<JavaClass> typeHierarchy(JavaClass javaClass) {
        return Stream.concat(
                Stream.concat(Stream.of(javaClass), javaClass.getAllRawSuperclasses().stream()),
                javaClass.getAllRawInterfaces().stream());
    }

    /** Name plus raw parameter types: equal for a method and the methods it overrides. */
    private static String signature(JavaMethod method) {
        return method.getName() + method.getRawParameterTypes().stream()
                .map(JavaClass::getName)
                .collect(Collectors.joining(",", "(", ")"));
    }

    /**
     * True when {@code target} is {@code origin}, a supertype of it, or (transitively) the class
     * enclosing it: in each case a call from {@code origin} reaches the bean's own instance
     * without passing through its proxy.
     */
    private static boolean isOwnOrEnclosingType(JavaClass origin, JavaClass target) {
        Optional<JavaClass> current = Optional.of(origin);
        while (current.isPresent()) {
            if (current.get().isAssignableTo(target.getName())) {
                return true;
            }
            current = current.get().getEnclosingClass();
        }
        return false;
    }

    private static ArchCondition<JavaMethod> takeNoRequestBoundIdentifier() {
        return new ArchCondition<>("take no request-bound identifier of any type (no "
                + "@PathVariable, @RequestParam, @ModelAttribute, @MatrixVariable, @RequestHeader "
                + "or @CookieValue parameter, no UUID or ServletRequest parameter, no unannotated "
                + "parameter MVC would bind from the request)") {
            @Override
            public void check(JavaMethod method, ConditionEvents events) {
                for (JavaParameter parameter : method.getParameters()) {
                    requestBoundIdentifierProblem(parameter).ifPresent(problem ->
                            events.add(SimpleConditionEvent.violated(
                                    method, method.getFullName() + " " + problem)));
                }
            }
        };
    }

    private static Optional<String> requestBoundIdentifierProblem(JavaParameter parameter) {
        int index = parameter.getIndex();
        for (Class<? extends Annotation> annotation : REQUEST_BOUND_IDENTIFIER_ANNOTATIONS) {
            if (parameter.isAnnotatedWith(annotation)) {
                return Optional.of("declares @" + annotation.getSimpleName() + " parameter #"
                        + index);
            }
        }
        JavaClass type = parameter.getRawType();
        if (type.isEquivalentTo(UUID.class)) {
            return Optional.of("declares UUID parameter #" + index);
        }
        if (type.isAssignableTo(ServletRequest.class)) {
            return Optional.of("declares ServletRequest parameter #" + index + " of type "
                    + type.getName() + ", which exposes every header, cookie and parameter");
        }
        if (parameter.isAnnotatedWith(RequestBody.class)
                || parameter.isMetaAnnotatedWith(AuthenticationPrincipal.class)
                || FRAMEWORK_PARAMETER_TYPES.stream().anyMatch(type::isAssignableTo)) {
            return Optional.empty();
        }
        boolean hasBindingAnnotation = parameter.getAnnotations().stream()
                .anyMatch(annotation -> annotation.getRawType().getPackageName()
                        .equals(WEB_BIND_ANNOTATION_PACKAGE));
        if (!hasBindingAnnotation) {
            return Optional.of("declares unannotated parameter #" + index + " of type "
                    + type.getName() + ", which MVC binds from the request as an implicit "
                    + "@RequestParam or @ModelAttribute");
        }
        return Optional.empty();
    }
}
