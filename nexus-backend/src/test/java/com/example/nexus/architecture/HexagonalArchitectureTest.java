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
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
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
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.MatrixVariable;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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
    // handlers guard the platform's role-definition surface.
    @ArchTest
    static final ArchRule requires_permission_methods_must_be_public_and_non_final =
            methods().that().areAnnotatedWith(RequiresPermission.class)
                    .should().bePublic()
                    .andShould().notHaveModifier(JavaModifier.FINAL)
                    .because("Spring AOP cannot proxy a non-public or final method, so "
                            + "@RequiresPermission is SILENTLY never enforced on one — no error, "
                            + "no log, no failing test (SECURITY.md §3.1). US-015 quadruples this "
                            + "context's annotated-handler count and its handlers guard the "
                            + "platform's role-definition surface.")
                    .allowEmptyShould(true);

    @ArchTest
    static final ArchRule requires_permission_declaring_classes_must_not_be_final =
            classes().that().containAnyMethodsThat(annotatedWith(RequiresPermission.class))
                    .should().notHaveModifier(JavaModifier.FINAL)
                    .because("CGLIB cannot subclass a final class, so every @RequiresPermission "
                            + "on it is silently unenforced for the same reason as the "
                            + "method-level rule above.")
                    .allowEmptyShould(true);

    // US-015 RC-5a (03b-threat-model.md T-E14): RoleManagementService has UserRoleAssignmentPort
    // injected for exactly one reason: AC11's hasActiveAdminAssignment (Q11, the fresh, locking
    // read). findActiveAssignmentViews is the port's OTHER, non-locking read, built for a
    // different caller's field-redaction decision, and has no legitimate use here — there is no
    // target user in this story's flows. This rule turns that mistake into a build failure
    // instead of a code-review-only expectation.
    @ArchTest
    static final ArchRule role_management_service_must_not_call_the_non_locking_admin_read =
            noClasses().that().haveSimpleName("RoleManagementService")
                    .should().callMethod(
                            UserRoleAssignmentPort.class,
                            "findActiveAssignmentViews",
                            UUID.class,
                            UUID.class)
                    .because("RC-5a (03b-threat-model.md T-E14). RoleManagementService has "
                            + "UserRoleAssignmentPort injected for exactly one reason: AC11's "
                            + "hasActiveAdminAssignment (Q11, the fresh, locking read). "
                            + "findActiveAssignmentViews is the port's OTHER, non-locking read, "
                            + "built for a different caller's field-redaction decision, and has "
                            + "no legitimate use here — there is no target user in this story's "
                            + "flows. The realistic F1 failure is not calling a private helper on "
                            + "another service; it is reaching for the wrong method on a port "
                            + "that is already injected. This rule turns that mistake into a "
                            + "build failure instead of a code-review-only expectation.");

    // US-018 MC-2 (03-design.md §4.3, §4.11): grant-subset decisions read the caller's holdings
    // only from M13 (findHeldRolePermissionIdsForAuthorization). M12 is documented "MUST NEVER be
    // used for an authorization decision"; until M3 deletes it, its single permitted caller is the
    // self-assignment canary helper, which records a signal for an already-decided request.
    // Renaming that helper makes this rule fail, which is intended: the exemption must be
    // re-reviewed, never widened silently.
    @ArchTest
    static final ArchRule m12_is_never_read_on_an_rbac_decision_path =
            noClasses()
                    .that().haveSimpleName("RoleAssignmentService")
                    .or().haveSimpleName("RoleManagementService")
                    .should().callMethodWhere(
                            DescribedPredicate.describe(
                                    "call UserRoleAssignmentPort."
                                            + "findPermissionNamesForActiveAssignmentsOfUser (M12) "
                                            + "from anywhere other than RoleAssignmentService."
                                            + "callerHoldsActiveAdminEquivalentRole",
                                    call -> call.getTarget().getName()
                                                    .equals("findPermissionNamesForActiveAssignmentsOfUser")
                                            && call.getTarget().getOwner()
                                                    .isAssignableTo(UserRoleAssignmentPort.class)
                                            && !(call.getOriginOwner().getSimpleName()
                                                            .equals("RoleAssignmentService")
                                                    && call.getOrigin().getName()
                                                            .equals("callerHoldsActiveAdminEquivalentRole"))))
                    .because("MC-2 (US-018 03-design.md §4.3): A2 and A3 must decide from M13 alone. "
                            + "M12 is a non-authoritative canary read; reusing it, or the JWT, for a "
                            + "grant decision re-opens FR-A2.b.");

    private static final List<Class<? extends Annotation>> ACCESS_MARKERS =
            List.of(RequiresPermission.class, AuthenticatedEndpoint.class, PublicEndpoint.class);

    /** Parameter annotations that bind a value of the request URI or query into the handler. */
    private static final List<Class<? extends Annotation>> REQUEST_BOUND_IDENTIFIER_ANNOTATIONS =
            List.of(PathVariable.class, RequestParam.class, ModelAttribute.class,
                    MatrixVariable.class);

    /** Parameter types MVC resolves from the security context or the servlet, never by binding. */
    private static final List<Class<?>> FRAMEWORK_PARAMETER_TYPES =
            List.of(Principal.class, ServletRequest.class, ServletResponse.class);

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
    // every method of it whose signature carries a @RequestMapping on the class itself, a
    // superclass or an interface (so inherited and interface-declared mappings too). Markers are
    // resolved through the same hierarchy, as AnnotatedElementUtils and Spring Security do.
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
     * implicit binding; recorded as D-8 in 09-technical.md §6) the rule fails on any parameter
     * that:
     *
     * <ul>
     *   <li>carries {@code @PathVariable}, {@code @RequestParam}, {@code @ModelAttribute} or {@code
     *       @MatrixVariable}, whatever its type;
     *   <li>has the raw type {@code UUID}, whatever its annotations;
     *   <li>carries no {@code org.springframework.web.bind.annotation} annotation and is not a
     *       framework or principal type: MVC would bind it from the request, a simple type (as
     *       {@code BeanUtils.isSimpleProperty} defines it: {@code String}, primitives and
     *       wrappers, enums, {@code Number}, {@code CharSequence}, dates and temporals, {@code
     *       UUID}, ...) as an implicit {@code @RequestParam} and any other type as an implicit
     *       {@code @ModelAttribute}. This is fail-closed: an unannotated type the rule does not
     *       know is flagged, not allowed.
     * </ul>
     *
     * <p>Allowed: {@code Authentication}, {@code Principal}, {@code HttpServletRequest} / {@code
     * HttpServletResponse} (any {@code Principal}, {@code ServletRequest} or {@code
     * ServletResponse}), a parameter carrying {@code @AuthenticationPrincipal} (directly or as a
     * meta-annotation), and {@code @RequestBody}. An identifier inside a {@code @RequestBody} is
     * <b>out of scope</b> for this rule: the body is not addressed by the URI and needs review, not
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
                            + "owner's approval (T-004 Option B, extended after code review M1; "
                            + "D-8): an @AuthenticatedEndpoint handler has no permission check, so "
                            + "it may only address the caller's own data through the principal. It "
                            + "takes no request-bound identifier of ANY type: no @PathVariable, "
                            + "@RequestParam, @ModelAttribute or @MatrixVariable parameter, no UUID "
                            + "parameter, and no unannotated parameter that MVC would bind from the "
                            + "request as an implicit @RequestParam or @ModelAttribute. Identifiers "
                            + "in a @RequestBody are out of scope. An endpoint that takes an "
                            + "identifier must use @RequiresPermission.")
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
                Map<String, List<JavaMethod>> methodsBySignature = typeHierarchy(handlerClass)
                        .flatMap(type -> type.getMethods().stream())
                        .filter(method -> !method.getModifiers().contains(JavaModifier.STATIC))
                        .collect(Collectors.groupingBy(HexagonalArchitectureTest::signature,
                                LinkedHashMap::new, Collectors.toList()));
                for (List<JavaMethod> sameSignature : methodsBySignature.values()) {
                    if (sameSignature.stream().noneMatch(
                            method -> method.isMetaAnnotatedWith(RequestMapping.class))) {
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
                        JavaMethod handler = sameSignature.get(0);
                        String location = handler.getOwner().equals(handlerClass)
                                ? handler.getFullName()
                                : handlerClass.getName() + " handler " + handler.getFullName();
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
        if (target.isAnnotatedWith(RequiresPermission.class)) {
            return true;
        }
        if (!(target instanceof JavaMethod method)) {
            return false;
        }
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
                + "@PathVariable, @RequestParam, @ModelAttribute or @MatrixVariable parameter, no "
                + "UUID parameter, no unannotated parameter MVC would bind from the request)") {
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
