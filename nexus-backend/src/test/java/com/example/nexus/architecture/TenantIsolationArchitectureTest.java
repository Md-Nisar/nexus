package com.example.nexus.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Set;
import org.junit.jupiter.api.Tag;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/**
 * Tenant-isolation gate: every query method declared on a Spring Data repository whose entity
 * carries a {@code tenantId} field must be tenant-scoped — its name contains {@code Tenant}
 * (derived queries such as {@code findByTenantIdAndEmailHmac}) or it binds a
 * {@code @Param("tenantId")} (JPQL queries).
 *
 * <p>A method that is legitimately unscoped (it is keyed by a globally unique id whose tenant the
 * caller has already verified) must be added to {@link #UNSCOPED_ALLOWLIST} with a reason. That
 * turns "forgot the tenant predicate" from a code-review-only expectation into a build failure,
 * and makes every exception a visible, code-owner-reviewed diff.
 *
 * <p>Limits: inherited {@code JpaRepository} methods ({@code findById}, {@code findAll}) are not
 * checked, and the rule inspects method signatures, not JPQL bodies — a {@code tenantId} parameter
 * that is bound but never used in the WHERE clause still needs human review.
 */
@AnalyzeClasses(
        packages = "com.example.nexus",
        importOptions = ImportOption.DoNotIncludeTests.class)
@Tag("UnitTest")
class TenantIsolationArchitectureTest {

    /**
     * {@code Repository#method} entries exempt from the rule. Entries present when the rule was
     * introduced are grandfathered: they are keyed by a globally unique id (UUIDv7) and predate
     * this gate. Remove an entry when its method gains a tenant predicate; never add one without
     * a reason in the PR description and security-reviewer sign-off.
     */
    private static final Set<String> UNSCOPED_ALLOWLIST = Set.of(
            // Grandfathered at introduction — keyed by a globally unique id.
            "JpaUserRepository#resetFailedAttemptsDirect",
            "JpaRoleRepository#findRoleViewById",
            "JpaRoleRepository#findPermissionNamesByRole",
            "JpaUserRoleRepository#countActiveByUserAndRole",
            "JpaUserRoleRepository#revokeById",
            "JpaUserRoleRepository#findActiveUserIdsByRole");

    @ArchTest
    static final ArchRule tenant_scoped_repository_methods_must_filter_by_tenant =
            classes()
                    .that().areInterfaces()
                    .and().areAssignableTo(Repository.class)
                    .should(declareOnlyTenantScopedQueries())
                    .because("a query on a tenant-owned entity without a tenant predicate is a "
                            + "cross-tenant data leak waiting for one wrong caller (ARCHITECTURE.md: "
                            + "tenant id comes from the auth token). Add the tenant predicate, or "
                            + "allowlist the method with a reason and security-reviewer sign-off.")
                    .allowEmptyShould(true);

    private static ArchCondition<JavaClass> declareOnlyTenantScopedQueries() {
        return new ArchCondition<>("declare only tenant-scoped query methods") {
            @Override
            public void check(JavaClass repository, ConditionEvents events) {
                Class<?> repositoryType = repository.reflect();
                Class<?> entity = entityType(repositoryType);
                if (entity == null || !hasTenantIdField(entity)) {
                    return;
                }
                for (Method method : repositoryType.getDeclaredMethods()) {
                    String key = repositoryType.getSimpleName() + "#" + method.getName();
                    if (isTenantScoped(method) || UNSCOPED_ALLOWLIST.contains(key)) {
                        continue;
                    }
                    events.add(SimpleConditionEvent.violated(repository, key
                            + " queries tenant-owned " + entity.getSimpleName()
                            + " without a Tenant-named method or @Param(\"tenantId\")"));
                }
            }
        };
    }

    private static Class<?> entityType(Class<?> repositoryType) {
        for (Type type : repositoryType.getGenericInterfaces()) {
            if (type instanceof ParameterizedType parameterized
                    && parameterized.getRawType() instanceof Class<?> raw
                    && Repository.class.isAssignableFrom(raw)
                    && parameterized.getActualTypeArguments()[0] instanceof Class<?> entity) {
                return entity;
            }
        }
        return null;
    }

    private static boolean hasTenantIdField(Class<?> entity) {
        for (Class<?> c = entity; c != null && c != Object.class; c = c.getSuperclass()) {
            if (Arrays.stream(c.getDeclaredFields()).anyMatch(f -> f.getName().equals("tenantId"))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isTenantScoped(Method method) {
        return method.getName().contains("Tenant")
                || Arrays.stream(method.getParameterAnnotations())
                        .flatMap(Arrays::stream)
                        .anyMatch(a -> a instanceof Param p && p.value().equals("tenantId"));
    }
}
