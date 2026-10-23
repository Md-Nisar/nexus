package com.example.nexus.config;

import com.example.nexus.common.web.ProblemResponse;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.IntegerSchema;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import java.util.Set;
import java.util.TreeSet;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.method.HandlerMethod;

/**
 * OpenAPI metadata for the generated spec (/v3/api-docs) and Swagger UI (/swagger-ui.html).
 * Disabled in production via the prod profile.
 */
@Configuration
public class OpenApiConfig {

  static final String PROBLEM_DETAIL_SCHEMA = "ProblemDetail";
  static final String PROBLEM_MEDIA_TYPE = "application/problem+json";
  static final String ERROR_CODES_EXTENSION = "x-nexus-error-codes";

  @Bean
  OpenAPI nexusOpenApi() {
    return new OpenAPI()
        .info(new Info()
            .title("Nexus API")
            .description("Nexus platform REST API")
            .version("v1"))
        .components(new Components().addSchemas(PROBLEM_DETAIL_SCHEMA, problemDetailSchema()));
  }

  /** Turns each {@link ProblemResponse} on a handler into a {@code ProblemDetail} response. */
  @Bean
  OperationCustomizer problemResponseCustomizer() {
    return (Operation operation, HandlerMethod handlerMethod) -> {
      Set<ProblemResponse> problems =
          AnnotatedElementUtils.getMergedRepeatableAnnotations(
              handlerMethod.getMethod(), ProblemResponse.class);
      if (problems.isEmpty()) {
        return operation;
      }
      if (operation.getResponses() == null) {
        operation.setResponses(new ApiResponses());
      }
      Set<String> codes = new TreeSet<>();
      for (ProblemResponse problem : problems) {
        operation
            .getResponses()
            .addApiResponse(String.valueOf(problem.status()), problemResponse(problem));
        codes.addAll(Set.of(problem.codes()));
      }
      operation.addExtension(ERROR_CODES_EXTENSION, codes.stream().toList());
      return operation;
    };
  }

  private static ApiResponse problemResponse(ProblemResponse problem) {
    Schema<?> reference = new Schema<>().$ref("#/components/schemas/" + PROBLEM_DETAIL_SCHEMA);
    return new ApiResponse()
        .description(problem.description())
        .content(new Content().addMediaType(PROBLEM_MEDIA_TYPE, new MediaType().schema(reference)));
  }

  private static Schema<?> problemDetailSchema() {
    Schema<?> details =
        new ObjectSchema()
            .addProperty("field", new StringSchema())
            .addProperty("message", new StringSchema());
    return new ObjectSchema()
        .description("RFC 9457 problem detail returned for every non-2xx response")
        .addProperty("type", new StringSchema().example("about:blank"))
        .addProperty("title", new StringSchema().example("Conflict"))
        .addProperty("status", new IntegerSchema().example(409))
        .addProperty("detail", new StringSchema().description("Human-readable, safe to display"))
        .addProperty("instance", new StringSchema().example("/api/v1/roles"))
        .addProperty("code", new StringSchema().description("Stable machine-readable code").example("RBAC_003"))
        .addProperty("traceId", new StringSchema().description("The request correlation id"))
        .addProperty("details", new ArraySchema().items(details).description("Validation errors only"))
        .addProperty(
            "requiredPermission",
            new StringSchema().description("RBAC_001 only: the permission the caller lacks"))
        .addProperty(
            "reason",
            new StringSchema().description("Caller-facing denial reason on a 403, when disclosed"));
  }
}
