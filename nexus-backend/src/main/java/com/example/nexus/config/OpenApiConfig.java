package com.example.nexus.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI metadata for the generated spec (/v3/api-docs) and Swagger UI (/swagger-ui.html).
 * Disabled in production via the prod profile.
 */
@Configuration
public class OpenApiConfig {

  @Bean
  OpenAPI nexusOpenApi() {
    return new OpenAPI()
        .info(new Info()
            .title("Nexus API")
            .description("Nexus platform REST API")
            .version("v1"));
  }
}
