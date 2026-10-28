package com.example.nexus.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

/**
 * Validates YAML configuration files adhere to standard 2-space indentation and parse cleanly.
 */
@Tag("UnitTest")
class YamlConfigurationSyntaxTest {

  @Test
  void should_conform_to_two_space_indentation() throws Exception {
    ClassPathResource resource = new ClassPathResource("application-prod.yml");
    try (BufferedReader reader =
        new BufferedReader(
            new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      int lineNum = 0;
      while ((line = reader.readLine()) != null) {
        lineNum++;
        if (line.trim().isEmpty() || line.trim().startsWith("#")) {
          continue;
        }
        int indent = 0;
        while (indent < line.length() && line.charAt(indent) == ' ') {
          indent++;
        }
        assertThat(indent % 2)
            .as("Line %d in application-prod.yml has odd indentation: %s", lineNum, line)
            .isZero();
      }
    }

    YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
    yaml.setResources(resource);
    Properties props = yaml.getObject();
    assertThat(props).isNotNull();
    assertThat(props.getProperty("logging.structured.format.console")).isEqualTo("ecs");
  }
}
