package com.example.nexus.config;

import com.example.nexus.common.web.MdcTaskDecorator;
import org.springframework.boot.task.SimpleAsyncTaskExecutorCustomizer;
import org.springframework.boot.task.ThreadPoolTaskExecutorCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskDecorator;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Activates asynchronous execution support and applies trace propagation to all executors.
 */
@Configuration
@EnableAsync
public class AsyncConfig {

  /**
   * Defines the MDC TaskDecorator bean used to copy parent MDC to child threads.
   */
  @Bean
  public TaskDecorator taskDecorator() {
    return new MdcTaskDecorator();
  }

  /**
   * Applies the MDC TaskDecorator automatically to any auto-configured ThreadPoolTaskExecutor.
   */
  @Bean
  public ThreadPoolTaskExecutorCustomizer threadPoolTaskExecutorCustomizer(
      TaskDecorator taskDecorator) {
    return executor -> executor.setTaskDecorator(taskDecorator);
  }

  /**
   * Applies the MDC TaskDecorator automatically to any auto-configured SimpleAsyncTaskExecutor
   * (used when virtual threads are enabled).
   */
  @Bean
  public SimpleAsyncTaskExecutorCustomizer simpleAsyncTaskExecutorCustomizer(
      TaskDecorator taskDecorator) {
    return executor -> executor.setTaskDecorator(taskDecorator);
  }
}
