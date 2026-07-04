package com.example.nexus.common.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

class MdcTaskDecoratorTest {

  private MdcTaskDecorator decorator;

  @BeforeEach
  void setUp() {
    decorator = new MdcTaskDecorator();
    MDC.clear();
  }

  @Test
  void shouldPropagateAndRestoreMdc() throws Exception {
    MDC.put("correlationId", "parent-id");

    Runnable task = () -> {
      assertEquals("parent-id", MDC.get("correlationId"));
      MDC.put("correlationId", "child-id");
    };

    Runnable decorated = decorator.decorate(task);

    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<?> future = executor.submit(decorated);
      future.get();
    } finally {
      executor.shutdown();
    }

    // Verify parent MDC was unaffected by child thread modifications
    assertEquals("parent-id", MDC.get("correlationId"));
  }

  @Test
  void shouldHandleEmptyMdc() throws Exception {
    Runnable task = () -> {
      assertNull(MDC.get("correlationId"));
    };

    Runnable decorated = decorator.decorate(task);

    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<?> future = executor.submit(decorated);
      future.get();
    } finally {
      executor.shutdown();
    }
  }
}
