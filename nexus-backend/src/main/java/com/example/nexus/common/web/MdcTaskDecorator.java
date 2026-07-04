package com.example.nexus.common.web;

import java.util.Map;
import org.slf4j.MDC;
import org.springframework.core.task.TaskDecorator;

/**
 * TaskDecorator that copies the parent thread's MDC context map to the child thread.
 * Guarantees MDC state restoration on the executor thread to prevent thread pollution and leaks.
 */
public class MdcTaskDecorator implements TaskDecorator {

  @Override
  public Runnable decorate(Runnable runnable) {
    Map<String, String> contextMap = MDC.getCopyOfContextMap();
    return () -> {
      Map<String, String> previousContext = MDC.getCopyOfContextMap();
      if (contextMap != null) {
        MDC.setContextMap(contextMap);
      } else {
        MDC.clear();
      }
      try {
        runnable.run();
      } finally {
        if (previousContext != null) {
          MDC.setContextMap(previousContext);
        } else {
          MDC.clear();
        }
      }
    };
  }
}
