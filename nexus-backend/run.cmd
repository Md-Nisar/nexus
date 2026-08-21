@echo off
java ^
  -Xmx1g ^
  -XX:+ExitOnOutOfMemoryError ^
  -XX:+HeapDumpOnOutOfMemoryError ^
  -XX:HeapDumpPath=nexus-backend.hprof ^
  -jar target/nexus-backend-0.0.1-SNAPSHOT.jar