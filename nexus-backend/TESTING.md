# Testing Configuration Guide

## Current Setup: H2 In-Memory Database

The tests are currently configured to use **H2 in-memory database**. This is a lightweight, fast solution for local testing.

- **Test Base Class**: `BaseH2IntegrationTest`
- **Configuration**: `application-test.properties` (H2 dialect)
- **Status**: ✅ Working

## MySQL Testcontainers Setup (When Docker is Ready)

Your project is configured with **MySQL Testcontainers** for integration testing with a real MySQL database instance. Once you resolve the Docker setup issue, you can switch to this configuration.

### Prerequisites
1. **Docker Desktop** running with WSL2 backend
2. Docker daemon must be responsive

### How to Switch to MySQL Testcontainers

1. Update `NexusBackendApplicationTests.java`:
```java
class NexusBackendApplicationTests extends BaseIntegrationTest {
    // ... rest of the test
}
```

2. Update `application-test.properties`:
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/nexus_test
spring.datasource.username=nexus
spring.datasource.password=nexus
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQL8Dialect
```

3. Run tests with Docker running:
```bash
mvn clean test
```

### Alternative Test Classes

- **`BaseH2IntegrationTest`**: Uses H2 in-memory database (fast, no Docker needed)
- **`BaseIntegrationTest`**: Uses MySQL via Testcontainers (realistic, requires Docker)

## Troubleshooting Docker Issues

If you encounter "Cannot find a valid Docker environment" errors:

1. Ensure Docker Desktop is running and fully initialized
2. Test Docker CLI: `docker ps` (should return list of containers)
3. Check Docker can run containers: `docker run --rm hello-world`

If Docker Desktop is running but Java/Testcontainers can't connect:
- Verify WSL2 integration is enabled in Docker Desktop settings
- Try restarting Docker Desktop
- Check Java/docker-java compatibility with your Docker version

## Dependencies

### H2 Configuration
- `com.h2database:h2:jar:test`

### MySQL Testcontainers Configuration
- `org.testcontainers:junit-jupiter:jar:test`
- `org.testcontainers:mysql:jar:test`

Both are included in `pom.xml`.

