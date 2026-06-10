# ---- Build stage ----
FROM eclipse-temurin:25-jdk AS build
WORKDIR /workspace

# Cache the dependency layer: only re-resolves when the pom changes
COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN ./mvnw -B dependency:go-offline

COPY src src
RUN ./mvnw -B package -DskipTests

# ---- Runtime stage ----
FROM eclipse-temurin:25-jre
WORKDIR /app

# Never run as root
RUN groupadd --system nexus && useradd --system --gid nexus nexus
USER nexus

COPY --from=build /workspace/target/nexus-backend-*.jar app.jar

EXPOSE 1000
ENV JAVA_OPTS=""

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["sh", "-c", "wget -qO- http://localhost:1000/actuator/health/liveness || exit 1"]

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
