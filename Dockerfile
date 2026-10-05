# syntax=docker/dockerfile:1
# Build with the platform root as a named context, as docker-compose.yml does:
#   docker build --build-context platform=../micro-services -t api-gateway .

# Gradle itself comes from the official image (same version as the wrapper), so the build does
# not depend on downloading the wrapper distribution; the JDK is Temurin 27.
FROM gradle:9.8.0-jdk21 AS gradle-distribution

FROM eclipse-temurin:27-jdk AS build
COPY --from=gradle-distribution /opt/gradle /opt/gradle
WORKDIR /workspace
# The version catalog and shared starter are resolved from ../micro-services (ADR 0003).
COPY --from=platform . micro-services/
COPY . api-gateway/
WORKDIR /workspace/api-gateway
RUN --mount=type=cache,target=/root/.gradle /opt/gradle/bin/gradle bootJar --no-daemon

FROM eclipse-temurin:27-jre-alpine
RUN apk add --no-cache curl && addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=build --chown=app:app /workspace/api-gateway/build/libs/application.jar application.jar
USER app:app
EXPOSE 9211
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=10 \
  CMD curl --fail --silent http://localhost:9211/actuator/health/readiness || exit 1
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "application.jar"]
