# Stage 1: Builder stage to extract JAR layers
FROM eclipse-temurin:21-jre-alpine AS builder
LABEL authors="skakumanu"

WORKDIR /application

ARG PROJECT_NAME=api-gateway
ARG PROJECT_VERSION=1.0
ARG JAR_FILE_LOCATION=build/libs
ARG JAR_FILE=${PROJECT_NAME}-${PROJECT_VERSION}.jar

# Use COPY for better transparency
COPY ${JAR_FILE_LOCATION}/${JAR_FILE} ./

# Extract the layers using Spring Boot's layertools
RUN java -Djarmode=layertools -jar ${JAR_FILE} extract

# Stage 2: Final runtime image
FROM eclipse-temurin:21-jre-alpine

# Create a dedicated, non-root user and group for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /application

# Copy the extracted layers from the builder stage
COPY --from=builder /application/dependencies/ ./
COPY --from=builder /application/spring-boot-loader/ ./
COPY --from=builder /application/snapshot-dependencies/ ./
COPY --from=builder /application/application/ ./

# Switch to the non-root user before starting the application
USER appuser:appgroup

ENTRYPOINT ["java", "-XX:+UseParallelGC", "-XX:GCTimeRatio=4", "-XX:AdaptiveSizePolicyWeight=90", "-XX:MinHeapFreeRatio=20", "-XX:MaxHeapFreeRatio=40", "-XX:+HeapDumpOnOutOfMemoryError", "-Xms512m", "-Xmx512m", "-Djava.security.egd=file:/dev/./urandom", "org.springframework.boot.loader.launch.JarLauncher"]