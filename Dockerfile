FROM eclipse-temurin:21-jre-alpine AS jre-build
LABEL authors="skakumanu"
RUN addgroup -S srikanth-group && adduser -S srikanth -G srikanth-group
USER srikanth:srikanth-group
WORKDIR application

ARG PROJECT_NAME=api-gateway
ARG PROJECT_VERSION=1.0
ARG JAR_FILE_LOCATION=build/libs
ARG JAR_FILE=${PROJECT_NAME}-${PROJECT_VERSION}.jar

ADD ${JAR_FILE_LOCATION}/${JAR_FILE} ./
RUN java -Djarmode=layertools -jar ${JAR_FILE} extract


FROM eclipse-temurin:21-jre-alpine

WORKDIR application
CMD apt-get update -y

COPY --from=jre-build application/dependencies/ ./
COPY --from=jre-build application/spring-boot-loader/ ./
COPY --from=jre-build application/snapshot-dependencies/ ./
COPY --from=jre-build application/application/ ./
ENTRYPOINT ["java", "-XX:+UseParallelGC", "-XX:GCTimeRatio=4", "-XX:AdaptiveSizePolicyWeight=90", "-XX:MinHeapFreeRatio=20", "-XX:MaxHeapFreeRatio=40", "-XX:+HeapDumpOnOutOfMemoryError", "-Xms512m", "-Xmx512m", "-Djava.security.egd=file:/dev/./urandom", "org.springframework.boot.loader.launch.JarLauncher"]