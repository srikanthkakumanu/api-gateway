# API Gateway

The API Gateway is the platform's reactive HTTP edge. It validates Keycloak bearer tokens, forwards requests to configured services, and removes client-supplied identity headers. It does not own user data, passwords, domain authorization records, or a database.

## Technology And Architecture

Java 27, Spring Boot 4.1.1, Spring Cloud 2025.1.3, Gradle 8.14.3 with an independent Groovy-DSL wrapper, and Spring Cloud Gateway's WebFlux server.

Gateway routing/security/configuration are infrastructure concerns. Domain models belong in downstream bounded contexts, not in this edge service. Downstream services still validate JWTs and enforce their own authorization; gateway authentication is not a substitute for resource-level access control.

## Ports And Dependencies

HTTP: `9211` (`SERVER_PORT` override). Keycloak issuer defaults to `http://localhost:8080/realms/company-platform`. Eureka defaults to `http://localhost:9111/eureka`, with discovery disabled unless `EUREKA_ENABLED=true`.

| Setting | Default / purpose |
| --- | --- |
| `USER_SERVICE_URI` | `lb://user-service` |
| `AUTH_SERVICE_URI` | `lb://auth-service` |
| `KEYCLOAK_ISSUER_URI` | Exact issuer matching token `iss` |
| `EUREKA_ENABLED` | False; enable for `lb://` routes |
| `EUREKA_CLIENT_SERVICE_URL_DEFAULT_ZONE` | Registry location |
| `SERVER_PORT` | 9211 |

There are no Config Client or Vault dependencies in this build. Supply environment properties directly unless those integrations are added.

## Current Routes

| Route | Forwarded target / behavior |
| --- | --- |
| `GET /api/users/ping` | User Service public connectivity |
| `/api/users/**` | User Service; path preserved |
| `/user-service/v3/api-docs`, `/user-service/api-docs`, `/user-service/swagger-ui/**` | User docs; service prefix stripped |
| `/api/roles/**`, `/api/permissions/**` | Auth Service; path preserved |
| `/auth-service/v3/api-docs`, `/auth-service/api-docs`, `/auth-service/swagger-ui/**` | Auth docs; service prefix stripped |

Important: Auth Service's implemented APIs are `/api/v1/roles` and `/api/v1/permissions`. The current gateway predicates do not match them. Use Auth Service directly on 9141 until routes are corrected. Books and video routes are pending; reviews routes are implemented.

## Security And Request Handling

Health and user ping are public; other routes require JWT authentication, including routed API documentation. Bearer authorization is forwarded so downstream services can independently validate the caller.

Default filters remove `Cookie`, `X-User-Id`, `X-Forwarded-User`, and `X-Internal-User`. Never rely on those incoming headers to establish ownership. HTTP connection timeout is 2 seconds and response timeout is 5 seconds.
## Build And Verification

Run commands from this repository's root; do not use another service's Gradle wrapper.

```bash
bash ./gradlew clean test bootJar
```

The application JAR is written to `build/libs/`. Dockerfiles consume that JAR, so build it before building an image. Java 27 is the target toolchain for migrated services. The current Gradle 8.x wrapper may need a supported older JVM to launch Gradle while the configured toolchain compiles with Java 27; do not assume Gradle itself can run on JDK 27.

Container recipes use layered-JAR extraction. The complete Docker image/startup path still needs verification after the Spring Boot upgrade.
## Run Without Discovery

Start Keycloak and the downstream services, then use explicit HTTP targets:

```bash
export EUREKA_ENABLED=false
export USER_SERVICE_URI=http://localhost:9121
export AUTH_SERVICE_URI=http://localhost:9141
export KEYCLOAK_ISSUER_URI=http://localhost:8080/realms/company-platform
bash ./gradlew bootRun
```

```bash
curl http://localhost:9211/api/users/ping
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:9211/api/users
```

To use discovery, start Eureka, ensure downstream instances register, enable `EUREKA_ENABLED`, and use `lb://` target values. The shared Compose configuration still needs discovery enablement alignment.

## Troubleshooting And Remaining Work

- 401: check issuer, expiry, signing keys, and bearer-header forwarding.
- 404 for Auth Service: current versioned-route mismatch described above.
- 503 with `lb://`: check discovery enablement and registered instance IDs.
- Upstream failure: verify target URI is reachable from the gateway's host/container, not only from your browser.
- Add missing business-service routes, versioned auth routes, fine-grained edge policy where appropriate, production observability, and full-stack smoke coverage.

See [platform setup](../micro-services/README.md), [User Service](../user-service/README.md), [Auth Service](../auth-service/README.md), and the [checkpoint](../micro-services/IAM_IMPLEMENTATION_CHECKPOINT.md).

## Reviews Integration

Reviews Service uses PostgreSQL reviewsdb, runtime role theuser, and migration role
reviewsadmin with the requested development password from Vault/config. The API is
/api/v1/reviews on 9171; repeated book/video reviews are supported. Local PostgreSQL
publishes 45432. Gateway REVIEWS_SERVICE_URI defaults to http://localhost:9171 and
shared Compose sets http://reviews-service:9171. Use postgres-init/02-reviews.sql
from micro-services for additive provisioning on existing volumes. The ignored Vault
seed now includes secret/data/db/reviewsdb for dev/qa/prod. Task APIs are retired.
