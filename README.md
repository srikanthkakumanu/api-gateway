# API Gateway

`api-gateway` is the platform's reactive HTTP edge service. It accepts client traffic on port `9211`, validates Keycloak-issued bearer tokens, removes untrusted client identity headers, and forwards requests to downstream microservices through Spring Cloud Gateway.

The gateway does not own business data, user credentials, roles, permissions, or persistence. It is an edge adapter only: downstream services must still validate tokens, enforce authorization rules, and own their domain workflows.

## Service Responsibilities

- Expose one entry point for platform HTTP APIs.
- Validate JWT access tokens against the configured Keycloak realm issuer.
- Relay the original `Authorization: Bearer ...` header to downstream services.
- Route requests to User Service, Auth Service, and Reviews Service.
- Strip request headers that clients must not be allowed to supply as identity.
- Provide actuator endpoints for health, gateway route inspection, metrics, Prometheus scraping, loggers, and thread dumps.

## Technology Stack

| Area | Choice |
| --- | --- |
| Runtime | Java 27 toolchain |
| Framework | Spring Boot 4.1.1 |
| Gateway | Spring Cloud Gateway Server WebFlux, Spring Cloud 2025.1.3 |
| Security | Spring Security reactive OAuth2 resource server |
| Discovery | Netflix Eureka client, disabled by default |
| Build | Gradle 8.14.3 Groovy DSL wrapper |
| Container | Multi-stage layered Spring Boot image on `eclipse-temurin:27-jre-alpine` |

The gateway uses the Spring Cloud Gateway 5 WebFlux namespace:

```yaml
spring.cloud.gateway.server.webflux
```

Do not move this configuration back to the older Boot 3 style `spring.cloud.gateway.routes` namespace; it will not bind to the selected Gateway 5 WebFlux runtime.

## Runtime Shape

```text
Client
  |
  | HTTP :9211
  v
api-gateway
  |-- validates JWT issuer/signature through Keycloak metadata
  |-- removes Cookie, X-User-Id, X-Forwarded-User, X-Internal-User
  |-- applies route predicates and path rewrites
  |
  +--> user-service
  +--> auth-service
  +--> reviews-service
```

Default profile selection is `dev` through `SPRING_ACTIVE_PROFILE`. The base configuration also enables virtual threads, although the selected gateway runtime is reactive WebFlux.

## Ports And Dependencies

| Dependency | Default | Notes |
| --- | --- | --- |
| Gateway HTTP port | `9211` | Override with `SERVER_PORT`. |
| Keycloak issuer | `http://localhost:8080/realms/company-platform` | Must exactly match the JWT `iss` claim. In Compose this is `http://keycloak:8080/realms/company-platform`. |
| Eureka registry | `http://localhost:9111/eureka` | Client is present but disabled unless `EUREKA_ENABLED=true`. |
| User Service target | `lb://user-service` | Requires Eureka unless overridden with an HTTP URL. |
| Auth Service target | `lb://auth-service` | Requires Eureka unless overridden with an HTTP URL. |
| Reviews Service target | `http://localhost:9171` | Compose overrides to `http://reviews-service:9171`. |

There is no database, Flyway, Cloud Config client, or Vault client in this project. Some shared Compose dependencies start Vault/Postgres before the gateway for platform ordering, but this gateway process does not connect to either one.

## Route Catalog

Routes are configured in [application.yaml](src/main/resources/application.yaml).

| Route ID | External path predicate | Target | Filters | Authentication |
| --- | --- | --- | --- | --- |
| `reviews-service-api` | `/api/v1/reviews`, `/api/v1/reviews/**` | `${REVIEWS_SERVICE_URI:http://localhost:9171}` | Global header removal | Required |
| `user-service-health` | `GET /api/users/ping` | `${USER_SERVICE_URI:lb://user-service}` | Global header removal | Public |
| `user-service-api` | `/api/users/**` | `${USER_SERVICE_URI:lb://user-service}` | `PreserveHostHeader` plus global header removal | Required |
| `user-service-openapi` | `/user-service/v3/api-docs`, `/user-service/api-docs`, `/user-service/swagger-ui/**` | `${USER_SERVICE_URI:lb://user-service}` | Rewrites `/user-service/{segment}` to `/{segment}` | Required |
| `auth-service-api` | `/api/roles/**`, `/api/permissions/**` | `${AUTH_SERVICE_URI:lb://auth-service}` | `PreserveHostHeader` plus global header removal | Required |
| `auth-service-openapi` | `/auth-service/v3/api-docs`, `/auth-service/api-docs`, `/auth-service/swagger-ui/**` | `${AUTH_SERVICE_URI:lb://auth-service}` | Rewrites `/auth-service/{segment}` to `/{segment}` | Required |

Current route caveat: Auth Service's implemented versioned APIs are documented as `/api/v1/roles` and `/api/v1/permissions`, while the gateway predicates currently match `/api/roles/**` and `/api/permissions/**`. Use Auth Service directly or add matching versioned predicates before relying on the gateway for those endpoints.

Books and video service routes are not configured in this repository yet.

## Security Model

Security is configured in [SecurityConfig.java](src/main/java/api/gateway/config/SecurityConfig.java).

- CSRF is disabled because this is a stateless API gateway.
- `/actuator/health` is public for liveness checks.
- `GET /api/users/ping` is public for User Service connectivity checks.
- Swagger/OpenAPI routes and all other exchanges require authentication.
- JWTs are validated by Spring Security's reactive OAuth2 resource server using the configured issuer metadata and JWKS.
- Realm roles from the Keycloak `realm_access.roles` claim are converted to Spring authorities prefixed with `ROLE_`.
- Scope authorities from the token are preserved through `JwtGrantedAuthoritiesConverter`.

The gateway authenticates the caller, but it is not the final authorization boundary. Downstream services should keep their own method or route authorization because gateway routes can be bypassed in local and internal deployments.

## Header And Timeout Policy

The following request headers are stripped globally before forwarding:

| Header | Reason |
| --- | --- |
| `Cookie` | Prevent browser/session state from leaking to stateless services. |
| `X-User-Id` | Prevent callers from spoofing user identity. |
| `X-Forwarded-User` | Prevent callers from spoofing forwarded identity. |
| `X-Internal-User` | Prevent callers from setting an internal-only identity header. |

The gateway preserves bearer tokens so resource services can independently validate the caller.

HTTP client defaults:

| Setting | Value |
| --- | --- |
| Connect timeout | `2000` milliseconds |
| Response timeout | `5s` |

## Configuration Reference

| Environment variable | Default | Description |
| --- | --- | --- |
| `SPRING_ACTIVE_PROFILE` | `dev` | Active Spring profile. The QA profile requires an explicit Keycloak issuer and enables Eureka by default. |
| `SPRING_APP_NAME` | `api-gateway` | Spring application name. |
| `SERVER_PORT` | `9211` | HTTP listener port. |
| `KEYCLOAK_ISSUER_URI` | `http://localhost:8080/realms/company-platform` | OIDC issuer used for JWT validation. |
| `EUREKA_ENABLED` | `false` | Enables Eureka registration and `lb://` resolution. QA defaults this to `true`. |
| `EUREKA_CLIENT_SERVICE_URL_DEFAULT_ZONE` | `http://localhost:9111/eureka` | Eureka server URL. |
| `USER_SERVICE_URI` | `lb://user-service` | Route target for user endpoints. Use an HTTP URL when discovery is off. |
| `AUTH_SERVICE_URI` | `lb://auth-service` | Route target for auth endpoints. Use an HTTP URL when discovery is off. |
| `REVIEWS_SERVICE_URI` | `http://localhost:9171` | Route target for reviews endpoints. |
| `ROOT_LOG_LEVEL` | `info` | Root logging level. |
| `SPRING_SECURITY_LOG_LEVEL` | `info`, `debug` in `dev` | Security logging level. |
| `SPRING_CLOUD_GATEWAY_LOG_LEVEL` | `info` | Gateway logging level. |
| `LOG_PATTERN_CONSOLE` | Custom colorized pattern | Console log pattern override. |

## Local Development

Run commands from this repository root:

```bash
cd /Users/skakumanu/practice/api-gateway
```

Build and test:

```bash
bash ./gradlew clean test bootJar
```

Run without Eureka by pointing `lb://` routes at concrete service URLs:

```bash
export EUREKA_ENABLED=false
export USER_SERVICE_URI=http://localhost:9121
export AUTH_SERVICE_URI=http://localhost:9141
export REVIEWS_SERVICE_URI=http://localhost:9171
export KEYCLOAK_ISSUER_URI=http://localhost:8080/realms/company-platform
bash ./gradlew bootRun
```

Smoke checks:

```bash
curl http://localhost:9211/actuator/health
curl http://localhost:9211/api/users/ping
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:9211/api/v1/reviews
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:9211/user-service/v3/api-docs
```

To use Eureka locally, start `eureka-discovery-service`, ensure downstream services register under `user-service` and `auth-service`, keep the `lb://` route targets, and set:

```bash
export EUREKA_ENABLED=true
export EUREKA_CLIENT_SERVICE_URL_DEFAULT_ZONE=http://localhost:9111/eureka
```

## Docker And Compose

Build the application JAR first because the Dockerfile copies `build/libs/api-gateway-1.0.jar`:

```bash
bash ./gradlew clean bootJar
docker build -t api-gateway:latest .
```

The Dockerfile extracts Spring Boot layers in a builder stage, then runs the service as a non-root `appuser` in the final image. The runtime command sets a fixed `512m` heap and starts `org.springframework.boot.loader.launch.JarLauncher`.

The shared platform Compose file is [micro-services/compose.yml](../micro-services/compose.yml). Its `api-gateway` service publishes `9211:9211`, points Keycloak to `http://keycloak:8080/realms/company-platform`, and overrides Reviews Service to `http://reviews-service:9171`.

Compose currently does not set `USER_SERVICE_URI`, `AUTH_SERVICE_URI`, or `EUREKA_ENABLED` for the gateway service. With the repository defaults, user and auth routes depend on Eureka-backed `lb://` resolution. Align Compose by either enabling Eureka for the gateway or setting explicit HTTP service URLs.

## Actuator Operations

Exposed actuator endpoints:

| Endpoint | Purpose |
| --- | --- |
| `/actuator/health` | Public health check. |
| `/actuator/info` | Build, git, Java, OS, and app info when available. |
| `/actuator/gateway` | Gateway route and filter diagnostics. |
| `/actuator/metrics` | Micrometer metrics. |
| `/actuator/prometheus` | Prometheus scrape endpoint. |
| `/actuator/loggers` | Runtime logger inspection and changes. |
| `/actuator/threaddump` | Thread dump diagnostics. |

Health details are currently set to `always`, which is useful locally but should be reviewed before exposing management endpoints outside trusted environments.

## Testing Notes

The current test class only starts the Spring context scaffold and has its `contextLoads` method commented out. Useful next tests for this gateway would cover:

- Security rules for public health and ping routes versus protected routes.
- JWT role conversion from `realm_access.roles`.
- Route predicates for users, auth, reviews, and OpenAPI paths.
- Header removal for spoofable identity headers.
- Rewrite behavior for `/user-service/...` and `/auth-service/...` documentation routes.
- Failure behavior for unavailable upstreams and `lb://` discovery misses.

Use a controlled upstream HTTP server for route/filter tests instead of mocking gateway internals.

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| `401 Unauthorized` | Confirm the request has a bearer token, token is not expired, `KEYCLOAK_ISSUER_URI` exactly matches `iss`, and the gateway can reach Keycloak JWKS metadata. |
| `403 Forbidden` | Authentication succeeded, but downstream authorization may have rejected the caller. Check downstream logs and token roles/scopes. |
| `404 Not Found` on auth routes | Check the known `/api` versus `/api/v1` route mismatch. |
| `503 Service Unavailable` with `lb://` routes | Confirm `EUREKA_ENABLED=true`, Eureka URL is reachable, and the target service is registered with the expected application name. |
| Connection timeout | Verify the target service URL from the gateway process or container network, not only from the host browser. |
| OpenAPI route fails | Confirm the prefixed route is used at the gateway and the rewrite target exists in the downstream service. |

## Known Gaps

- Add versioned Auth Service predicates for `/api/v1/roles/**` and `/api/v1/permissions/**`.
- Add Books Service and Video Service routes when those APIs are ready to be exposed through the gateway.
- Add route/filter/security tests.
- Decide whether Compose should use explicit HTTP URLs or Eureka for all gateway routes.
- Review management endpoint exposure and `show-details: always` before non-local deployment.
- Add rate limiting, request size limits, CORS policy, and route-level timeout overrides if public traffic requires them.
- Add production observability conventions for route ID, status, latency, and upstream failure tagging.

## Related Repositories

- [Platform orchestration](../micro-services/README.md)
- [User Service](../user-service/README.md)
- [Auth Service](../auth-service/README.md)
- [Reviews Service](../reviews-service/README.md)
- [Eureka Discovery](../eureka-discovery/README.md)
- [IAM implementation checkpoint](../micro-services/IAM_IMPLEMENTATION_CHECKPOINT.md)

## Maintainer Checklist

When changing gateway behavior, update this README and the affected downstream service README together.

| Change type | Files to inspect |
| --- | --- |
| New route | `src/main/resources/application.yaml`, downstream controller paths, `micro-services/compose.yml` target URLs |
| Auth behavior | `SecurityConfig.java`, downstream resource-server rules, Keycloak realm roles |
| Discovery behavior | `EUREKA_ENABLED`, `EUREKA_CLIENT_SERVICE_URL_DEFAULT_ZONE`, downstream `spring.application.name` |
| Header trust | Gateway default filters and downstream current-actor extraction |
| Timeout behavior | `spring.cloud.gateway.server.webflux.httpclient` and downstream client/server limits |

Quick route diagnostics while the service is running:

```bash
curl http://localhost:9211/actuator/gateway/routes
curl http://localhost:9211/actuator/health
curl http://localhost:9211/api/users/ping
```

Protected route checks require a token whose `iss` exactly matches `KEYCLOAK_ISSUER_URI`:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:9211/api/v1/reviews
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:9211/user-service/v3/api-docs
```
