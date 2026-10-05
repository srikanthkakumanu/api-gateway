# api-gateway

The single entry point of the identity platform. Clients call the gateway; it checks the access token, routes the request to the service that owns the path, and passes the token on. It holds no business logic and no data.

Built on Spring Cloud Gateway (reactive).

## Contents

- [What it does](#what-it-does)
- [Routes](#routes)
- [Public paths](#public-paths)
- [Token validation](#token-validation)
- [Headers](#headers)
- [Configuration](#configuration)
- [Run](#run)
- [Test](#test)
- [Adding a service](#adding-a-service)
- [Build and image](#build-and-image)

## What it does

| Concern | Behaviour |
| --- | --- |
| Routing | By path, to services found through Eureka (`lb://user-service`, `lb://auth-service`) |
| Authentication | Rejects requests without a valid platform access token, except on the public paths |
| Token relay | Forwards the `Authorization` header unchanged; services validate it again themselves |
| Correlation | Adds `X-Correlation-Id` to the request and the response |
| Header hygiene | Drops caller-supplied identity headers |
| CORS | Answers preflights for the configured frontends |
| Discovery documents | Proxies the OIDC discovery document and JWKS, so consumers never need Keycloak's address |
| API docs | One Swagger UI over both services |

It does not authorize: permissions are checked by the services. It adds no identity headers, and the services would not trust them.

## Routes

Defined in `src/main/resources/application.yml`. The first matching route wins, so order matters.

| Order | Path | Goes to |
| --- | --- | --- |
| 1 | `GET /api/v1/auth/.well-known/openid-configuration` | Keycloak's discovery document |
| 2 | `GET /api/v1/auth/.well-known/jwks.json` | Keycloak's JWKS |
| 3 | `/api/v1/users/{id}/roles`, `/groups/**`, `/permissions` | auth-service |
| 4 | `/api/v1/users`, `/api/v1/users/**` | user-service |
| 5 | `/api/v1/auth/**`, `/sessions/**`, `/roles/**`, `/groups/**`, `/permissions/**`, `/authz/**`, `/clients/**`, `/audit/**`, `/tokens/**`, `/token-settings`, `/keys/**`, `/token-claims/**` | auth-service |
| 6 | `/docs/user-service/v3/api-docs`, `/docs/auth-service/v3/api-docs` | Each service's OpenAPI document |

Route 3 must stay above route 4: a user's roles, groups and permissions belong to the access context although the path starts with `/users`. A test checks this for every path family.

Anything else is `404`.

## Public paths

No token needed:

| Method | Paths |
| --- | --- |
| `POST` | `/api/v1/users/register`, `/api/v1/users/password-reset-requests`, `/api/v1/auth/login`, `/api/v1/auth/refresh`, `/api/v1/auth/service-token`, `/api/v1/tokens/exchange` |
| `GET` | `/api/v1/auth/.well-known/**`, `/actuator/health/**`, `/actuator/info`, `/swagger-ui.html`, `/v3/api-docs/**`, `/docs/*/v3/api-docs` |
| `OPTIONS` | everything (CORS preflight) |

A path is public only for the method listed. Everything else answers `401` with an RFC 9457 problem (`code` `unauthorized`) before any service is called.

## Token validation

Done with the shared `platform-security-starter` from `micro-services`, the same code the services use:

1. Signature against the JWKS. Keys are cached; an unknown `kid` causes a refetch, which is what makes key rotation work without a restart.
2. RS256 only. `alg: none` and HMAC-signed tokens are rejected.
3. `iss` equals the configured issuer exactly.
4. `aud` contains `api-gateway`.
5. `exp` and `nbf`, with 30 seconds of clock skew.
6. `typ` is `Bearer`.

Service-to-service calls do not go through the gateway; a service token therefore does not need `api-gateway` in its audience.

## Headers

| Header | Behaviour |
| --- | --- |
| `Authorization` | Relayed to the service unchanged |
| `X-Correlation-Id` | Kept if the caller sent a well-formed one (8 to 64 letters, digits, `.`, `_`, `-`), otherwise generated. Sent to the service and returned to the caller. |
| `X-User-Id`, `X-User-Roles`, `X-Forwarded-User` | Removed from incoming requests |

## Configuration

Split by environment ([ADR 0014](../micro-services/docs/adr/0014-environment-profiles.md)):

| File | Holds |
| --- | --- |
| `application.yml` | Routes, default filters, CORS methods and headers, graceful shutdown, Swagger UI sources |
| `application-dev.yml` | Config Server import (optional), Keycloak address and CORS origins with localhost defaults |
| `application-qa.yml`, `application-prod.yml` | The same, required, with no defaults |

More settings come from the Config Server (`service-configs/application*.yml` and `api-gateway*.yml`). The gateway needs no secrets and does not talk to Vault.

| Variable | Default in `dev` | Meaning |
| --- | --- | --- |
| `SPRING_PROFILES_ACTIVE` | `dev` | `dev`, `qa` or `prod` |
| `SERVER_PORT` | `9211` | HTTP port |
| `CONFIG_SERVER_URL` | `http://localhost:9311` | Config Server |
| `KEYCLOAK_URL` | `http://localhost:8080` | Where the discovery routes are proxied to, and where keys are fetched |
| `KEYCLOAK_PUBLIC_URL` | `http://localhost:8080` | The issuer in tokens; compared exactly |
| `EUREKA_URL` | `http://localhost:9111/eureka/` | Registry |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Frontends allowed to call it |

Route targets can be overridden with `platform.gateway.routes.user-service` and `platform.gateway.routes.auth-service` (the tests point them at stubs).

## Run

This repository must sit next to [`micro-services`](../micro-services/README.md), which holds the version catalog and the shared starter.

**With the whole platform** (the usual way): `cd ../micro-services && make up`. The gateway is then at http://localhost:9211 and Swagger UI at http://localhost:9211/swagger-ui.html.

**From source, against the running platform:** `cd ../micro-services && scripts/run-from-source.sh api-gateway`

**Restart just the gateway** after a change: `cd ../micro-services && scripts/restart.sh --build api-gateway`

The gateway reports healthy a few seconds before it has fetched the registry from Eureka, and answers `503` for routed calls until then. `scripts/start.sh` waits for that; `scripts/status.sh` shows it. On stop it finishes requests in flight (up to 30 seconds).

## Test

```bash
./gradlew build
```

46 tests, none skipped, no Docker needed. They run the real gateway against stub services and a test issuer whose JWKS is fetched over HTTP:

- every path family reaches the right service, including the `/users/{id}/roles` ordering
- public paths need no token; everything else is rejected before reaching a service
- tampered, unsigned, HMAC-signed, unknown-key, expired, not-yet-valid, wrong-issuer, wrong-audience and non-access tokens are rejected
- the token is relayed, the correlation ID is added or kept, spoofed identity headers are dropped
- CORS preflight is answered for allowed origins only

## Adding a service

In `application.yml`, copy a route block and point it at `lb://<service-name>`. Put anything more specific than an existing pattern above it.

```yaml
- id: books-service
  uri: lb://books-service
  predicates:
    - Path=/api/v1/books,/api/v1/books/**
```

The full onboarding flow is in [Integrating a new service](../micro-services/docs/integrating-a-new-service.md).

## Build and image

- Java 27, Gradle 9.8.0 (wrapper), Spring Boot 4.1.1, Spring Cloud 2025.1.3. Versions come from `../micro-services/gradle/libs.versions.toml`.
- `Dockerfile` is multi-stage: build on JDK 27, run on a JRE 27 Alpine image as a non-root user, with a health check on `/actuator/health/readiness`. It needs the platform root as a named build context:

```bash
docker build --build-context platform=../micro-services -t api-gateway .
```
