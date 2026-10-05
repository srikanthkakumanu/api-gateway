# api-gateway

The single entry point. It validates the access token, routes to the services through Eureka, relays the token, adds a correlation ID, answers CORS preflights for local frontends, and proxies the OIDC discovery document and JWKS so consumers never need the identity provider's address.

Routes are in `src/main/resources/application.yml`. `/api/v1/users/{id}/roles`, `/groups` and `/permissions` go to auth-service and are listed above the generic `/api/v1/users/**` route to user-service; order matters.

Public without a token: `POST` register, password-reset request, login, refresh, service-token and token exchange; `GET` the discovery documents, health and the API docs. Everything else needs a valid token, and the services validate it again themselves.

Swagger UI for both services: `/swagger-ui.html`.

Part of the identity platform; the platform root is [`../micro-services`](../micro-services/README.md). This repository must sit next to it, because the version catalog and the shared security starter are read from there.

## Run

The usual way is the whole stack: `make up` in `../micro-services`. The service then listens on port 9211.

To run it from source against that stack, stop its container and start it:

```bash
cd ../micro-services && docker compose stop api-gateway && cd ../api-gateway
./gradlew bootRun
```

## Test

```bash
./gradlew build
```

Needs Docker. The build tests routing for every path family, public versus protected paths, rejection of tampered, expired, unsigned, HMAC-signed and wrong-audience tokens, token relay, correlation IDs and CORS, with stub services and a test issuer.

## Configuration

Configuration is split by environment: `application.yml` holds what is common, `application-dev.yml`, `-qa.yml` and `-prod.yml` the rest. Further non-secret settings come from the Config Server (`service-configs/api-gateway*.yml` and `application*.yml`, split the same way). The gateway needs no secrets.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CONFIG_SERVER_URL` | `http://localhost:9311` | Config Server |
| `SPRING_PROFILES_ACTIVE` | `dev` | `dev`, `qa` or `prod`. In `qa` and `prod` the addresses below have no default and must be set. |
| `SERVER_PORT` | `9211` | HTTP port |

`platform.gateway.cors.allowed-origins` lists the frontends allowed to call it (`http://localhost:3000` and `:5173` by default).

## Adding a service

Copy a route block, point it at `lb://<service-name>`, and put anything more specific than an existing pattern above it. See [Integrating a new service](../micro-services/docs/integrating-a-new-service.md).
