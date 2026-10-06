package com.gateway;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Routing, public and protected paths, and token rejection, with stub services downstream and
 * tokens signed by a test issuer whose JWKS the gateway fetches over HTTP.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class GatewayTest {

	private static final String USER = "7c1f0e9a-3b5d-4f6a-8b7c-9d0e1f2a3b4c";

	private static final TestIdentityProvider idp = new TestIdentityProvider();
	private static final StubService userService = new StubService("user-service");
	private static final StubService authService = new StubService("auth-service");
	private static final StubService booksService = new StubService("books-service");
	private static final StubService videoService = new StubService("video-service");
	private static final StubService keycloak = new StubService("keycloak");

	@Value("${local.server.port}")
	private int port;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("platform.gateway.routes.user-service", userService::url);
		registry.add("platform.gateway.routes.auth-service", authService::url);
		registry.add("platform.gateway.routes.books-service", booksService::url);
		registry.add("platform.gateway.routes.video-service", videoService::url);
		registry.add("platform.keycloak.server-url", keycloak::url);
		registry.add("platform.security.jwt.issuer-uri", () -> TestIdentityProvider.ISSUER);
		registry.add("platform.security.jwt.jwk-set-uri", idp::jwkSetUri);
		registry.add("platform.security.jwt.jwk-set-refresh-min-interval", () -> "0s");
	}

	@AfterAll
	static void stop() {
		idp.close();
		userService.close();
		authService.close();
		booksService.close();
		videoService.close();
		keycloak.close();
	}

	// --- routing

	@ParameterizedTest
	@CsvSource({
			"/api/v1/users, user-service",
			"/api/v1/users/me, user-service",
			"/api/v1/users/" + USER + ", user-service",
			"/api/v1/users/" + USER + "/profile, user-service",
			"/api/v1/users/" + USER + "/credentials, user-service",
			"/api/v1/users/" + USER + "/actions/required, user-service",
			"/api/v1/users/" + USER + "/roles, auth-service",
			"/api/v1/users/" + USER + "/groups, auth-service",
			"/api/v1/users/" + USER + "/groups/22222222-2222-3333-4444-555555555555, auth-service",
			"/api/v1/users/" + USER + "/permissions, auth-service",
			"/api/v1/auth/me, auth-service",
			"/api/v1/auth/me/sessions, auth-service",
			"/api/v1/sessions/users/" + USER + ", auth-service",
			"/api/v1/roles, auth-service",
			"/api/v1/roles/REVIEWER/composites, auth-service",
			"/api/v1/groups, auth-service",
			"/api/v1/permissions, auth-service",
			"/api/v1/authz/decisions, auth-service",
			"/api/v1/clients/sample-service, auth-service",
			"/api/v1/audit/login-events, auth-service",
			"/api/v1/tokens/inspect, auth-service",
			"/api/v1/token-settings, auth-service",
			"/api/v1/keys, auth-service",
			"/api/v1/token-claims, auth-service",
			"/api/v1/books, books-service",
			"/api/v1/books/22222222-2222-3333-4444-555555555555, books-service",
			"/api/v1/books/22222222-2222-3333-4444-555555555555/owner, books-service",
			"/api/v1/authors, books-service",
			"/api/v1/authors/22222222-2222-3333-4444-555555555555, books-service",
			"/api/v1/videos, video-service",
			"/api/v1/videos/22222222-2222-3333-4444-555555555555, video-service",
			"/api/v1/videos/22222222-2222-3333-4444-555555555555/complete, video-service",
			"/api/v1/videos/22222222-2222-3333-4444-555555555555/owner, video-service" })
	void routesEachPathToTheServiceThatOwnsIt(String path, String service) {
		client().get().uri(path).headers(headers -> headers.setBearerAuth(idp.validToken())).exchange()
				.expectStatus().isOk()
				.expectBody().jsonPath("$.service").isEqualTo(service).jsonPath("$.path").isEqualTo(path);
	}

	@Test
	void aUsersRolesAndGroupsGoToAuthServiceWhileTheUserItselfGoesToUserService() {
		String token = idp.validToken();

		client().post().uri("/api/v1/users/" + USER + "/roles").headers(headers -> headers.setBearerAuth(token))
				.contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange()
				.expectBody().jsonPath("$.service").isEqualTo("auth-service").jsonPath("$.method").isEqualTo("POST");
		client().put().uri("/api/v1/users/" + USER).headers(headers -> headers.setBearerAuth(token))
				.contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange()
				.expectBody().jsonPath("$.service").isEqualTo("user-service").jsonPath("$.method").isEqualTo("PUT");
		// "roles" as a user ID segment deeper down still belongs to user-service.
		client().get().uri("/api/v1/users/" + USER + "/profile/roles").headers(headers -> headers.setBearerAuth(token))
				.exchange().expectBody().jsonPath("$.service").isEqualTo("user-service");
	}

	@Test
	void unknownPathsAreNotRouted() {
		String token = idp.validToken();

		client().get().uri("/api/v1/reviews").headers(headers -> headers.setBearerAuth(token)).exchange()
				.expectStatus().isNotFound();
		client().get().uri("/api/videos").headers(headers -> headers.setBearerAuth(token)).exchange()
				.expectStatus().isNotFound();
		// The old, unversioned catalog paths are gone.
		client().get().uri("/api/books").headers(headers -> headers.setBearerAuth(token)).exchange()
				.expectStatus().isNotFound();
		client().get().uri("/api/v1/bookshelves").headers(headers -> headers.setBearerAuth(token)).exchange()
				.expectStatus().isNotFound();
	}

	// --- public and protected paths

	@ParameterizedTest
	@ValueSource(strings = { "/api/v1/users/register", "/api/v1/users/password-reset-requests", "/api/v1/auth/login",
			"/api/v1/auth/refresh", "/api/v1/auth/service-token", "/api/v1/tokens/exchange" })
	void publicEndpointsNeedNoToken(String path) {
		client().post().uri(path).contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.path").isEqualTo(path);
	}

	@ParameterizedTest
	@ValueSource(strings = { "/api/v1/users", "/api/v1/users/me", "/api/v1/auth/me", "/api/v1/roles",
			"/api/v1/users/" + USER + "/roles", "/api/v1/keys", "/api/v1/audit/login-events", "/api/v1/books",
			"/api/v1/books/22222222-2222-3333-4444-555555555555", "/api/v1/authors", "/api/v1/videos",
			"/api/v1/videos/22222222-2222-3333-4444-555555555555" })
	void everythingElseIsRejectedWithoutATokenBeforeReachingAService(String path) {
		client().get().uri(path).exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
				.expectBody().jsonPath("$.code").isEqualTo("unauthorized")
				.jsonPath("$.type").isEqualTo("https://platform.local/problems/unauthorized")
				.jsonPath("$.status").isEqualTo(401).jsonPath("$.service").doesNotExist();
	}

	@Test
	void publicPathsArePublicOnlyForTheirMethod() {
		client().get().uri("/api/v1/auth/login").exchange().expectStatus().isUnauthorized();
		client().delete().uri("/api/v1/users/register").exchange().expectStatus().isUnauthorized();
	}

	@Test
	void healthAndDiscoveryDocumentsArePublic() {
		client().get().uri("/actuator/health").exchange().expectStatus().isOk();
		client().get().uri("/api/v1/auth/.well-known/openid-configuration").exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.service").isEqualTo("keycloak")
				.jsonPath("$.path").isEqualTo("/realms/platform/.well-known/openid-configuration");
		client().get().uri("/api/v1/auth/.well-known/jwks.json").exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.path").isEqualTo("/realms/platform/protocol/openid-connect/certs");
		client().get().uri("/docs/user-service/v3/api-docs").exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.service").isEqualTo("user-service").jsonPath("$.path").isEqualTo("/v3/api-docs");
		client().get().uri("/docs/auth-service/v3/api-docs").exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.service").isEqualTo("auth-service");
	}

	// --- token validation

	@Test
	void rejectsTamperedUnsignedSymmetricAndUnknownKeyTokens() {
		assertRejected(TestIdentityProvider.tamper(idp.validToken()));
		assertRejected(idp.unsignedToken());
		assertRejected(idp.hmacSignedToken());
		assertRejected(idp.tokenSignedByUnknownKey());
		assertRejected("not.a.token");
	}

	@Test
	void rejectsExpiredNotYetValidWrongIssuerWrongAudienceAndNonAccessTokens() {
		Date issued = Date.from(Instant.now().minus(Duration.ofMinutes(10)));
		Date expired = Date.from(Instant.now().minus(Duration.ofMinutes(2)));
		Date future = Date.from(Instant.now().plus(Duration.ofMinutes(2)));

		assertRejected(idp.token(claims -> claims.issueTime(issued).expirationTime(expired)));
		assertRejected(idp.token(claims -> claims.notBeforeTime(future)));
		assertRejected(idp.token(claims -> claims.issuer("http://keycloak:8080/realms/platform")));
		assertRejected(idp.token(claims -> claims.audience(List.of("user-service", "auth-service"))));
		assertRejected(idp.token(claims -> claims.claim("typ", "Refresh")));
	}

	// --- what reaches the service

	@Test
	void relaysTheTokenAddsACorrelationIdAndDropsSpoofedIdentityHeaders() {
		String token = idp.validToken();

		var result = client().get().uri("/api/v1/users/me").headers(headers -> {
			headers.setBearerAuth(token);
			headers.set("X-User-Id", "someone-else");
		}).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.authorization").isEqualTo("Bearer " + token)
				.jsonPath("$.userId").isEqualTo("")
				.jsonPath("$.correlationId").value(id -> assertThat((String) id).hasSize(36))
				.returnResult();

		assertThat(result.getResponseHeaders().getFirst("X-Correlation-Id")).hasSize(36);
	}

	@Test
	void keepsAWellFormedCorrelationIdAndReplacesAMalformedOne() {
		client().get().uri("/api/v1/users/me").headers(headers -> {
			headers.setBearerAuth(idp.validToken());
			headers.set("X-Correlation-Id", "trace-1234-abcd");
		}).exchange().expectHeader().valueEquals("X-Correlation-Id", "trace-1234-abcd")
				.expectBody().jsonPath("$.correlationId").isEqualTo("trace-1234-abcd");

		client().get().uri("/api/v1/users/me").headers(headers -> {
			headers.setBearerAuth(idp.validToken());
			headers.set("X-Correlation-Id", "bad id with spaces");
		}).exchange().expectBody().jsonPath("$.correlationId").value(id -> assertThat((String) id).hasSize(36));
	}

	@Test
	void answersCorsPreflightForLocalFrontendsOnly() {
		client().options().uri("/api/v1/users/me").header(HttpHeaders.ORIGIN, "http://localhost:3000")
				.header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
				.header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Authorization").exchange()
				.expectStatus().isOk()
				.expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:3000");
		client().options().uri("/api/v1/users/me").header(HttpHeaders.ORIGIN, "http://evil.example")
				.header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET").exchange()
				.expectStatus().isForbidden();
	}

	private void assertRejected(String token) {
		client().get().uri("/api/v1/users/me").headers(headers -> headers.setBearerAuth(token)).exchange()
				.expectStatus().isUnauthorized()
				.expectBody().jsonPath("$.code").isEqualTo("unauthorized").jsonPath("$.service").doesNotExist();
	}

	private WebTestClient client() {
		return WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
	}
}
