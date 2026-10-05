package com.gateway;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;

/** A minimal issuer for tests: serves a JWKS over HTTP and mints tokens, including broken ones. */
final class TestIdentityProvider implements AutoCloseable {

	static final String ISSUER = "http://localhost:8080/realms/platform";
	static final String AUDIENCE = "api-gateway";

	private final HttpServer server;
	private final AtomicInteger jwksRequests = new AtomicInteger();
	private volatile RSAKey signingKey;
	private volatile JWKSet published;

	TestIdentityProvider() {
		this.signingKey = newKey();
		this.published = new JWKSet(signingKey.toPublicJWK());
		try {
			this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
		}
		catch (IOException ex) {
			throw new IllegalStateException(ex);
		}
		server.createContext("/certs", exchange -> {
			jwksRequests.incrementAndGet();
			byte[] body = published.toString().getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(200, body.length);
			try (var out = exchange.getResponseBody()) {
				out.write(body);
			}
		});
		server.start();
	}

	String jwkSetUri() {
		return "http://localhost:" + server.getAddress().getPort() + "/certs";
	}

	int jwksRequests() {
		return jwksRequests.get();
	}

	/** Keeps the old key published as passive and signs new tokens with a fresh one. */
	void rotateSigningKey() {
		var previous = signingKey;
		this.signingKey = newKey();
		this.published = new JWKSet(List.of(signingKey.toPublicJWK(), previous.toPublicJWK()));
	}

	/** Stops publishing every key except the current one. */
	void retirePassiveKeys() {
		this.published = new JWKSet(signingKey.toPublicJWK());
	}

	String currentKeyId() {
		return signingKey.getKeyID();
	}

	String validToken() {
		return token(claims -> {
		});
	}

	String token(Consumer<JWTClaimsSet.Builder> customizer) {
		return sign(claims(customizer), signingKey);
	}

	String tokenSignedByUnknownKey() {
		return sign(claims(claims -> {
		}), newKey());
	}

	String unsignedToken() {
		return new PlainJWT(claims(claims -> {
		})).serialize();
	}

	/** Algorithm confusion: an HS256 token keyed with the published RSA public key. */
	String hmacSignedToken() {
		try {
			var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(signingKey.getKeyID()).build(),
					claims(claims -> {
					}));
			jwt.sign(new MACSigner(signingKey.toRSAPublicKey().getEncoded()));
			return jwt.serialize();
		}
		catch (JOSEException ex) {
			throw new IllegalStateException(ex);
		}
	}

	static String tamper(String token) {
		String[] parts = token.split("\\.");
		char last = parts[2].charAt(parts[2].length() / 2);
		char replacement = last == 'A' ? 'B' : 'A';
		int middle = parts[2].length() / 2;
		return parts[0] + "." + parts[1] + "." + parts[2].substring(0, middle) + replacement
				+ parts[2].substring(middle + 1);
	}

	private static JWTClaimsSet claims(Consumer<JWTClaimsSet.Builder> customizer) {
		var now = Instant.now();
		var builder = new JWTClaimsSet.Builder()
				.issuer(ISSUER)
				.subject("7c1f")
				.audience(List.of(AUDIENCE, "account"))
				.issueTime(Date.from(now))
				.expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
				.jwtID(UUID.randomUUID().toString())
				.claim("typ", "Bearer")
				.claim("preferred_username", "alice")
				.claim("permissions", List.of("users:read"));
		customizer.accept(builder);
		return builder.build();
	}

	private static String sign(JWTClaimsSet claims, RSAKey key) {
		try {
			var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
			jwt.sign(new RSASSASigner(key));
			return jwt.serialize();
		}
		catch (JOSEException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static RSAKey newKey() {
		try {
			return new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
		}
		catch (JOSEException ex) {
			throw new IllegalStateException(ex);
		}
	}

	@Override
	public void close() {
		server.stop(0);
	}
}
