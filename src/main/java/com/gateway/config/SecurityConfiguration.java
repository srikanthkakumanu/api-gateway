package com.gateway.config;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The gateway rejects requests without a valid platform token before they reach a service,
 * except for the public paths. Services validate the token again themselves; the gateway adds no
 * identity headers and services would not trust them.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
public class SecurityConfiguration {

	/** No token needed: registering, asking for a password reset, signing in, and services presenting their own secret. */
	static final String[] PUBLIC_POST = { "/api/v1/users/register", "/api/v1/users/password-reset-requests",
			"/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/service-token", "/api/v1/tokens/exchange" };

	static final String[] PUBLIC_GET = { "/api/v1/auth/.well-known/**", "/actuator/health", "/actuator/health/**",
			"/actuator/info", "/v3/api-docs", "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**", "/webjars/**",
			"/docs/*/v3/api-docs" };

	@Bean
	SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
			ReactiveJwtAuthenticationConverterAdapter converter) {
		return http
				.csrf(ServerHttpSecurity.CsrfSpec::disable)
				.cors(Customizer.withDefaults())
				.authorizeExchange(exchange -> exchange
						.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
						.pathMatchers(HttpMethod.POST, PUBLIC_POST).permitAll()
						.pathMatchers(HttpMethod.GET, PUBLIC_GET).permitAll()
						.anyExchange().authenticated())
				.oauth2ResourceServer(resourceServer -> resourceServer
						.jwt(jwt -> jwt.jwtAuthenticationConverter(converter))
						.authenticationEntryPoint((exchange, ex) -> problem(exchange, HttpStatus.UNAUTHORIZED,
								"unauthorized", "A valid access token is required"))
						.accessDeniedHandler((exchange, ex) -> problem(exchange, HttpStatus.FORBIDDEN, "forbidden",
								"You do not have permission to do this")))
				.build();
	}

	/** RFC 9457 problem detail with the same type scheme the services use. */
	private static Mono<Void> problem(ServerWebExchange exchange, HttpStatus status, String code, String detail) {
		String body = """
				{"type":"https://platform.local/problems/%s","title":"%s","status":%d,"detail":"%s","instance":"%s","code":"%s"}"""
				.formatted(code, status.getReasonPhrase(), status.value(), detail,
						URI.create(exchange.getRequest().getPath().value()).toASCIIString(), code);
		var response = exchange.getResponse();
		response.setStatusCode(status);
		response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
		DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
		return response.writeWith(Mono.just(buffer));
	}
}
