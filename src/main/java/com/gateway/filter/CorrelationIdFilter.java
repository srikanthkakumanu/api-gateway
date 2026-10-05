package com.gateway.filter;

import java.util.UUID;
import java.util.regex.Pattern;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Gives every request a correlation ID, passes it to the service and returns it to the caller, so
 * one request can be followed across logs. A well-formed ID supplied by the caller is kept.
 */
@Component
public class CorrelationIdFilter implements GlobalFilter, Ordered {

	public static final String HEADER = "X-Correlation-Id";

	private static final Pattern ACCEPTABLE = Pattern.compile("[A-Za-z0-9._-]{8,64}");

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		String supplied = exchange.getRequest().getHeaders().getFirst(HEADER);
		String correlationId = supplied != null && ACCEPTABLE.matcher(supplied).matches() ? supplied
				: UUID.randomUUID().toString();
		var request = exchange.getRequest().mutate().headers(headers -> headers.set(HEADER, correlationId)).build();
		exchange.getResponse().getHeaders().set(HEADER, correlationId);
		return chain.filter(exchange.mutate().request(request).build());
	}

	@Override
	public int getOrder() {
		return Ordered.HIGHEST_PRECEDENCE;
	}
}
