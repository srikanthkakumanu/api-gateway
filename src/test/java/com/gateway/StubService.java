package com.gateway;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import com.sun.net.httpserver.HttpServer;

/** Stands in for a downstream service: answers every request with its own name and what it received. */
final class StubService implements AutoCloseable {

	private final HttpServer server;

	StubService(String name) {
		try {
			server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
		}
		catch (IOException ex) {
			throw new IllegalStateException(ex);
		}
		server.createContext("/", exchange -> {
			var headers = exchange.getRequestHeaders();
			String body = """
					{"service":"%s","method":"%s","path":"%s","authorization":"%s","correlationId":"%s","userId":"%s"}"""
					.formatted(name, exchange.getRequestMethod(), exchange.getRequestURI().getPath(),
							value(headers.getFirst("Authorization")), value(headers.getFirst("X-Correlation-Id")),
							value(headers.getFirst("X-User-Id")));
			byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(200, bytes.length);
			try (var out = exchange.getResponseBody()) {
				out.write(bytes);
			}
		});
		server.start();
	}

	String url() {
		return "http://localhost:" + server.getAddress().getPort();
	}

	private static String value(String header) {
		return header == null ? "" : header;
	}

	@Override
	public void close() {
		server.stop(0);
	}
}
