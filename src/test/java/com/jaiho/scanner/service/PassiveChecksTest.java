package com.jaiho.scanner.service;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import com.jaiho.scanner.domain.Finding;
import com.jaiho.scanner.domain.Severity;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the real {@link PassiveChecks} and {@link HttpProbe} against a small
 * in-process HTTP server, so the checks run over real HTTP rather than mocks.
 */
class PassiveChecksTest {

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private URI startServer(Consumer<HttpExchange> handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", handler::accept);
        server.start();
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    private static void respond(HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private List<Finding> run(URI target) {
        PassiveChecks checks = new PassiveChecks(new HttpProbe(), new ScanProgressStore(), 25);
        return checks.run(1L, target, Set.of(new DiscoveredEndpoint("GET", target.toString())));
    }

    private boolean hasTitle(List<Finding> findings, String fragment) {
        return findings.stream().anyMatch(f -> f.getTitle().contains(fragment));
    }

    @Test
    void flagsMissingHeadersInsecureCookieAndReflectedInput() throws IOException {
        URI target = startServer(exchange -> {
            try {
                String query = exchange.getRequestURI().getQuery();
                exchange.getResponseHeaders().add("Content-Type", "text/html");
                exchange.getResponseHeaders().add("Set-Cookie", "SESSION=abc123; Path=/");
                respond(exchange, "<html><body>" + (query == null ? "" : query) + "</body></html>");
            } catch (IOException ignored) {
            }
        });

        List<Finding> findings = run(target);

        assertTrue(hasTitle(findings, "No Content-Security-Policy header"), "missing CSP");
        assertTrue(hasTitle(findings, "Cookie 'SESSION' missing flags"), "insecure cookie");
        assertTrue(hasTitle(findings, "reflected in HTML response"), "reflected input");
        assertTrue(hasTitle(findings, "cleartext HTTP"), "cleartext transport");
    }

    @Test
    void secureSiteProducesNoHeaderCookieOrReflectionFindings() throws IOException {
        URI target = startServer(exchange -> {
            try {
                exchange.getResponseHeaders().add("Content-Type", "text/html");
                exchange.getResponseHeaders().add("Content-Security-Policy", "default-src 'self'");
                exchange.getResponseHeaders().add("X-Content-Type-Options", "nosniff");
                exchange.getResponseHeaders().add("X-Frame-Options", "DENY");
                exchange.getResponseHeaders().add("Set-Cookie",
                        "SESSION=abc; Path=/; HttpOnly; Secure; SameSite=Lax");
                respond(exchange, "<html><body>static content</body></html>");
            } catch (IOException ignored) {
            }
        });

        List<Finding> findings = run(target);

        assertFalse(hasTitle(findings, "Content-Security-Policy"), "CSP header present");
        assertFalse(hasTitle(findings, "missing flags"), "cookie fully flagged");
        assertFalse(hasTitle(findings, "reflected in HTML response"), "no reflection");
    }

    @Test
    void flagsPubliclyExposedActuatorEnvAsHigh() throws IOException {
        URI target = startServer(exchange -> {
            try {
                if (exchange.getRequestURI().getPath().equals("/actuator/env")) {
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    respond(exchange, "{\"propertySources\": []}");
                } else {
                    exchange.getResponseHeaders().add("Content-Type", "text/html");
                    respond(exchange, "<html><body>static content</body></html>");
                }
            } catch (IOException ignored) {
            }
        });

        List<Finding> findings = run(target);

        assertTrue(findings.stream().anyMatch(f ->
                        f.getTitle().contains("/actuator/env") && f.getSeverity() == Severity.HIGH),
                "actuator/env exposure flagged HIGH");
    }
}
