package com.jaiho.scanner.service;

import java.net.URI;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenApiDiscovererTest {

    private static final URI TARGET = URI.create("http://localhost:8080");

    @Test
    void extractsAllowedMethodsAndSkipsDelete() {
        String doc = """
                {
                  "openapi": "3.0.1",
                  "paths": {
                    "/api/users": { "get": {}, "post": {} },
                    "/api/users/{id}": { "get": {}, "patch": {}, "delete": {} }
                  }
                }
                """;

        Set<DiscoveredEndpoint> endpoints =
                OpenApiDiscoverer.parsePaths(doc, TARGET, ScanPolicy.ALLOWED_METHODS);

        assertEquals(4, endpoints.size());
        assertTrue(endpoints.contains(new DiscoveredEndpoint("GET", "http://localhost:8080/api/users")));
        assertTrue(endpoints.contains(new DiscoveredEndpoint("POST", "http://localhost:8080/api/users")));
        assertTrue(endpoints.contains(new DiscoveredEndpoint("GET", "http://localhost:8080/api/users/{id}")));
        assertTrue(endpoints.contains(new DiscoveredEndpoint("PATCH", "http://localhost:8080/api/users/{id}")));
        assertFalse(endpoints.stream().anyMatch(e -> e.method().equals("DELETE")));
    }

    @Test
    void handlesMissingOrInvalidPaths() {
        assertTrue(OpenApiDiscoverer.parsePaths("{}", TARGET, ScanPolicy.ALLOWED_METHODS).isEmpty());
        assertTrue(OpenApiDiscoverer.parsePaths("not json", TARGET, ScanPolicy.ALLOWED_METHODS).isEmpty());
    }

    @Test
    void buildsUrlsFromTargetOriginIgnoringServersAndKeepingPort() {
        String doc = """
                {
                  "servers": [ { "url": "https://prod.example.com/api" } ],
                  "paths": { "/orders/{id}": { "get": {} } }
                }
                """;

        Set<DiscoveredEndpoint> endpoints =
                OpenApiDiscoverer.parsePaths(doc, TARGET, ScanPolicy.ALLOWED_METHODS);

        assertEquals(1, endpoints.size());
        assertTrue(endpoints.contains(
                new DiscoveredEndpoint("GET", "http://localhost:8080/orders/{id}")));
    }
}
