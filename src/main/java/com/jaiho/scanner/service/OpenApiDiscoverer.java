package com.jaiho.scanner.service;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Discovers endpoints from an OpenAPI document the target exposes (by default at
 * {@code /v3/api-docs}). Unlike the HTML crawler, this picks up JSON APIs and
 * methods HTML forms cannot express, such as PATCH.
 */
@Component
public class OpenApiDiscoverer {

    private static final Logger log = LoggerFactory.getLogger(OpenApiDiscoverer.class);
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final HttpProbe probe;
    private final String docPath;

    public OpenApiDiscoverer(HttpProbe probe,
                             @Value("${scanner.openapi.path:/v3/api-docs}") String docPath) {
        this.probe = probe;
        this.docPath = docPath;
    }

    /** Fetches and parses the target's OpenAPI document, if it has one. */
    public Set<DiscoveredEndpoint> discover(URI target) {
        String base = target.toString();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        String docUrl = base + docPath;
        HttpProbe.Result result = probe.get(docUrl);
        if (result.failed() || result.status() != 200 || result.body() == null
                || !result.body().stripLeading().startsWith("{")) {
            log.debug("No OpenAPI document at {}", docUrl);
            return Set.of();
        }
        Set<DiscoveredEndpoint> endpoints = parsePaths(result.body(), target, ScanPolicy.ALLOWED_METHODS);
        log.info("OpenAPI discovery found {} endpoint(s) at {}", endpoints.size(), docUrl);
        return endpoints;
    }

    /**
     * Parses the {@code paths} of an OpenAPI 3 document into endpoints, keeping only
     * the allowed methods. URLs are built from the target's origin plus each path.
     * Pure and side-effect free, so it can be unit tested without a server.
     */
    static Set<DiscoveredEndpoint> parsePaths(String json, URI target, List<String> allowedMethods) {
        Set<DiscoveredEndpoint> endpoints = new LinkedHashSet<>();
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (Exception e) {
            log.debug("Could not parse OpenAPI document: {}", e.getMessage());
            return endpoints;
        }
        JsonNode paths = root.get("paths");
        if (paths == null || !paths.isObject()) {
            return endpoints;
        }
        String origin = origin(target);
        for (Map.Entry<String, JsonNode> pathEntry : paths.properties()) {
            String path = pathEntry.getKey();
            JsonNode methods = pathEntry.getValue();
            if (methods == null || !methods.isObject()) {
                continue;
            }
            for (Map.Entry<String, JsonNode> methodEntry : methods.properties()) {
                String method = methodEntry.getKey().toUpperCase(Locale.ROOT);
                if (allowedMethods.contains(method)) {
                    endpoints.add(new DiscoveredEndpoint(method, origin + path));
                }
            }
        }
        return endpoints;
    }

    private static String origin(URI target) {
        StringBuilder sb = new StringBuilder();
        sb.append(target.getScheme()).append("://").append(target.getHost());
        if (target.getPort() != -1) {
            sb.append(':').append(target.getPort());
        }
        return sb.toString();
    }
}
