package com.aegisprobe.scanner.service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Minimal, read-only HTTP client for probing a target. Redirects are not
 * followed, so the immediate response headers (including Set-Cookie) are visible,
 * and error statuses are returned rather than thrown.
 */
@Component
public class HttpProbe {

    private static final Logger log = LoggerFactory.getLogger(HttpProbe.class);

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /** Result of a probe. {@code null} {@link #body} means the request failed. */
    public record Result(int status, HttpResponse<String> response, String body) {

        public List<String> header(String name) {
            if (response == null) {
                return List.of();
            }
            return response.headers().allValues(name);
        }

        public Optional<String> firstHeader(String name) {
            return header(name).stream().findFirst();
        }

        public boolean failed() {
            return response == null;
        }
    }

    public Result get(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .header("User-Agent", "AegisProbe-Scanner")
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return new Result(response.statusCode(), response, response.body());
        } catch (Exception e) {
            log.debug("Probe failed for {}: {}", url, e.getMessage());
            return new Result(0, null, null);
        }
    }
}
