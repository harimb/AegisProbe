package com.jaiho.scanner.service;

import com.jaiho.scanner.domain.Finding;
import com.jaiho.scanner.domain.Severity;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Runs safe, mostly passive checks aligned with the OWASP Top 10 and turns the
 * results into {@link Finding}s. Nothing here is destructive: the checks read
 * response headers and bodies, and the only crafted request adds a harmless
 * random marker to look for reflected input.
 *
 * <p>The per-endpoint checks (cookies, reflected input) run on at most
 * {@code scanner.sample-endpoints} URLs, so a large crawl does not re-run the same
 * test against hundreds of similar pages. Findings are deduplicated by type later.
 */
@Component
public class PassiveChecks {

    private final HttpProbe probe;
    private final ScanProgressStore progressStore;
    private final int sampleEndpoints;

    public PassiveChecks(HttpProbe probe, ScanProgressStore progressStore,
                         @Value("${scanner.sample-endpoints:25}") int sampleEndpoints) {
        this.probe = probe;
        this.progressStore = progressStore;
        this.sampleEndpoints = sampleEndpoints;
    }

    public List<Finding> run(Long scanId, URI target, Set<DiscoveredEndpoint> endpoints) {
        ScanProgress progress = progressStore.forScan(scanId);
        List<Finding> findings = new ArrayList<>();

        progress.log("Checking transport security on " + target);
        checkTransport(scanId, target, findings);
        progress.log("Checking security headers on " + target);
        checkBaseHeaders(scanId, target, findings);
        progress.log("Probing for exposed /actuator endpoints…");
        checkActuatorExposure(scanId, target, findings);
        progress.log("Checking the error page for stack-trace leaks…");
        checkErrorPageLeak(scanId, target, findings);

        long gets = endpoints.stream().filter(e -> e.method().equals("GET")).count();
        progress.log("Checking cookies and reflected input on up to " + sampleEndpoints
                + " of " + gets + " GET endpoint(s)…");
        int checked = 0;
        for (DiscoveredEndpoint endpoint : endpoints) {
            if (progress.isCancelled()) {
                break;
            }
            if (!endpoint.method().equals("GET")) {
                continue;
            }
            if (checked >= sampleEndpoints) {
                progress.log("Reached the sample limit (" + sampleEndpoints
                        + ") — skipping the remaining GET endpoint(s)");
                break;
            }
            checked++;
            progress.log("  → checking GET " + endpoint.url());
            checkCookies(scanId, endpoint, findings);
            checkReflectedInput(scanId, target, endpoint, findings);
            pause();
        }
        return findings;
    }

    // --- A02: transport security ------------------------------------------------

    private void checkTransport(Long scanId, URI target, List<Finding> findings) {
        if ("http".equalsIgnoreCase(target.getScheme())) {
            findings.add(new Finding(scanId,
                    "A02 Cryptographic Failures", Severity.LOW,
                    "Site served over cleartext HTTP",
                    target.toString(), "GET",
                    "The target responds over http://, so traffic is unencrypted.",
                    "Acceptable for local development. In production, serve over HTTPS "
                    + "and redirect HTTP to HTTPS."));
        }
    }

    // --- A05: security headers on the base response -----------------------------

    private void checkBaseHeaders(Long scanId, URI target, List<Finding> findings) {
        HttpProbe.Result result = probe.get(target.toString());
        if (result.failed()) {
            return;
        }
        String url = target.toString();

        requireHeader(scanId, findings, result, url, "Content-Security-Policy",
                "A05 Security Misconfiguration", Severity.MEDIUM,
                "No Content-Security-Policy header",
                "Add a Content-Security-Policy header to limit where scripts and other "
                + "resources can load from. This is a strong defence against XSS.");

        requireHeader(scanId, findings, result, url, "X-Content-Type-Options",
                "A05 Security Misconfiguration", Severity.LOW,
                "No X-Content-Type-Options header",
                "Set 'X-Content-Type-Options: nosniff' so browsers do not guess content types.");

        boolean hasFrameProtection = !result.header("X-Frame-Options").isEmpty()
                || result.firstHeader("Content-Security-Policy")
                        .map(v -> v.toLowerCase(Locale.ROOT).contains("frame-ancestors"))
                        .orElse(false);
        if (!hasFrameProtection) {
            findings.add(new Finding(scanId,
                    "A05 Security Misconfiguration", Severity.LOW,
                    "No clickjacking protection",
                    url, "GET",
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive is set.",
                    "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive."));
        }

        if ("https".equalsIgnoreCase(target.getScheme())
                && result.header("Strict-Transport-Security").isEmpty()) {
            findings.add(new Finding(scanId,
                    "A02 Cryptographic Failures", Severity.MEDIUM,
                    "No HTTP Strict-Transport-Security header",
                    url, "GET",
                    "The HTTPS response has no Strict-Transport-Security header.",
                    "Add an HSTS header so browsers always use HTTPS for this site."));
        }

        // A06: version banners, informational only.
        result.firstHeader("Server").ifPresent(server -> {
            if (server.matches(".*\\d.*")) {
                findings.add(new Finding(scanId,
                        "A06 Vulnerable and Outdated Components", Severity.INFO,
                        "Server version disclosed in headers",
                        url, "GET",
                        "Server header: " + server,
                        "Consider removing version details from the Server header; review "
                        + "the component for known vulnerabilities."));
            }
        });
        result.firstHeader("X-Powered-By").ifPresent(powered ->
                findings.add(new Finding(scanId,
                        "A06 Vulnerable and Outdated Components", Severity.INFO,
                        "Technology disclosed in X-Powered-By header",
                        url, "GET",
                        "X-Powered-By: " + powered,
                        "Remove the X-Powered-By header to avoid advertising the stack.")));
    }

    private void requireHeader(Long scanId, List<Finding> findings, HttpProbe.Result result,
                               String url, String header, String category, Severity severity,
                               String title, String remediation) {
        if (result.header(header).isEmpty()) {
            findings.add(new Finding(scanId, category, severity, title, url, "GET",
                    "Response has no " + header + " header.", remediation));
        }
    }

    // --- A01 / A05: actuator exposure ------------------------------------------

    private void checkActuatorExposure(Long scanId, URI target, List<Finding> findings) {
        String base = stripTrailingSlash(target.toString());
        String[] paths = {"/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings"};
        for (String path : paths) {
            String url = base + path;
            HttpProbe.Result result = probe.get(url);
            if (!result.failed() && result.status() == 200
                    && result.body() != null
                    && (result.body().contains("\"status\"") || result.body().contains("_links")
                        || result.body().contains("\"propertySources\""))) {
                Severity severity = path.equals("/actuator/env") || path.equals("/actuator/mappings")
                        ? Severity.HIGH : Severity.MEDIUM;
                findings.add(new Finding(scanId,
                        "A05 Security Misconfiguration", severity,
                        "Actuator endpoint publicly accessible: " + path,
                        url, "GET",
                        "Returned HTTP 200 with actuator data without authentication.",
                        "Expose only /actuator/health publicly, and secure the rest behind "
                        + "authentication (management.endpoints.web.exposure.include)."));
            }
            pause();
        }
    }

    // --- A05: verbose error pages ----------------------------------------------

    private void checkErrorPageLeak(Long scanId, URI target, List<Finding> findings) {
        String url = stripTrailingSlash(target.toString()) + "/jaiho-scan-" + UUID.randomUUID();
        HttpProbe.Result result = probe.get(url);
        if (result.failed() || result.body() == null) {
            return;
        }
        String body = result.body();
        boolean leaksTrace = body.contains("Exception")
                && (body.contains("\tat ") || body.contains(" at ") || body.contains("Trace"));
        if (leaksTrace) {
            findings.add(new Finding(scanId,
                    "A05 Security Misconfiguration", Severity.MEDIUM,
                    "Error page exposes a stack trace",
                    url, "GET",
                    "An unknown path returned an error page containing a stack trace.",
                    "Disable detailed error output in production "
                    + "(server.error.include-stacktrace=never) and show a generic error page."));
        }
    }

    // --- A02 / A05: cookie flags -----------------------------------------------

    private void checkCookies(Long scanId, DiscoveredEndpoint endpoint, List<Finding> findings) {
        HttpProbe.Result result = probe.get(endpoint.url());
        if (result.failed()) {
            return;
        }
        for (String cookie : result.header("Set-Cookie")) {
            String lower = cookie.toLowerCase(Locale.ROOT);
            String name = cookie.split("=", 2)[0];
            List<String> missing = new ArrayList<>();
            if (!lower.contains("httponly")) {
                missing.add("HttpOnly");
            }
            if (!lower.contains("secure")) {
                missing.add("Secure");
            }
            if (!lower.contains("samesite")) {
                missing.add("SameSite");
            }
            if (!missing.isEmpty()) {
                findings.add(new Finding(scanId,
                        "A05 Security Misconfiguration", Severity.MEDIUM,
                        "Cookie '" + name + "' missing flags: " + String.join(", ", missing),
                        endpoint.url(), "GET",
                        "Set-Cookie: " + cookie,
                        "Set the missing attributes. HttpOnly blocks script access, Secure "
                        + "restricts the cookie to HTTPS, and SameSite limits cross-site sending."));
            }
        }
    }

    // --- A03: reflected input (benign marker) ----------------------------------

    private void checkReflectedInput(Long scanId, URI target, DiscoveredEndpoint endpoint,
                                     List<Finding> findings) {
        String marker = "jaihoRef" + Long.toHexString(System.nanoTime());
        String sep = endpoint.url().contains("?") ? "&" : "?";
        String probedUrl = endpoint.url() + sep + "jaihoscan=" + marker;
        HttpProbe.Result result = probe.get(probedUrl);
        if (result.failed() || result.body() == null) {
            return;
        }
        String contentType = result.firstHeader("Content-Type").orElse("");
        if (contentType.toLowerCase(Locale.ROOT).contains("text/html")
                && result.body().contains(marker)) {
            findings.add(new Finding(scanId,
                    "A03 Injection", Severity.MEDIUM,
                    "Request input reflected in HTML response",
                    probedUrl, "GET",
                    "A benign marker added to the query string was echoed back in the HTML. "
                    + "Reflected input is a reflected-XSS signal and needs manual confirmation.",
                    "Ensure all user input is contextually escaped on output. With Thymeleaf, "
                    + "use th:text (which escapes) rather than th:utext for untrusted values."));
        }
    }

    // --- helpers ----------------------------------------------------------------

    private String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private void pause() {
        try {
            Thread.sleep(ScanPolicy.REQUEST_DELAY_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
