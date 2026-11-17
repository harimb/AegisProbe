package com.aegisprobe.scanner.service;

import com.aegisprobe.scanner.domain.Finding;
import com.aegisprobe.scanner.domain.Severity;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Drives OWASP ZAP (running as a daemon, usually in the {@code scanner} Compose
 * profile) through its JSON API to run an active scan against the target and turn
 * ZAP's alerts into {@link Finding}s.
 *
 * <p>Active scanning sends crafted requests to the target, so it only runs when
 * the user opts in and the target is already allowlisted by {@link ScanPolicy}.
 * If ZAP is not reachable, the scan degrades gracefully to a single note.
 */
@Component
public class ZapScanner {

    private static final Logger log = LoggerFactory.getLogger(ZapScanner.class);
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private static final long POLL_INTERVAL_MILLIS = 2000L;
    private static final long SPIDER_TIMEOUT_MILLIS = 120_000L;
    private static final long ASCAN_TIMEOUT_MILLIS = 300_000L;
    private static final int MAX_ALERTS = 200;

    private final HttpProbe probe;
    private final ScanProgressStore progressStore;
    private final String baseUrl;
    private final String targetHostOverride;

    public ZapScanner(HttpProbe probe, ScanProgressStore progressStore,
                      @Value("${scanner.zap.base-url:http://localhost:8090}") String baseUrl,
                      @Value("${scanner.zap.target-host-override:host.docker.internal}") String targetHostOverride) {
        this.probe = probe;
        this.progressStore = progressStore;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.targetHostOverride = targetHostOverride;
    }

    /** True when the ZAP daemon answers its version call. */
    public boolean isReachable() {
        JsonNode node = call("/JSON/core/view/version/");
        return node != null && node.hasNonNull("version");
    }

    /**
     * Runs a ZAP spider + active scan against the target and returns the alerts as
     * findings. If ZAP is not reachable, returns one INFO finding explaining that.
     */
    public List<Finding> active(Long scanId, URI target) {
        ScanProgress progress = progressStore.forScan(scanId);
        progress.log("Connecting to ZAP at " + baseUrl);
        JsonNode version = call("/JSON/core/view/version/");
        if (version == null || !version.hasNonNull("version")) {
            log.info("Active scan requested but ZAP is not reachable at {}", baseUrl);
            progress.log("ZAP not reachable — skipping active scan");
            return List.of(new Finding(scanId, "Active scan (ZAP)", Severity.INFO,
                    "Active scan skipped — ZAP not reachable", target.toString(), "GET",
                    "No ZAP daemon answered at " + baseUrl + ".",
                    "Start it with: docker compose --profile scanner up -d zap"));
        }
        progress.log("Connected to ZAP " + version.get("version").asString());

        String zapTarget = zapTargetUrl(target);
        log.info("ZAP active scan starting against {}", zapTarget);
        progress.log("ZAP target URL: " + zapTarget);

        call("/JSON/core/action/accessUrl/", "url", zapTarget, "followRedirects", "true");
        String spiderId = runAndWait(progress, "spider", "/JSON/spider/action/scan/",
                "/JSON/spider/view/status/", "/JSON/spider/action/stop/", zapTarget,
                SPIDER_TIMEOUT_MILLIS, 50, 68, "maxChildren", "10", "recurse", "true");
        if (progress.isCancelled()) {
            return List.of();
        }
        logSpiderResults(progress, spiderId);
        runAndWait(progress, "active scan", "/JSON/ascan/action/scan/", "/JSON/ascan/view/status/",
                "/JSON/ascan/action/stop/", zapTarget, ASCAN_TIMEOUT_MILLIS, 68, 95,
                "recurse", "true", "inScopeOnly", "false");
        if (progress.isCancelled()) {
            return List.of();
        }

        List<Finding> findings = mapAlerts(scanId, target, zapTarget, progress);
        progress.log("ZAP produced " + findings.size() + " alert(s) (before dedup)");
        return findings;
    }

    /** Logs the URLs the spider crawled (capped so the log stays readable). */
    private void logSpiderResults(ScanProgress progress, String spiderId) {
        if (spiderId == null) {
            return;
        }
        JsonNode node = call("/JSON/spider/view/results/", "scanId", spiderId);
        if (node == null || !node.has("results")) {
            return;
        }
        JsonNode results = node.get("results");
        progress.log("ZAP spider visited " + results.size() + " URL(s):");
        int shown = 0;
        for (JsonNode url : results) {
            if (shown >= 200) {
                progress.log("  … and " + (results.size() - 200) + " more");
                break;
            }
            shown++;
            progress.log("  ↳ " + url.asString(""));
        }
    }

    // --- scan orchestration -----------------------------------------------------

    private String runAndWait(ScanProgress progress, String label, String scanPath, String statusPath,
                              String stopPath, String zapTarget, long timeoutMillis, int pctFrom,
                              int pctTo, String... extraParams) {
        String[] params = new String[extraParams.length + 2];
        params[0] = "url";
        params[1] = zapTarget;
        System.arraycopy(extraParams, 0, params, 2, extraParams.length);

        JsonNode start = call(scanPath, params);
        if (start == null || !start.hasNonNull("scan")) {
            log.warn("ZAP {} did not start", label);
            progress.log("ZAP " + label + " did not start");
            return null;
        }
        String scanId = start.get("scan").asString();
        progress.log("ZAP " + label + " started");
        int lastLogged = -100;
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (System.currentTimeMillis() < deadline) {
            if (progress.isCancelled()) {
                call(stopPath, "scanId", scanId);
                progress.log("ZAP " + label + " stopped (scan cancelled)");
                return scanId;
            }
            JsonNode status = call(statusPath, "scanId", scanId);
            int percent = status != null && status.hasNonNull("status")
                    ? parseInt(status.get("status").asString()) : 0;
            progress.setPhase("Active scan — " + label, pctFrom + (pctTo - pctFrom) * percent / 100);
            if (percent - lastLogged >= 10 && percent < 100) {
                progress.log("ZAP " + label + ": " + percent + "%");
                lastLogged = percent;
            }
            if (percent >= 100) {
                log.info("ZAP {} complete", label);
                progress.log("ZAP " + label + " complete");
                return scanId;
            }
            sleep();
        }
        log.warn("ZAP {} timed out; continuing with partial results", label);
        progress.log("ZAP " + label + " timed out; continuing with partial results");
        return scanId;
    }

    private List<Finding> mapAlerts(Long scanId, URI reportUrl, String zapTarget, ScanProgress progress) {
        JsonNode node = call("/JSON/core/view/alerts/", "baseurl", zapTarget, "start", "0", "count", "1000");
        if (node == null || !node.has("alerts")) {
            return List.of();
        }
        List<Finding> findings = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (JsonNode alert : node.get("alerts")) {
            if (findings.size() >= MAX_ALERTS) {
                break;
            }
            String name = alert.path("name").asString("ZAP alert");
            String url = restoreHost(alert.path("url").asString(zapTarget), reportUrl);
            String method = alert.path("method").asString("GET");
            String key = name + "|" + url + "|" + method;
            if (!seen.add(key)) {
                continue;
            }
            String risk = alert.path("risk").asString("Informational");
            progress.log("  ALERT [" + risk + "] " + name + " — " + method + " " + url);
            findings.add(new Finding(scanId,
                    owaspCategory(alert.path("cweid").asString("")),
                    severityOf(risk),
                    name, url, method,
                    truncate(alert.path("description").asString(""), 2000),
                    truncate(alert.path("solution").asString(""), 1000)));
        }
        log.info("ZAP active scan produced {} finding(s)", findings.size());
        return findings;
    }

    // --- helpers ----------------------------------------------------------------

    /** Rewrites a localhost target to a host ZAP (in a container) can reach. */
    String zapTargetUrl(URI target) {
        String host = target.getHost();
        boolean isLocal = "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host) || "::1".equals(host);
        if (isLocal && targetHostOverride != null && !targetHostOverride.isBlank()) {
            String port = target.getPort() == -1 ? "" : ":" + target.getPort();
            return target.getScheme() + "://" + targetHostOverride + port;
        }
        return target.toString();
    }

    /** Puts the user-facing host back on a URL ZAP reported against the override host. */
    private String restoreHost(String url, URI reportUrl) {
        if (targetHostOverride == null || targetHostOverride.isBlank()) {
            return url;
        }
        String port = reportUrl.getPort() == -1 ? "" : ":" + reportUrl.getPort();
        return url.replace(targetHostOverride + port, reportUrl.getHost() + port);
    }

    Severity severityOf(String risk) {
        return switch (risk.toLowerCase(Locale.ROOT)) {
            case "high" -> Severity.HIGH;
            case "medium" -> Severity.MEDIUM;
            case "low" -> Severity.LOW;
            default -> Severity.INFO;
        };
    }

    /** Best-effort mapping from a ZAP alert's CWE to an OWASP Top 10 category. */
    String owaspCategory(String cweid) {
        return switch (cweid) {
            case "79" -> "A03 Injection";                       // XSS
            case "89", "943" -> "A03 Injection";                // SQL / NoSQL injection
            case "22" -> "A01 Broken Access Control";           // path traversal
            case "352" -> "A01 Broken Access Control";          // CSRF
            case "319", "327" -> "A02 Cryptographic Failures";  // cleartext / weak crypto
            case "16", "693" -> "A05 Security Misconfiguration"; // config / headers
            case "1021" -> "A05 Security Misconfiguration";     // clickjacking
            default -> "Active scan (ZAP)";
        };
    }

    private JsonNode call(String path, String... params) {
        StringBuilder url = new StringBuilder(baseUrl).append(path);
        for (int i = 0; i + 1 < params.length; i += 2) {
            url.append(i == 0 ? '?' : '&')
               .append(params[i]).append('=')
               .append(URLEncoder.encode(params[i + 1], StandardCharsets.UTF_8));
        }
        HttpProbe.Result result = probe.get(url.toString());
        if (result.failed() || result.body() == null) {
            return null;
        }
        try {
            return MAPPER.readTree(result.body());
        } catch (Exception e) {
            log.debug("ZAP response was not JSON for {}: {}", path, e.getMessage());
            return null;
        }
    }

    private int parseInt(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private String truncate(String s, int max) {
        if (s == null) {
            return null;
        }
        return s.length() <= max ? s : s.substring(0, max);
    }

    private void sleep() {
        try {
            Thread.sleep(POLL_INTERVAL_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
