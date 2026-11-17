package com.aegisprobe.scanner.service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Enforces the rules that keep this scanner to authorized, self-owned targets.
 *
 * <ul>
 *   <li>The caller must confirm they are authorized to test the target.</li>
 *   <li>The target host must be on the allowlist (localhost only, by default).</li>
 *   <li>Discovery stays on the target's own host (same-origin).</li>
 * </ul>
 *
 * The allowlist is configured with {@code scanner.allowed-hosts}; add a staging
 * host you control there only if you need it.
 */
@Component
public class ScanPolicy {

    /** HTTP methods the scanner is allowed to send. DELETE is deliberately excluded. */
    public static final List<String> ALLOWED_METHODS = List.of("GET", "POST", "PATCH");

    /** Delay between requests, to stay gentle on the target. */
    public static final long REQUEST_DELAY_MILLIS = 200L;

    /** Upper bound on pages the crawler will visit in one scan. */
    public static final int MAX_ENDPOINTS = 100;

    private final List<String> allowedHosts;

    public ScanPolicy(@Value("${scanner.allowed-hosts:localhost,127.0.0.1,::1,apac.co.uk,partybits.co.uk}") List<String> allowedHosts) {
        this.allowedHosts = allowedHosts.stream()
                .map(h -> normalizeHost(h.trim()))
                .toList();
    }

    /**
     * Validates a scan request before any request is sent to the target.
     *
     * @return the normalized target URI
     * @throws ScanNotAllowedException if the request is not authorized or the host is not allowed
     */
    public URI validateTarget(String targetUrl, boolean authorized) {
        if (!authorized) {
            throw new ScanNotAllowedException(
                    "You must confirm you are authorized to test this target.");
        }
        URI uri = parse(targetUrl);
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equals("http") || scheme.equals("https"))) {
            throw new ScanNotAllowedException("Target must be an http:// or https:// URL.");
        }
        if (!isAllowedHost(uri.getHost())) {
            throw new ScanNotAllowedException(
                    "Host '" + uri.getHost() + "' is not on the allowlist. "
                    + "This scanner only tests hosts you have explicitly authorized "
                    + "(localhost by default; see scanner.allowed-hosts).");
        }
        return uri;
    }

    /** True when {@code candidate} is on the same host as the scan target. */
    public boolean isSameHost(URI target, String candidateUrl) {
        try {
            URI candidate = new URI(candidateUrl);
            String host = candidate.getHost();
            return host != null && target.getHost() != null
                    && normalizeHost(host).equals(normalizeHost(target.getHost()));
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private boolean isAllowedHost(String host) {
        return host != null && allowedHosts.contains(normalizeHost(host));
    }

    /**
     * Lowercases a host and strips the brackets that {@link URI#getHost()} keeps
     * around IPv6 literals (e.g. {@code [::1]} becomes {@code ::1}), so bracketed
     * and bare forms compare equal.
     */
    private static String normalizeHost(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        return h;
    }

    private URI parse(String targetUrl) {
        try {
            return new URI(targetUrl.trim());
        } catch (URISyntaxException e) {
            throw new ScanNotAllowedException("Target is not a valid URL.");
        }
    }

    public List<String> getAllowedHosts() {
        return allowedHosts;
    }
}
