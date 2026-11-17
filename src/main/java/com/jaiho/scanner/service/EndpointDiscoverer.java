package com.jaiho.scanner.service;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Queue;
import java.util.Set;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Finds endpoints on the target by crawling its own pages: every same-origin
 * link is a GET endpoint, and every HTML {@code <form>} contributes its method
 * and action.
 *
 * <p>HTML forms can only express GET and POST. PATCH and JSON endpoints come
 * from an OpenAPI document, which a later step reads; this crawler covers the
 * rendered site.
 */
@Component
public class EndpointDiscoverer {

    private static final Logger log = LoggerFactory.getLogger(EndpointDiscoverer.class);

    private final ScanPolicy policy;

    public EndpointDiscoverer(ScanPolicy policy) {
        this.policy = policy;
    }

    /**
     * Crawls from {@code target}, staying on its host, and returns the endpoints
     * found (bounded by {@link ScanPolicy#MAX_ENDPOINTS}).
     */
    public Set<DiscoveredEndpoint> discover(URI target, ScanProgress progress) {
        Set<DiscoveredEndpoint> endpoints = new LinkedHashSet<>();
        Set<String> visited = new LinkedHashSet<>();
        Queue<String> toVisit = new ArrayDeque<>();

        String start = target.toString();
        toVisit.add(start);
        endpoints.add(new DiscoveredEndpoint("GET", start));

        while (!toVisit.isEmpty() && visited.size() < ScanPolicy.MAX_ENDPOINTS) {
            if (progress.isCancelled()) {
                break;
            }
            String pageUrl = toVisit.poll();
            if (!visited.add(pageUrl)) {
                continue;
            }
            progress.log("Crawling (" + visited.size() + "/" + ScanPolicy.MAX_ENDPOINTS + ") " + pageUrl);
            Document doc = fetch(pageUrl);
            if (doc == null) {
                continue;
            }

            for (Element link : doc.select("a[href]")) {
                String href = link.absUrl("href");
                int hash = href.indexOf('#');
                if (hash >= 0) {
                    href = href.substring(0, hash);   // drop #fragment — same page
                }
                if (isCrawlable(target, href) && !visited.contains(href)
                        && endpoints.size() < ScanPolicy.MAX_ENDPOINTS) {
                    if (endpoints.add(new DiscoveredEndpoint("GET", href))) {
                        progress.log("  found GET " + href);
                    }
                    toVisit.add(href);
                }
            }

            for (Element form : doc.select("form")) {
                String action = form.absUrl("action");
                if (action.isBlank()) {
                    action = pageUrl;
                }
                String method = form.hasAttr("method")
                        ? form.attr("method").toUpperCase(Locale.ROOT) : "GET";
                if (policy.isSameHost(target, action) && ScanPolicy.ALLOWED_METHODS.contains(method)
                        && endpoints.add(new DiscoveredEndpoint(method, action))) {
                    progress.log("  found " + method + " " + action);
                }
            }

            sleep();
        }

        log.info("Discovery found {} endpoint(s) on {}", endpoints.size(), target.getHost());
        return endpoints;
    }

    private Document fetch(String url) {
        try {
            return Jsoup.connect(url)
                    .userAgent("JaiHo-Scanner")
                    .timeout(5000)
                    .followRedirects(true)
                    .ignoreHttpErrors(true)
                    .ignoreContentType(true)
                    .get();
        } catch (IOException e) {
            log.debug("Could not fetch {}: {}", url, e.getMessage());
            return null;
        }
    }

    private boolean isCrawlable(URI target, String href) {
        if (href == null || href.isBlank()) {
            return false;
        }
        if (!href.startsWith("http://") && !href.startsWith("https://")) {
            return false;
        }
        // Don't follow the logout link; it would just end an (irrelevant) session.
        if (href.contains("/logout")) {
            return false;
        }
        return policy.isSameHost(target, href);
    }

    private void sleep() {
        try {
            Thread.sleep(ScanPolicy.REQUEST_DELAY_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
