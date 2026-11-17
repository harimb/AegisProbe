package com.aegisprobe.scanner.service;

import com.aegisprobe.scanner.domain.Finding;
import com.aegisprobe.scanner.domain.Scan;
import com.aegisprobe.scanner.domain.ScanStatus;
import com.aegisprobe.scanner.repository.FindingRepository;
import com.aegisprobe.scanner.repository.ScanRepository;

import java.net.URI;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Executes a scan on a background thread: discover endpoints (crawl + OpenAPI),
 * run the passive checks, optionally run a ZAP active scan, persist the findings,
 * and move the scan to its final status.
 */
@Component
public class ScanRunner {

    private static final Logger log = LoggerFactory.getLogger(ScanRunner.class);

    private final ScanRepository scans;
    private final FindingRepository findings;
    private final EndpointDiscoverer discoverer;
    private final OpenApiDiscoverer openApiDiscoverer;
    private final PassiveChecks passiveChecks;
    private final ZapScanner zapScanner;
    private final ScanProgressStore progressStore;

    public ScanRunner(ScanRepository scans, FindingRepository findings,
                      EndpointDiscoverer discoverer, OpenApiDiscoverer openApiDiscoverer,
                      PassiveChecks passiveChecks, ZapScanner zapScanner,
                      ScanProgressStore progressStore) {
        this.scans = scans;
        this.findings = findings;
        this.discoverer = discoverer;
        this.openApiDiscoverer = openApiDiscoverer;
        this.passiveChecks = passiveChecks;
        this.zapScanner = zapScanner;
        this.progressStore = progressStore;
    }

    @Async
    public void run(Long scanId, URI target, boolean activeScan) {
        Scan scan = scans.findById(scanId).orElseThrow();
        ScanProgress progress = progressStore.forScan(scanId);
        try {
            scan.setStatus(ScanStatus.RUNNING);
            scans.save(scan);
            progress.setPhase("Starting", 5);
            progress.log("Scan started for " + target);

            progress.setPhase("Discovering endpoints", 15);
            progress.log("Crawling " + target.getHost() + " for pages and forms…");
            Set<DiscoveredEndpoint> endpoints = new LinkedHashSet<>(discoverer.discover(target, progress));
            progress.log("Crawl finished: " + endpoints.size() + " endpoint(s) found");
            Set<DiscoveredEndpoint> apiEndpoints = openApiDiscoverer.discover(target);
            if (apiEndpoints.isEmpty()) {
                progress.log("No OpenAPI document found");
            } else {
                progress.log("OpenAPI document added " + apiEndpoints.size() + " endpoint(s):");
                apiEndpoints.forEach(e -> progress.log("  • " + e.method() + " " + e.url()));
            }
            endpoints.addAll(apiEndpoints);
            scan.setEndpointsSeen(endpoints.size());
            if (stopped(scanId, progress)) {
                return;
            }

            progress.setPhase("Passive checks", activeScan ? 35 : 55);
            progress.log("Running passive checks on " + endpoints.size() + " endpoint(s)…");
            List<Finding> results = new ArrayList<>(passiveChecks.run(scanId, target, endpoints));
            progress.log("Passive checks produced " + results.size() + " finding(s)");
            if (stopped(scanId, progress)) {
                return;
            }

            if (activeScan) {
                progress.setPhase("Active scan (ZAP)", 50);
                results.addAll(zapScanner.active(scanId, target));
            }
            if (stopped(scanId, progress)) {
                return;
            }

            progress.setPhase("Saving results", 97);
            List<Finding> deduped = FindingDeduplicator.dedupeByType(results);
            if (deduped.size() < results.size()) {
                progress.log("Collapsed " + results.size() + " finding(s) into "
                        + deduped.size() + " unique issue type(s)");
            }
            findings.saveAll(deduped);

            scan.setStatus(ScanStatus.DONE);
            scan.setFinishedAt(OffsetDateTime.now());
            scans.save(scan);
            progress.log("Scan complete: " + deduped.size() + " finding(s)");
            progress.complete();
            log.info("Scan {} finished: {} endpoint(s), {} finding(s) (active={})",
                    scanId, endpoints.size(), deduped.size(), activeScan);
        } catch (Exception e) {
            log.warn("Scan {} failed", scanId, e);
            if (progress.isCancelled() || !scans.existsById(scanId)) {
                return;
            }
            progress.log("Scan failed: " + e.getClass().getSimpleName() + " " + e.getMessage());
            progress.setPhase("Failed", 100);
            scan.setStatus(ScanStatus.FAILED);
            scan.setErrorMessage(e.getClass().getSimpleName() + ": " + e.getMessage());
            scan.setFinishedAt(OffsetDateTime.now());
            scans.save(scan);
        }
    }

    /** True when the scan has been cancelled or deleted — the runner should bail. */
    private boolean stopped(Long scanId, ScanProgress progress) {
        if (progress.isCancelled() || !scans.existsById(scanId)) {
            log.info("Scan {} stopped (cancelled or deleted)", scanId);
            progress.log("Scan cancelled — stopping");
            return true;
        }
        return false;
    }
}
