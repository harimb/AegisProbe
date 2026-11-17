package com.aegisprobe.scanner.service;

import com.aegisprobe.scanner.domain.Scan;
import com.aegisprobe.scanner.repository.FindingRepository;
import com.aegisprobe.scanner.repository.ScanRepository;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

/**
 * Entry point for starting and reading scans. Starting a scan validates it
 * against {@link ScanPolicy}, records it, and hands off to {@link ScanRunner}.
 */
@Service
public class ScanService {

    private final ScanPolicy policy;
    private final ScanRepository scans;
    private final FindingRepository findings;
    private final ScanRunner runner;
    private final ScanProgressStore progressStore;

    public ScanService(ScanPolicy policy, ScanRepository scans, FindingRepository findings,
                       ScanRunner runner, ScanProgressStore progressStore) {
        this.policy = policy;
        this.scans = scans;
        this.findings = findings;
        this.runner = runner;
        this.progressStore = progressStore;
    }

    /**
     * Validates and starts a scan. Returns the new scan's id; the scan itself
     * runs in the background.
     *
     * @throws ScanNotAllowedException if the request fails a policy rule
     */
    public Long startScan(String targetUrl, boolean authorized, boolean activeScan, String username) {
        URI target = policy.validateTarget(targetUrl, authorized);
        Scan scan = scans.save(new Scan(target.toString(), username));
        runner.run(scan.getId(), target, activeScan);
        return scan.getId();
    }

    public Optional<Scan> getScan(Long id) {
        return scans.findById(id);
    }

    public Optional<ScanSummary> getSummary(Long id) {
        return scans.findById(id)
                .map(scan -> ScanSummary.of(scan, findings.findByScanId(id)));
    }

    public List<Scan> recentScans() {
        return scans.findAllByOrderByStartedAtDesc();
    }

    /**
     * Permanently deletes a scan and its findings (the finding rows are removed by
     * the {@code ON DELETE CASCADE} foreign key). If the scan is still running it is
     * cancelled first, so the background thread stops instead of re-saving it.
     */
    public boolean deleteScan(Long id) {
        if (!scans.existsById(id)) {
            return false;
        }
        progressStore.find(id).ifPresent(ScanProgress::cancel);
        scans.deleteById(id);
        progressStore.remove(id);
        return true;
    }

    /** Deletes several scans, returning how many were removed. */
    public int deleteScans(List<Long> ids) {
        int deleted = 0;
        for (Long id : ids) {
            if (deleteScan(id)) {
                deleted++;
            }
        }
        return deleted;
    }

    public List<String> allowedHosts() {
        return policy.getAllowedHosts();
    }
}
