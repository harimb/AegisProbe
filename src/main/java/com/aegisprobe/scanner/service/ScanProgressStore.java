package com.aegisprobe.scanner.service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * Holds live {@link ScanProgress} per scan id, in memory, so the running scan can
 * report progress and the status endpoint can read it. Progress is transient and
 * not persisted — it only backs the live view while a scan runs.
 */
@Component
public class ScanProgressStore {

    private final Map<Long, ScanProgress> byScan = new ConcurrentHashMap<>();

    /** The progress for a scan, creating it on first use. */
    public ScanProgress forScan(Long scanId) {
        return byScan.computeIfAbsent(scanId, k -> new ScanProgress());
    }

    /** The progress for a scan if one exists, without creating it. */
    public Optional<ScanProgress> find(Long scanId) {
        return Optional.ofNullable(byScan.get(scanId));
    }

    /** Discards a scan's progress, e.g. when the scan is deleted. */
    public void remove(Long scanId) {
        byScan.remove(scanId);
    }
}
