package com.aegisprobe.scanner.service;

import com.aegisprobe.scanner.domain.Finding;
import com.aegisprobe.scanner.domain.Scan;
import com.aegisprobe.scanner.domain.Severity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A scan plus its findings, with counts ready for the report header. Findings are
 * sorted most-severe first.
 */
public record ScanSummary(Scan scan, List<Finding> findings,
                          long high, long medium, long low, long info) {

    public static ScanSummary of(Scan scan, List<Finding> unsorted) {
        List<Finding> findings = unsorted.stream()
                .sorted(Comparator.comparingInt((Finding f) -> f.getSeverity().getWeight())
                        .reversed()
                        .thenComparing(Finding::getOwaspCategory))
                .toList();
        long high = count(findings, Severity.HIGH);
        long medium = count(findings, Severity.MEDIUM);
        long low = count(findings, Severity.LOW);
        long info = count(findings, Severity.INFO);
        return new ScanSummary(scan, findings, high, medium, low, info);
    }

    public int total() {
        return findings.size();
    }

    /**
     * Findings grouped by OWASP category, ordered by how many each has (most
     * first). Used for the grouped view and the category chart.
     */
    public Map<String, List<Finding>> byCategory() {
        Map<String, List<Finding>> grouped = new TreeMap<>();
        for (Finding finding : findings) {
            grouped.computeIfAbsent(finding.getOwaspCategory(), k -> new ArrayList<>())
                    .add(finding);
        }
        return grouped.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()))
                .collect(LinkedHashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), Map::putAll);
    }

    /** Category names, ordered for the chart (most findings first). */
    public List<String> categoryLabels() {
        return new ArrayList<>(byCategory().keySet());
    }

    /** Finding counts per category, aligned with {@link #categoryLabels()}. */
    public List<Integer> categoryValues() {
        return byCategory().values().stream().map(List::size).toList();
    }

    private static long count(List<Finding> findings, Severity severity) {
        return findings.stream().filter(f -> f.getSeverity() == severity).count();
    }
}
