package com.aegisprobe.scanner.service;

import java.util.List;

import com.aegisprobe.scanner.domain.Finding;
import com.aegisprobe.scanner.domain.Scan;
import com.aegisprobe.scanner.domain.Severity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;

class ScanSummaryTest {

    private final Scan scan = new Scan("http://localhost:8080", "tester");

    private Finding finding(Severity severity, String category) {
        return new Finding(1L, category, severity, severity + " in " + category,
                "http://localhost:8080", "GET", "evidence", "fix");
    }

    @Test
    void sortsFindingsMostSevereFirst() {
        ScanSummary summary = ScanSummary.of(scan, List.of(
                finding(Severity.LOW, "A02"),
                finding(Severity.HIGH, "A01"),
                finding(Severity.INFO, "A09"),
                finding(Severity.MEDIUM, "A05")));

        List<Severity> order = summary.findings().stream().map(Finding::getSeverity).toList();
        assertIterableEquals(
                List.of(Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO), order);
    }

    @Test
    void countsEachSeverity() {
        ScanSummary summary = ScanSummary.of(scan, List.of(
                finding(Severity.HIGH, "A01"),
                finding(Severity.MEDIUM, "A05"),
                finding(Severity.MEDIUM, "A05"),
                finding(Severity.LOW, "A02")));

        assertEquals(1, summary.high());
        assertEquals(2, summary.medium());
        assertEquals(1, summary.low());
        assertEquals(0, summary.info());
        assertEquals(4, summary.total());
    }

    @Test
    void groupsByCategoryOrderedByCountDescending() {
        ScanSummary summary = ScanSummary.of(scan, List.of(
                finding(Severity.LOW, "A02 Crypto"),
                finding(Severity.HIGH, "A05 Misconfig"),
                finding(Severity.MEDIUM, "A05 Misconfig"),
                finding(Severity.LOW, "A05 Misconfig")));

        assertIterableEquals(List.of("A05 Misconfig", "A02 Crypto"), summary.categoryLabels());
        assertIterableEquals(List.of(3, 1), summary.categoryValues());
    }

    @Test
    void handlesNoFindings() {
        ScanSummary summary = ScanSummary.of(scan, List.of());
        assertEquals(0, summary.total());
        assertEquals(0, summary.high());
        assertEquals(List.of(), summary.categoryLabels());
    }
}
