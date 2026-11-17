package com.jaiho.scanner.service;

import java.util.List;

import com.jaiho.scanner.domain.Finding;
import com.jaiho.scanner.domain.Severity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingDeduplicatorTest {

    private Finding f(String category, String title, Severity sev, String url) {
        return new Finding(1L, category, sev, title, url, "GET", "evidence", "fix");
    }

    @Test
    void collapsesSameTypeAcrossUrlsToOneWithACount() {
        List<Finding> result = FindingDeduplicator.dedupeByType(List.of(
                f("A05", "Cookie 'X' missing flags", Severity.MEDIUM, "http://host/a"),
                f("A05", "Cookie 'X' missing flags", Severity.MEDIUM, "http://host/b"),
                f("A05", "Cookie 'X' missing flags", Severity.MEDIUM, "http://host/c")));

        assertEquals(1, result.size());
        assertEquals("http://host/a", result.get(0).getUrl(), "keeps first location");
        assertTrue(result.get(0).getEvidence().contains("2 other"), "notes the other locations");
    }

    @Test
    void keepsDistinctTypesInFirstSeenOrder() {
        List<Finding> result = FindingDeduplicator.dedupeByType(List.of(
                f("A03", "Reflected input", Severity.MEDIUM, "http://host/a"),
                f("A05", "No CSP header", Severity.MEDIUM, "http://host/a"),
                f("A03", "Reflected input", Severity.MEDIUM, "http://host/b")));

        assertEquals(2, result.size());
        assertEquals("Reflected input", result.get(0).getTitle());
        assertEquals("No CSP header", result.get(1).getTitle());
    }

    @Test
    void leavesASingleFindingUntouched() {
        List<Finding> result = FindingDeduplicator.dedupeByType(List.of(
                f("A02", "Cleartext HTTP", Severity.LOW, "http://host/")));

        assertEquals(1, result.size());
        assertEquals("evidence", result.get(0).getEvidence());
    }

    @Test
    void treatsDifferentSeveritiesAsDistinct() {
        List<Finding> result = FindingDeduplicator.dedupeByType(List.of(
                f("A05", "Same title", Severity.HIGH, "http://host/a"),
                f("A05", "Same title", Severity.LOW, "http://host/b")));

        assertEquals(2, result.size());
    }
}
