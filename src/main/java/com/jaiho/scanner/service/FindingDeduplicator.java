package com.jaiho.scanner.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.jaiho.scanner.domain.Finding;

/**
 * Collapses findings of the same type so each issue is reported once. A "type" is
 * the same severity, OWASP category and title; the first occurrence is kept (as the
 * representative location) and its evidence notes how many other URLs showed it.
 *
 * <p>This stops a single misconfiguration (e.g. a cookie flag) from producing one
 * finding per crawled URL.
 */
public final class FindingDeduplicator {

    private FindingDeduplicator() {
    }

    public static List<Finding> dedupeByType(List<Finding> findings) {
        Map<String, List<Finding>> byType = new LinkedHashMap<>();
        for (Finding f : findings) {
            String key = f.getSeverity() + "\u0000" + f.getOwaspCategory() + "\u0000" + f.getTitle();
            byType.computeIfAbsent(key, k -> new ArrayList<>()).add(f);
        }

        List<Finding> result = new ArrayList<>(byType.size());
        for (List<Finding> group : byType.values()) {
            Finding first = group.get(0);
            int others = group.size() - 1;
            if (others == 0) {
                result.add(first);
            } else {
                String note = "Also found on " + others + " other location"
                        + (others == 1 ? "" : "s") + " in this scan.";
                String evidence = first.getEvidence() == null || first.getEvidence().isBlank()
                        ? note
                        : first.getEvidence() + " " + note;
                result.add(new Finding(first.getScanId(), first.getOwaspCategory(), first.getSeverity(),
                        first.getTitle(), first.getUrl(), first.getMethod(), evidence, first.getRemediation()));
            }
        }
        return result;
    }
}
