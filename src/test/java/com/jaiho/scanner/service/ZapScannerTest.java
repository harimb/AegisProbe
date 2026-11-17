package com.jaiho.scanner.service;

import java.net.URI;
import java.util.List;

import com.jaiho.scanner.domain.Finding;
import com.jaiho.scanner.domain.Severity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ZapScannerTest {

    // Points at a port where nothing listens, so ZAP is unreachable.
    private final ZapScanner zap =
            new ZapScanner(new HttpProbe(), new ScanProgressStore(), "http://127.0.0.1:1", "host.docker.internal");

    @Test
    void returnsSingleInfoFindingWhenZapUnreachable() {
        List<Finding> findings = zap.active(1L, URI.create("http://localhost:8080"));

        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals(Severity.INFO, f.getSeverity());
        assertEquals("Active scan (ZAP)", f.getOwaspCategory());
    }

    @Test
    void mapsZapRiskToSeverity() {
        assertEquals(Severity.HIGH, zap.severityOf("High"));
        assertEquals(Severity.MEDIUM, zap.severityOf("Medium"));
        assertEquals(Severity.LOW, zap.severityOf("Low"));
        assertEquals(Severity.INFO, zap.severityOf("Informational"));
        assertEquals(Severity.INFO, zap.severityOf("anyt    hing else"));
    }

    @Test
    void mapsCweToOwaspCategory() {
        assertEquals("A03 Injection", zap.owaspCategory("79"));
        assertEquals("A02 Cryptographic Failures", zap.owaspCategory("319"));
        assertEquals("A05 Security Misconfiguration", zap.owaspCategory("1021"));
        assertEquals("Active scan (ZAP)", zap.owaspCategory(""));
    }

    @Test
    void rewritesLocalhostTargetToOverrideHostButLeavesExternalHosts() {
        assertEquals("http://host.docker.internal:8080",
                zap.zapTargetUrl(URI.create("http://localhost:8080")));
        assertEquals("http://apac.co.uk",
                zap.zapTargetUrl(URI.create("http://apac.co.uk")));
    }
}
