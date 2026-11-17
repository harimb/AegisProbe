package com.jaiho.scanner.service;

import java.net.URI;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanPolicyTest {

    private final ScanPolicy policy = new ScanPolicy(List.of("localhost", "127.0.0.1", "::1"));

    @Test
    void rejectsWhenNotAuthorized() {
        assertThrows(ScanNotAllowedException.class,
                () -> policy.validateTarget("http://localhost:8080", false));
    }

    @Test
    void rejectsHostNotOnAllowlist() {
        assertThrows(ScanNotAllowedException.class,
                () -> policy.validateTarget("http://example.com", true));
    }

    @Test
    void rejectsNonHttpScheme() {
        assertThrows(ScanNotAllowedException.class,
                () -> policy.validateTarget("ftp://localhost", true));
    }

    @Test
    void rejectsMalformedUrl() {
        assertThrows(ScanNotAllowedException.class,
                () -> policy.validateTarget("http://has space/", true));
    }

    @Test
    void acceptsAllowlistedHostAndReturnsUri() {
        URI uri = policy.validateTarget("http://localhost:8080/path", true);
        assertEquals("localhost", uri.getHost());
        assertEquals(8080, uri.getPort());
    }

    @Test
    void acceptsIpv6LoopbackWhenAllowlisted() {
        URI uri = policy.validateTarget("http://[::1]:8080", true);
        assertEquals(8080, uri.getPort());
    }

    @Test
    void allowlistIsTrimmedAndCaseInsensitive() {
        ScanPolicy p = new ScanPolicy(List.of("  LOCALHOST  "));
        URI uri = p.validateTarget("http://localhost:9000", true);
        assertEquals("localhost", uri.getHost());
    }

    @Test
    void sameHostMatchesRegardlessOfPathOrPort() {
        URI target = URI.create("http://localhost:8080");
        assertTrue(policy.isSameHost(target, "http://localhost:8080/login"));
        assertTrue(policy.isSameHost(target, "http://localhost:9999/other"));
        assertFalse(policy.isSameHost(target, "http://example.com/"));
    }
}
