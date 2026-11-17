package com.aegisprobe.scanner.service;

/**
 * An endpoint found during discovery: an HTTP method and the URL it applies to.
 */
public record DiscoveredEndpoint(String method, String url) {
}
