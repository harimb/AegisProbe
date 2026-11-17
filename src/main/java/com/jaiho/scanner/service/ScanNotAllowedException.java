package com.jaiho.scanner.service;

/**
 * Thrown when a scan request breaks a {@link ScanPolicy} rule — missing
 * authorization, a host that is not allowlisted, or a malformed target.
 */
public class ScanNotAllowedException extends RuntimeException {

    public ScanNotAllowedException(String message) {
        super(message);
    }
}
