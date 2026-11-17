package com.aegisprobe.scanner.domain;

/**
 * Lifecycle of a scan. The UI polls while a scan is RUNNING and stops once it
 * reaches DONE or FAILED.
 */
public enum ScanStatus {
    PENDING,
    RUNNING,
    DONE,
    FAILED
}
