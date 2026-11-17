package com.aegisprobe.scanner.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Enables {@code @Async} so scans run on a background thread and the request that
 * starts a scan returns immediately.
 */
@Configuration
@EnableAsync
public class ScannerConfig {
}
