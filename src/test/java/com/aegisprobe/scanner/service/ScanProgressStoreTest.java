package com.aegisprobe.scanner.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanProgressStoreTest {

    private final ScanProgressStore store = new ScanProgressStore();

    @Test
    void returnsSameProgressForSameScanId() {
        ScanProgress first = store.forScan(7L);
        ScanProgress again = store.forScan(7L);
        assertSame(first, again);
    }

    @Test
    void returnsDistinctProgressForDifferentScanIds() {
        assertNotSame(store.forScan(1L), store.forScan(2L));
    }

    @Test
    void removeDiscardsStoredProgress() {
        store.forScan(5L);
        assertTrue(store.find(5L).isPresent());

        store.remove(5L);

        assertFalse(store.find(5L).isPresent());
    }
}
