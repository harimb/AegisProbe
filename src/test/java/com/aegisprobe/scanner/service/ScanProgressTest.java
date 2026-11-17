package com.aegisprobe.scanner.service;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanProgressTest {

    @Test
    void logRecordsMessagesInOrder() {
        ScanProgress progress = new ScanProgress();
        progress.log("first");
        progress.log("second");

        List<String> log = progress.getLog();
        assertEquals(2, log.size());
        assertTrue(log.get(0).contains("first"));
        assertTrue(log.get(1).contains("second"));
    }

    @Test
    void setPhaseUpdatesPhaseAndPercent() {
        ScanProgress progress = new ScanProgress();
        progress.setPhase("Passive checks", 40);

        assertEquals("Passive checks", progress.getPhase());
        assertEquals(40, progress.getPercent());
        assertFalse(progress.isDone());
    }

    @Test
    void percentIsClampedToRange() {
        ScanProgress progress = new ScanProgress();
        progress.setPhase("over", 150);
        assertEquals(100, progress.getPercent());
        progress.setPhase("under", -5);
        assertEquals(0, progress.getPercent());
    }

    @Test
    void cancelSetsTheCancelledFlag() {
        ScanProgress progress = new ScanProgress();
        assertFalse(progress.isCancelled());

        progress.cancel();

        assertTrue(progress.isCancelled());
    }

    @Test
    void completeMarksDoneAtFullPercent() {
        ScanProgress progress = new ScanProgress();
        progress.complete();

        assertTrue(progress.isDone());
        assertEquals(100, progress.getPercent());
    }

    @Test
    void logIsCappedKeepingMostRecent() {
        ScanProgress progress = new ScanProgress();
        for (int i = 0; i < 900; i++) {
            progress.log("line " + i);
        }
        List<String> log = progress.getLog();
        assertTrue(log.size() <= 800, "log capped");
        assertTrue(log.get(log.size() - 1).contains("line 899"), "keeps newest");
    }
}
