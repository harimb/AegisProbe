package com.jaiho.scanner.service;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * Live progress of a single scan: the current phase, a percent, a done flag, and
 * a rolling log of what the scan is doing. Written by the scan thread and read by
 * the status endpoint, so all access is synchronized.
 */
public class ScanProgress {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final int MAX_LOG_LINES = 800;

    private final Deque<String> log = new ArrayDeque<>();

    private volatile String phase = "Queued";
    private volatile int percent = 0;
    private volatile boolean done = false;
    private volatile boolean cancelled = false;

    /** Appends a timestamped message, dropping the oldest when the cap is reached. */
    public synchronized void log(String message) {
        if (log.size() >= MAX_LOG_LINES) {
            log.removeFirst();
        }
        log.addLast("[" + LocalTime.now().format(TIME) + "] " + message);
    }

    /** Sets the current phase and percent (clamped to 0–100). */
    public void setPhase(String phase, int percent) {
        this.phase = phase;
        this.percent = Math.max(0, Math.min(100, percent));
    }

    /** Marks the scan finished at 100%. */
    public void complete() {
        this.done = true;
        this.percent = 100;
    }

    /** Requests that the running scan stop as soon as it reaches a checkpoint. */
    public void cancel() {
        this.cancelled = true;
    }

    public boolean isCancelled() {
        return cancelled;
    }

    public String getPhase() {
        return phase;
    }

    public int getPercent() {
        return percent;
    }

    public boolean isDone() {
        return done;
    }

    /** A snapshot copy of the log lines, oldest first. */
    public synchronized List<String> getLog() {
        return new ArrayList<>(log);
    }
}
