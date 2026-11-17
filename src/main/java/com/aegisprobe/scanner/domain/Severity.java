package com.aegisprobe.scanner.domain;

/**
 * Severity of a finding, ordered high to low. The {@code weight} orders findings
 * in the report and drives the summary counts.
 */
public enum Severity {

    HIGH(3),
    MEDIUM(2),
    LOW(1),
    INFO(0);

    private final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    public int getWeight() {
        return weight;
    }
}
