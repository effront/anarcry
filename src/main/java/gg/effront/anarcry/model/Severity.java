package gg.effront.anarcry.model;

public enum Severity {
    CRITICAL, HIGH, MEDIUM, LOW, INFO;

    /** CVSS v3.1 score ranges to severity (NIST NVD). */
    public static Severity fromScore(double score) {
        if (score >= 9.0) {
            return CRITICAL;
        }
        if (score >= 7.0) {
            return HIGH;
        }
        if (score >= 4.0) {
            return MEDIUM;
        }
        if (score >= 0.1) {
            return LOW;
        }
        return INFO;
    }
}
