package gg.effront.anarcry.model;

public record Finding(String module, String endpoint, String title, Severity severity, String evidence, String impact,
        String reproduction, String recommendation, String cweId, String cweTitle, String cvssVector,
        double cvssScore) {
    /**
     * Convenience factory: auto-fills CWE and CVSS fields from the module registry.
     */
    public static Finding of(String module, String endpoint, String title, Severity severity, String evidence,
            String impact, String reproduction, String recommendation) {
        String vec = CweRegistry.cvssVector(module);
        double score = CvssCalculator.calculate(vec);
        return new Finding(module, endpoint, title, severity, evidence, impact, reproduction, recommendation,
                CweRegistry.cweId(module), CweRegistry.cweTitle(module), vec, score);
    }

    /** Convenience factory with explicit CWE and CVSS fields. */
    public static Finding of(String module, String endpoint, String title, Severity severity, String evidence,
            String impact, String reproduction, String recommendation, String cweId, String cweTitle, String cvssVector,
            double cvssScore) {
        return new Finding(module, endpoint, title, severity, evidence, impact, reproduction, recommendation, cweId,
                cweTitle, cvssVector, cvssScore);
    }
}
