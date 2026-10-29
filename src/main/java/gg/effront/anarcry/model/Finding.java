package gg.effront.anarcry.model;

public record Finding(String module, String endpoint, String title, Severity severity, String evidence, String impact,
        String reproduction, String recommendation, String cweId, String cweTitle, String cvssVector,
        double cvssScore) {
    /**
     * Convenience factory: auto-fills CWE and CVSS fields from the module registry.
     * Severity is derived from the CVSS score, not from the passed parameter (kept
     * for source compatibility).
     */
    public static Finding of(String module, String endpoint, String title, Severity severity, String evidence,
            String impact, String reproduction, String recommendation) {
        String vec = CweRegistry.cvssVector(module);
        double score = CvssCalculator.calculate(vec);
        return new Finding(module, endpoint, title, Severity.fromScore(score), evidence, impact, reproduction,
                recommendation, CweRegistry.cweId(module), CweRegistry.cweTitle(module), vec, score);
    }

    /**
     * Convenience factory with explicit CWE and CVSS fields. Severity is derived
     * from cvssScore, not from the passed parameter.
     */
    public static Finding of(String module, String endpoint, String title, Severity severity, String evidence,
            String impact, String reproduction, String recommendation, String cweId, String cweTitle, String cvssVector,
            double cvssScore) {
        return new Finding(module, endpoint, title, Severity.fromScore(cvssScore), evidence, impact, reproduction,
                recommendation, cweId, cweTitle, cvssVector, cvssScore);
    }
}
