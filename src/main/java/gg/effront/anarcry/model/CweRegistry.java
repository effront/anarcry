package gg.effront.anarcry.model;

public class CweRegistry {

    private static final String[] FALLBACK = new String[]{"CWE-200", "Exposure of Sensitive Information",
            CvssCalculator.defaultVector(Severity.MEDIUM)};

    public static String[] forModule(String moduleId) {
        return KnowledgeBase.getInstance().byModule(moduleId)
                .map(e -> new String[]{e.cweId(), e.cweTitle(), e.cvssVector()}).orElse(FALLBACK);
    }

    public static String cweId(String moduleId) {
        return forModule(moduleId)[0];
    }

    public static String cweTitle(String moduleId) {
        return forModule(moduleId)[1];
    }

    public static String cvssVector(String moduleId) {
        return forModule(moduleId)[2];
    }
}
