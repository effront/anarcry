package gg.effront.anarcry.scanner;

public record ScanEvent(Type type, String moduleId, int index, int total, int findingCount) {
    public enum Type {
        SCAN_START, MODULE_START, MODULE_DONE, FINDING_DISCOVERED, SCAN_DONE
    }

    /** Backward-compatible constructor -- defaults findingCount to 0. */
    public ScanEvent(Type type, String moduleId, int index, int total) {
        this(type, moduleId, index, total, 0);
    }
}
