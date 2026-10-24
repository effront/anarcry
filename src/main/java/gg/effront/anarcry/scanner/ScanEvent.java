package gg.effront.anarcry.scanner;

public record ScanEvent(Type type, String moduleId, int index, int total) {
    public enum Type { SCAN_START, MODULE_START, MODULE_DONE, SCAN_DONE }
}
