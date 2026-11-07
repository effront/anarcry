package gg.effront.anarcry.apiclient.model;

public record RunSummary(int total, int passed, int failed, int skipped, long totalDurationMs) {
}
