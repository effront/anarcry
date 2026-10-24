package gg.effront.anarcry.model;

public record RequestRecord(String method, String url, int statusCode, long responseBodySize, long timestampMs,
        String moduleId) {
}
