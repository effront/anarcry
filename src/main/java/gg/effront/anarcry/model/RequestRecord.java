package gg.effront.anarcry.model;

import java.util.Map;

public record RequestRecord(String method, String url, int statusCode, long responseBodySize, long timestampMs,
        String moduleId, Map<String, String> responseHeaders, String responseBodySnippet) {

    private static final int MAX_SNIPPET = 8192;

    public RequestRecord(String method, String url, int statusCode, long responseBodySize, long timestampMs,
            String moduleId) {
        this(method, url, statusCode, responseBodySize, timestampMs, moduleId, Map.of(), "");
    }

    public RequestRecord {
        if (responseHeaders == null) {
            responseHeaders = Map.of();
        }
        if (responseBodySnippet == null) {
            responseBodySnippet = "";
        }
        if (responseBodySnippet.length() > MAX_SNIPPET) {
            responseBodySnippet = responseBodySnippet.substring(0, MAX_SNIPPET);
        }
    }

    public boolean hasBody() {
        return !responseBodySnippet.isEmpty();
    }
}
