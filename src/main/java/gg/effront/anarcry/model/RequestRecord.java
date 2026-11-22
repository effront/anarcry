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

    public static String humanSize(long bytes) {
        if (bytes <= 0) {
            return "--";
        }
        if (bytes < 1024) {
            return bytes + "B";
        }
        return (bytes / 1024) + "KB";
    }

    public static String formatDetail(RequestRecord r) {
        StringBuilder sb = new StringBuilder();
        sb.append(r.method()).append(" ").append(r.url()).append("\n");
        sb.append("Status: ").append(r.statusCode());
        sb.append("  Size: ").append(humanSize(r.responseBodySize()));
        sb.append("  Module: ").append(r.moduleId()).append("\n\n");

        if (!r.responseHeaders().isEmpty()) {
            sb.append("--- Response Headers ---\n");
            for (var entry : r.responseHeaders().entrySet()) {
                sb.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
            sb.append("\n");
        }

        if (r.hasBody()) {
            sb.append("--- Response Body ---\n");
            sb.append(r.responseBodySnippet());
            if (r.responseBodySize() > r.responseBodySnippet().length()) {
                sb.append("\n\n[truncated -- ").append(humanSize(r.responseBodySize())).append(" total]");
            }
        } else {
            sb.append("[sem body capturado]");
        }

        return sb.toString();
    }
}
