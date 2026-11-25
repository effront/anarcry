package gg.effront.anarcry.util;

import java.net.http.HttpRequest;

public final class HttpRequestUtil {

    private HttpRequestUtil() {
    }

    public static void applyMethod(HttpRequest.Builder builder, String method, String body) {
        boolean hasBody = body != null && !body.isBlank();
        switch (method.toUpperCase()) {
            case "GET" -> builder.GET();
            case "DELETE" -> builder.DELETE();
            case "HEAD" -> builder.method("HEAD", HttpRequest.BodyPublishers.noBody());
            case "OPTIONS" -> builder.method("OPTIONS", HttpRequest.BodyPublishers.noBody());
            case "POST" -> builder.POST(HttpRequest.BodyPublishers.ofString(hasBody ? body : ""));
            case "PUT" -> builder.PUT(HttpRequest.BodyPublishers.ofString(hasBody ? body : ""));
            case "PATCH" -> builder.method("PATCH", HttpRequest.BodyPublishers.ofString(hasBody ? body : ""));
            default -> builder.method(method,
                    hasBody ? HttpRequest.BodyPublishers.ofString(body) : HttpRequest.BodyPublishers.noBody());
        }
    }

    public static void applyHeaders(HttpRequest.Builder builder, String rawHeaders) {
        for (String line : rawHeaders.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int sep = trimmed.indexOf(':');
            if (sep > 0) {
                String key = trimmed.substring(0, sep).trim();
                String val = trimmed.substring(sep + 1).trim();
                builder.header(key, val);
            }
        }
    }

    public static String csvEscape(String s) {
        if (s == null) {
            return "";
        }
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }
}
