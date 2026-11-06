package gg.effront.anarcry.apiclient.model;

import java.util.List;
import java.util.Map;

public record ResponseData(int status, String statusText, Map<String, List<String>> headers, String body,
        byte[] rawBody, long responseTimeMs, long size) {

    public ResponseData {
        if (statusText == null) {
            statusText = "";
        }
        if (headers == null) {
            headers = Map.of();
        }
        if (body == null) {
            body = "";
        }
    }

    public String header(String name) {
        List<String> values = headers.get(name);
        if (values == null) {
            for (var entry : headers.entrySet()) {
                if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                    values = entry.getValue();
                    break;
                }
            }
        }
        return values != null && !values.isEmpty() ? values.getFirst() : null;
    }
}
