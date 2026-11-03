package gg.effront.anarcry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public record EnvLoader(String target, String jwt1, String jwt2, String scopeHosts, String sessionCookie,
        String assistantProvider, String assistantApiKey, String assistantModel, int assistantMaxTokens) {

    public static EnvLoader load(String path) throws IOException {
        Map<String, String> map = new HashMap<>();
        for (String rawLine : Files.readAllLines(Paths.get(path))) {
            String line = rawLine.strip();
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            int sepColon = line.indexOf(':');
            int sepEquals = line.indexOf('=');
            int sep;
            if (sepColon < 1 && sepEquals < 1) {
                continue;
            } else if (sepColon < 1) {
                sep = sepEquals;
            } else if (sepEquals < 1) {
                sep = sepColon;
            } else {
                sep = Math.min(sepColon, sepEquals);
            }
            String key = line.substring(0, sep).strip().toLowerCase();
            String val = line.substring(sep + 1).strip();
            map.put(key, val);
        }
        String target = normalize(map.getOrDefault("target", ""));
        String jwt1 = map.getOrDefault("jwt1", "");
        String jwt2 = map.getOrDefault("jwt2", "");
        String scopeHosts = map.getOrDefault("scope_hosts", "");
        String sessionCookie = map.getOrDefault("session_cookie", "");
        String assistantProvider = map.getOrDefault("assistant_provider", "");
        String assistantApiKey = map.getOrDefault("assistant_api_key", "");
        String assistantModel = map.getOrDefault("assistant_model", "");
        int assistantMaxTokens = parseIntOrDefault(map.getOrDefault("assistant_max_tokens", ""), 4096);
        return new EnvLoader(target, jwt1, jwt2, scopeHosts, sessionCookie, assistantProvider, assistantApiKey,
                assistantModel, assistantMaxTokens);
    }

    public boolean hasTarget() {
        return target != null && !target.isBlank();
    }

    public boolean hasAssistant() {
        return assistantProvider != null && !assistantProvider.isBlank();
    }

    public Map<String, String> asMap() {
        Map<String, String> m = new HashMap<>();
        m.put("target", target != null ? target : "");
        m.put("jwt1", jwt1 != null ? jwt1 : "");
        m.put("jwt2", jwt2 != null ? jwt2 : "");
        m.put("scope_hosts", scopeHosts != null ? scopeHosts : "");
        m.put("session_cookie", sessionCookie != null ? sessionCookie : "");
        m.put("assistant_provider", assistantProvider != null ? assistantProvider : "");
        m.put("assistant_api_key", assistantApiKey != null ? assistantApiKey : "");
        m.put("assistant_model", assistantModel != null ? assistantModel : "");
        m.put("assistant_max_tokens", String.valueOf(assistantMaxTokens));
        return Collections.unmodifiableMap(m);
    }

    private static String normalize(String t) {
        if (t.isBlank()) {
            return t;
        }
        int comma = t.indexOf(',');
        if (comma > 0) {
            t = t.substring(0, comma).strip();
        }
        if (!t.startsWith("http://") && !t.startsWith("https://")) {
            return "https://" + t;
        }
        return t;
    }

    private static int parseIntOrDefault(String s, int defaultVal) {
        if (s == null || s.isBlank()) {
            return defaultVal;
        }
        try {
            return Integer.parseInt(s.strip());
        } catch (NumberFormatException e) {
            return defaultVal;
        }
    }
}
