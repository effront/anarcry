package gg.effront.anarcry.apiclient.vars;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Interpolator {

    private static final Pattern VAR_PATTERN = Pattern.compile("\\{\\{(.+?)}}");
    private static final int MAX_DEPTH = 10;

    public String interpolate(String template, VariableStore vars) {
        return interpolate(template, vars, new HashSet<>(), 0);
    }

    private String interpolate(String template, VariableStore vars, Set<String> visited, int depth) {
        if (template == null || depth > MAX_DEPTH || !template.contains("{{")) {
            return template;
        }

        Matcher matcher = VAR_PATTERN.matcher(template);
        if (!matcher.find()) {
            return template;
        }

        StringBuffer sb = new StringBuffer();
        matcher.reset();
        while (matcher.find()) {
            String key = matcher.group(1).trim();
            String replacement = resolveKey(key, vars, visited, depth);
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private String resolveKey(String key, VariableStore vars, Set<String> visited, int depth) {
        if (key.startsWith("$")) {
            String resolved = BuiltInFunctions.resolve(key.substring(1));
            return resolved != null ? resolved : "{{" + key + "}}";
        }

        if (key.startsWith("process.env.")) {
            String envVal = System.getenv(key.substring(12));
            return envVal != null ? envVal : "{{" + key + "}}";
        }

        if (visited.contains(key)) {
            return "{{" + key + "}}";
        }

        String value = vars.resolve(key);
        if (value == null) {
            return "{{" + key + "}}";
        }

        visited.add(key);
        String resolved = interpolate(value, vars, visited, depth + 1);
        visited.remove(key);
        return resolved;
    }

    public String interpolateUrl(String url, VariableStore vars) {
        String interpolated = interpolate(url, vars);
        int queryStart = interpolated.indexOf('?');
        if (queryStart < 0) {
            return interpolated;
        }
        String base = interpolated.substring(0, queryStart);
        String query = interpolated.substring(queryStart + 1);
        StringBuilder encoded = new StringBuilder(base).append('?');
        String[] pairs = query.split("&");
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) {
                encoded.append('&');
            }
            int eq = pairs[i].indexOf('=');
            if (eq < 0) {
                encoded.append(urlEncode(pairs[i]));
            } else {
                encoded.append(urlEncode(pairs[i].substring(0, eq)));
                encoded.append('=');
                encoded.append(urlEncode(pairs[i].substring(eq + 1)));
            }
        }
        return encoded.toString();
    }

    public Map<String, String> interpolateMap(Map<String, String> map, VariableStore vars) {
        if (map == null || map.isEmpty()) {
            return map;
        }
        Map<String, String> result = new LinkedHashMap<>(map.size());
        for (var entry : map.entrySet()) {
            result.put(entry.getKey(), interpolate(entry.getValue(), vars));
        }
        return result;
    }

    public String interpolateJson(String json, VariableStore vars) {
        if (json == null || !json.contains("{{")) {
            return json;
        }

        Matcher matcher = VAR_PATTERN.matcher(json);
        if (!matcher.find()) {
            return json;
        }

        Set<String> visited = new HashSet<>();
        StringBuffer sb = new StringBuffer();
        matcher.reset();
        while (matcher.find()) {
            String key = matcher.group(1).trim();
            String raw = resolveKey(key, vars, visited, 0);
            String escaped = escapeJson(raw);
            matcher.appendReplacement(sb, Matcher.quoteReplacement(escaped));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
