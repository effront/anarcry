package gg.effront.anarcry.scanner.auth.harvester;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FormParser {

    private static final Pattern FORM_PATTERN = Pattern.compile("<form\\b([^>]*)>(.*?)</form>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern INPUT_PATTERN = Pattern.compile("<input\\b([^>]*)>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern ATTR_PATTERN = Pattern.compile(
            "(name|type|value|action|method)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", Pattern.CASE_INSENSITIVE);

    public record LoginForm(String action, String method, Map<String, String> hiddenFields, String usernameField,
            String passwordField) {
    }

    private FormParser() {
    }

    public static LoginForm findLoginForm(String pageSource, String baseUrl) {
        List<LoginForm> candidates = new ArrayList<>();
        Matcher formMatcher = FORM_PATTERN.matcher(pageSource);
        while (formMatcher.find()) {
            String formAttrs = formMatcher.group(1);
            String formBody = formMatcher.group(2);

            if (!hasPasswordInput(formBody)) {
                continue;
            }

            String action = extractAttr(formAttrs, "action");
            String method = extractAttr(formAttrs, "method");
            if (method == null || method.isBlank()) {
                method = "POST";
            }

            String resolvedAction = resolveAction(action, baseUrl);
            Map<String, String> hiddenFields = new LinkedHashMap<>();
            String usernameField = null;
            String passwordField = null;

            Matcher inputMatcher = INPUT_PATTERN.matcher(formBody);
            while (inputMatcher.find()) {
                String inputAttrs = inputMatcher.group(1);
                Map<String, String> attrs = parseAttrs(inputAttrs);
                String type = attrs.getOrDefault("type", "text").toLowerCase();
                String name = attrs.get("name");
                if (name == null || name.isBlank()) {
                    continue;
                }

                switch (type) {
                    case "hidden" -> hiddenFields.put(name, attrs.getOrDefault("value", ""));
                    case "password" -> passwordField = name;
                    case "text", "email", "tel" -> {
                        if (usernameField == null) {
                            usernameField = name;
                        }
                    }
                    default -> {
                    }
                }
            }

            if (passwordField != null) {
                if (usernameField == null) {
                    usernameField = guessUsernameField(hiddenFields);
                }
                candidates.add(new LoginForm(resolvedAction, method.toUpperCase(), hiddenFields, usernameField,
                        passwordField));
            }
        }

        return candidates.isEmpty() ? null : candidates.get(0);
    }

    public static boolean looksLikeLoginPage(String pageSource) {
        if (pageSource == null || pageSource.isBlank()) {
            return false;
        }
        Matcher formMatcher = FORM_PATTERN.matcher(pageSource);
        while (formMatcher.find()) {
            if (hasPasswordInput(formMatcher.group(2))) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasPasswordInput(String formBody) {
        return Pattern.compile("<input[^>]*type\\s*=\\s*[\"']password[\"'][^>]*>", Pattern.CASE_INSENSITIVE)
                .matcher(formBody).find();
    }

    private static String extractAttr(String tag, String attrName) {
        Pattern p = Pattern.compile(attrName + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))",
                Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(tag);
        if (m.find()) {
            return m.group(1) != null ? m.group(1) : m.group(2) != null ? m.group(2) : m.group(3);
        }
        return null;
    }

    private static Map<String, String> parseAttrs(String tag) {
        Map<String, String> result = new LinkedHashMap<>();
        Matcher m = ATTR_PATTERN.matcher(tag);
        while (m.find()) {
            String key = m.group(1).toLowerCase();
            String value = m.group(2) != null ? m.group(2) : m.group(3) != null ? m.group(3) : m.group(4);
            result.put(key, value != null ? value : "");
        }
        return result;
    }

    private static String resolveAction(String action, String baseUrl) {
        if (action == null || action.isBlank()) {
            return baseUrl;
        }
        if (action.startsWith("http://") || action.startsWith("https://")) {
            return action;
        }
        try {
            return URI.create(baseUrl).resolve(action).toString();
        } catch (Exception e) {
            return baseUrl;
        }
    }

    private static String guessUsernameField(Map<String, String> hiddenFields) {
        for (String key : hiddenFields.keySet()) {
            String lower = key.toLowerCase();
            if (lower.contains("user") || lower.contains("email") || lower.contains("login")) {
                return key;
            }
        }
        return "username";
    }
}
