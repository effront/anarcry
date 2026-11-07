package gg.effront.anarcry.apiclient.runner;

import gg.effront.anarcry.apiclient.model.AssertOp;
import gg.effront.anarcry.apiclient.model.Assertion;
import gg.effront.anarcry.apiclient.model.AssertionResult;
import gg.effront.anarcry.apiclient.model.ResponseData;
import gg.effront.anarcry.apiclient.vars.Interpolator;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class AssertionEngine {

    private final Interpolator interpolator;

    public AssertionEngine(Interpolator interpolator) {
        this.interpolator = interpolator;
    }

    public List<AssertionResult> evaluate(List<Assertion> assertions, ResponseData response, VariableStore vars) {
        if (assertions == null || assertions.isEmpty()) {
            return Collections.emptyList();
        }
        List<AssertionResult> results = new ArrayList<>(assertions.size());
        for (Assertion assertion : assertions) {
            if (!assertion.enabled()) {
                continue;
            }
            results.add(evaluateOne(assertion, response, vars));
        }
        return results;
    }

    private AssertionResult evaluateOne(Assertion assertion, ResponseData response, VariableStore vars) {
        String lhs = interpolator.interpolate(assertion.lhs(), vars);
        String actual = resolveLhs(lhs, response);
        String expected = assertion.rhs() != null ? interpolator.interpolate(assertion.rhs(), vars) : null;

        try {
            boolean passed = check(assertion.op(), actual, expected);
            if (passed) {
                return AssertionResult.pass(assertion, actual);
            }
            String msg = formatFailure(assertion.op(), actual, expected);
            return AssertionResult.fail(assertion, actual, msg);
        } catch (Exception e) {
            return AssertionResult.fail(assertion, actual, "Error: " + e.getMessage());
        }
    }

    private String resolveLhs(String expression, ResponseData response) {
        if (expression.equals("res.status")) {
            return String.valueOf(response.status());
        }
        if (expression.equals("res.statusText")) {
            return response.statusText();
        }
        if (expression.equals("res.responseTime")) {
            return String.valueOf(response.responseTimeMs());
        }
        if (expression.equals("res.body")) {
            return response.body();
        }
        if (expression.equals("res.body.length")) {
            return String.valueOf(response.body().length());
        }
        if (expression.startsWith("res.headers.")) {
            String headerName = expression.substring("res.headers.".length());
            String val = response.header(headerName);
            return val != null ? val : "";
        }
        if (expression.startsWith("res.body.")) {
            return extractJsonPath(response.body(), expression.substring("res.body.".length()));
        }
        return expression;
    }

    @SuppressWarnings("checkstyle:CyclomaticComplexity")
    private boolean check(AssertOp op, String actual, String expected) {
        return switch (op) {
            case EQ -> equals(actual, expected);
            case NEQ -> !equals(actual, expected);
            case GT -> compareNumeric(actual, expected) > 0;
            case GTE -> compareNumeric(actual, expected) >= 0;
            case LT -> compareNumeric(actual, expected) < 0;
            case LTE -> compareNumeric(actual, expected) <= 0;
            case IN -> expected != null && expected.contains(actual);
            case NOT_IN -> expected == null || !expected.contains(actual);
            case CONTAINS -> actual != null && expected != null && actual.contains(expected);
            case NOT_CONTAINS -> actual == null || expected == null || !actual.contains(expected);
            case LENGTH -> actual != null && expected != null && String.valueOf(actual.length()).equals(expected);
            case MATCHES -> matchesRegex(actual, expected);
            case NOT_MATCHES -> !matchesRegex(actual, expected);
            case STARTS_WITH -> actual != null && expected != null && actual.startsWith(expected);
            case ENDS_WITH -> actual != null && expected != null && actual.endsWith(expected);
            case BETWEEN -> checkBetween(actual, expected);
            case IS_NULL -> actual == null || actual.equals("null");
            case IS_UNDEFINED -> actual == null || actual.isEmpty();
            case IS_DEFINED -> actual != null && !actual.isEmpty();
            case IS_TRUTHY -> isTruthy(actual);
            case IS_FALSY -> !isTruthy(actual);
            case IS_JSON -> isValidJson(actual);
            case IS_NUMBER -> isNumeric(actual);
            case IS_STRING -> actual != null;
            case IS_BOOLEAN -> "true".equalsIgnoreCase(actual) || "false".equalsIgnoreCase(actual);
            case IS_ARRAY -> actual != null && actual.trim().startsWith("[");
            case IS_EMPTY -> actual == null || actual.isEmpty() || actual.equals("[]") || actual.equals("{}");
            case IS_NOT_EMPTY -> actual != null && !actual.isEmpty() && !actual.equals("[]") && !actual.equals("{}");
        };
    }

    private boolean equals(String a, String b) {
        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        if (a.equals(b)) {
            return true;
        }
        if (isNumeric(a) && isNumeric(b)) {
            return Double.parseDouble(a) == Double.parseDouble(b);
        }
        return false;
    }

    private int compareNumeric(String a, String b) {
        double da = parseDouble(a);
        double db = parseDouble(b);
        return Double.compare(da, db);
    }

    private boolean matchesRegex(String actual, String pattern) {
        if (actual == null || pattern == null) {
            return false;
        }
        try {
            return Pattern.matches(pattern, actual);
        } catch (PatternSyntaxException e) {
            return false;
        }
    }

    private boolean checkBetween(String actual, String range) {
        if (actual == null || range == null) {
            return false;
        }
        String[] parts = range.split(",", 2);
        if (parts.length != 2) {
            return false;
        }
        double val = parseDouble(actual);
        double lo = parseDouble(parts[0].trim());
        double hi = parseDouble(parts[1].trim());
        return val >= lo && val <= hi;
    }

    private boolean isTruthy(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        return !"false".equalsIgnoreCase(value) && !"0".equals(value) && !"null".equalsIgnoreCase(value);
    }

    private boolean isValidJson(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String trimmed = value.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    private boolean isNumeric(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        try {
            Double.parseDouble(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private double parseDouble(String value) {
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException | NullPointerException e) {
            return 0;
        }
    }

    private String extractJsonPath(String json, String path) {
        if (json == null || json.isBlank()) {
            return "";
        }
        String[] keys = path.split("\\.");
        String current = json.trim();
        for (String key : keys) {
            if (key.matches("\\d+")) {
                current = extractArrayElement(current, Integer.parseInt(key));
            } else {
                current = extractJsonField(current, key);
            }
            if (current == null) {
                return "";
            }
        }
        if (current.startsWith("\"") && current.endsWith("\"")) {
            return current.substring(1, current.length() - 1);
        }
        return current;
    }

    private String extractJsonField(String json, String field) {
        String needle = "\"" + field + "\"";
        int idx = json.indexOf(needle);
        if (idx < 0) {
            return null;
        }
        int colonIdx = json.indexOf(':', idx + needle.length());
        if (colonIdx < 0) {
            return null;
        }
        return extractValue(json, colonIdx + 1);
    }

    private String extractArrayElement(String json, int index) {
        String trimmed = json.trim();
        if (!trimmed.startsWith("[")) {
            return null;
        }
        int depth = 0;
        int elementStart = -1;
        int currentIndex = 0;
        int pos = 1;

        while (pos < trimmed.length()) {
            char c = trimmed.charAt(pos);
            if (c == '"') {
                pos = skipString(trimmed, pos) + 1;
                if (elementStart < 0) {
                    elementStart = pos;
                }
                continue;
            }
            if (c == '{' || c == '[') {
                if (elementStart < 0) {
                    elementStart = pos;
                }
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
                if (depth < 0) {
                    if (currentIndex == index && elementStart >= 0) {
                        return trimmed.substring(elementStart, pos).trim();
                    }
                    return null;
                }
            } else if (c == ',' && depth == 0) {
                if (currentIndex == index && elementStart >= 0) {
                    return trimmed.substring(elementStart, pos).trim();
                }
                currentIndex++;
                elementStart = -1;
            } else if (!Character.isWhitespace(c) && elementStart < 0) {
                elementStart = pos;
            }
            pos++;
        }
        return null;
    }

    private int skipString(String json, int openQuote) {
        int pos = openQuote + 1;
        while (pos < json.length()) {
            char c = json.charAt(pos);
            if (c == '\\') {
                pos += 2;
                continue;
            }
            if (c == '"') {
                return pos;
            }
            pos++;
        }
        return json.length() - 1;
    }

    private String extractValue(String json, int start) {
        int i = start;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
            i++;
        }
        if (i >= json.length()) {
            return null;
        }
        char c = json.charAt(i);
        if (c == '"') {
            int end = skipString(json, i);
            return json.substring(i, end + 1);
        }
        if (c == '{' || c == '[') {
            int depth = 1;
            int j = i + 1;
            char close = c == '{' ? '}' : ']';
            while (j < json.length() && depth > 0) {
                char ch = json.charAt(j);
                if (ch == '"') {
                    j = skipString(json, j);
                } else if (ch == '{' || ch == '[') {
                    depth++;
                } else if (ch == '}' || ch == ']') {
                    depth--;
                }
                j++;
            }
            return json.substring(i, j).trim();
        }
        int end = i;
        while (end < json.length()) {
            char ch = json.charAt(end);
            if (ch == ',' || ch == '}' || ch == ']' || Character.isWhitespace(ch)) {
                break;
            }
            end++;
        }
        return json.substring(i, end);
    }

    private String formatFailure(AssertOp op, String actual, String expected) {
        if (op.isUnary()) {
            return "Expected " + op.symbol() + " but got: " + actual;
        }
        return "Expected " + op.symbol() + " " + expected + " but got: " + actual;
    }
}
