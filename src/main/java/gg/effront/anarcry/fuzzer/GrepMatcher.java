package gg.effront.anarcry.fuzzer;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class GrepMatcher {

    private final List<CompiledRule> matchRules = new ArrayList<>();
    private final List<CompiledRule> extractRules = new ArrayList<>();

    public record GrepRule(String expression, boolean regex, boolean caseSensitive) {
    }

    private record CompiledRule(String expression, Pattern pattern) {
    }

    public void setMatchRules(List<GrepRule> rules) {
        matchRules.clear();
        for (GrepRule rule : rules) {
            matchRules.add(compile(rule));
        }
    }

    public void setExtractRules(List<GrepRule> rules) {
        extractRules.clear();
        for (GrepRule rule : rules) {
            extractRules.add(compile(rule));
        }
    }

    public int[] countMatches(String body) {
        if (body == null || matchRules.isEmpty()) {
            return new int[matchRules.size()];
        }
        int[] counts = new int[matchRules.size()];
        for (int i = 0; i < matchRules.size(); i++) {
            Matcher m = matchRules.get(i).pattern().matcher(body);
            while (m.find()) {
                counts[i]++;
            }
        }
        return counts;
    }

    public String[] extract(String body) {
        if (body == null || extractRules.isEmpty()) {
            return new String[extractRules.size()];
        }
        String[] results = new String[extractRules.size()];
        for (int i = 0; i < extractRules.size(); i++) {
            Matcher m = extractRules.get(i).pattern().matcher(body);
            if (m.find()) {
                results[i] = m.groupCount() > 0 ? m.group(1) : m.group();
            }
        }
        return results;
    }

    public List<String> matchLabels() {
        return matchRules.stream().map(CompiledRule::expression).toList();
    }

    public List<String> extractLabels() {
        return extractRules.stream().map(CompiledRule::expression).toList();
    }

    public int matchRuleCount() {
        return matchRules.size();
    }

    public int extractRuleCount() {
        return extractRules.size();
    }

    private static CompiledRule compile(GrepRule rule) {
        int flags = rule.caseSensitive() ? 0 : Pattern.CASE_INSENSITIVE;
        String expr = rule.regex() ? rule.expression() : Pattern.quote(rule.expression());
        return new CompiledRule(rule.expression(), Pattern.compile(expr, flags));
    }
}
