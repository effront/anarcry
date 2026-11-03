package gg.effront.anarcry.assistant.tools;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.model.KnowledgeEntry;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class QueryKbTool implements AssistantTool {

    private static final int MAX_RESULTS = 3;
    private static final Gson GSON = new Gson();

    private final KnowledgeBase kb;

    public QueryKbTool(KnowledgeBase kb) {
        this.kb = kb;
    }

    @Override
    public String name() {
        return "query_kb";
    }

    @Override
    public String description() {
        return "Searches the vulnerability knowledge base for a given topic";
    }

    @Override
    public String paramsSchema() {
        return """
                {
                  "type": "object",
                  "properties": {
                    "topic": {
                      "type": "string",
                      "description": "The vulnerability topic to search for, e.g. XSS, SQL injection, SSRF"
                    }
                  },
                  "required": ["topic"]
                }""";
    }

    @Override
    public String call(String paramsJson) {
        JsonObject params = GSON.fromJson(paramsJson, JsonObject.class);
        String topic = params != null && params.has("topic") ? params.get("topic").getAsString() : "";

        String lowerTopic = topic.toLowerCase();
        List<Map<String, Object>> results = kb.all().values().stream().filter(e -> matchesTopic(e, lowerTopic))
                .limit(MAX_RESULTS).map(QueryKbTool::toMap).collect(Collectors.toList());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("query", topic);
        response.put("count", results.size());
        response.put("entries", results);
        return GSON.toJson(response);
    }

    private static boolean matchesTopic(KnowledgeEntry entry, String lowerTopic) {
        return containsIgnoreCase(entry.title(), lowerTopic) || containsIgnoreCase(entry.module(), lowerTopic)
                || containsIgnoreCase(entry.summary(), lowerTopic) || containsIgnoreCase(entry.cweId(), lowerTopic)
                || containsIgnoreCase(entry.cweTitle(), lowerTopic);
    }

    private static boolean containsIgnoreCase(String haystack, String needle) {
        return haystack != null && haystack.toLowerCase().contains(needle);
    }

    private static Map<String, Object> toMap(KnowledgeEntry e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("title", e.title());
        m.put("module", e.module());
        m.put("cweId", e.cweId());
        m.put("severity", e.severity());
        m.put("summary", e.summary());
        m.put("impact", e.impact());
        m.put("recommendation", e.recommendation());
        List<Map<String, String>> cves = e.notableCves().stream().map(c -> {
            Map<String, String> cm = new LinkedHashMap<>();
            cm.put("cve", c.cve());
            cm.put("product", c.product());
            cm.put("description", c.description());
            return cm;
        }).collect(Collectors.toList());
        m.put("notableCves", cves);
        return m;
    }
}
