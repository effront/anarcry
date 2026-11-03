package gg.effront.anarcry.assistant.tools;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.model.KnowledgeEntry;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ExplainCweTool implements AssistantTool {

    private static final Gson GSON = new Gson();

    private final KnowledgeBase kb;

    public ExplainCweTool(KnowledgeBase kb) {
        this.kb = kb;
    }

    @Override
    public String name() {
        return "explain_cwe";
    }

    @Override
    public String description() {
        return "Explains a CWE ID with description, CVSS vector, and related knowledge base entry";
    }

    @Override
    public String paramsSchema() {
        return """
                {
                  "type": "object",
                  "properties": {
                    "cwe_id": {
                      "type": "string",
                      "description": "CWE identifier, e.g. CWE-79, CWE-89"
                    }
                  },
                  "required": ["cwe_id"]
                }""";
    }

    @Override
    public String call(String paramsJson) {
        JsonObject params = GSON.fromJson(paramsJson, JsonObject.class);
        String cweId = params != null && params.has("cwe_id") ? params.get("cwe_id").getAsString() : "";

        String normalizedId = cweId.toUpperCase().startsWith("CWE-") ? cweId.toUpperCase() : "CWE-" + cweId;

        KnowledgeEntry matchedEntry = null;
        for (KnowledgeEntry entry : kb.all().values()) {
            if (normalizedId.equalsIgnoreCase(entry.cweId())) {
                matchedEntry = entry;
                break;
            }
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("cweId", normalizedId);

        if (matchedEntry != null) {
            response.put("cweTitle", matchedEntry.cweTitle());
            response.put("cvssVector", matchedEntry.cvssVector());
            response.put("cvssScore", CvssCalculator.calculate(matchedEntry.cvssVector()));
            response.put("severity", matchedEntry.severity());
            Map<String, String> kbEntry = new LinkedHashMap<>();
            kbEntry.put("title", matchedEntry.title());
            kbEntry.put("summary", matchedEntry.summary());
            kbEntry.put("impact", matchedEntry.impact());
            kbEntry.put("recommendation", matchedEntry.recommendation());
            response.put("kbEntry", kbEntry);
        } else {
            response.put("found", false);
            response.put("message", "No knowledge base entry found for " + normalizedId);
        }

        return GSON.toJson(response);
    }
}
