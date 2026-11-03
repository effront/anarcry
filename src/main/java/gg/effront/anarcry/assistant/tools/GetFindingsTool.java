package gg.effront.anarcry.assistant.tools;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public final class GetFindingsTool implements AssistantTool {

    private static final int MAX_FINDINGS = 50;
    private static final Gson GSON = new Gson();

    private final Supplier<List<Finding>> findingsSupplier;

    public GetFindingsTool(Supplier<List<Finding>> findingsSupplier) {
        this.findingsSupplier = findingsSupplier;
    }

    @Override
    public String name() {
        return "get_findings";
    }

    @Override
    public String description() {
        return "Returns current scan findings, optionally filtered by severity or module";
    }

    @Override
    public String paramsSchema() {
        return """
                {
                  "type": "object",
                  "properties": {
                    "severity": {
                      "type": "string",
                      "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"
                    },
                    "module": {
                      "type": "string",
                      "description": "Filter by module ID, e.g. SQLi, XSS, TLS"
                    }
                  }
                }""";
    }

    @Override
    public String call(String paramsJson) {
        JsonObject params = GSON.fromJson(paramsJson, JsonObject.class);
        String severityFilter = params != null && params.has("severity")
                ? params.get("severity").getAsString().toUpperCase()
                : null;
        String moduleFilter = params != null && params.has("module") ? params.get("module").getAsString() : null;

        Severity targetSeverity = null;
        if (severityFilter != null) {
            try {
                targetSeverity = Severity.valueOf(severityFilter);
            } catch (IllegalArgumentException ignored) {
                // invalid severity filter -- ignore
            }
        }

        Severity finalTargetSeverity = targetSeverity;
        List<Finding> findings = findingsSupplier.get();
        List<Map<String, Object>> result = findings.stream()
                .filter(f -> finalTargetSeverity == null || f.severity() == finalTargetSeverity)
                .filter(f -> moduleFilter == null || f.module().equalsIgnoreCase(moduleFilter)).limit(MAX_FINDINGS)
                .map(GetFindingsTool::toMap).collect(Collectors.toList());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("count", result.size());
        response.put("total", findings.size());
        response.put("findings", result);
        return GSON.toJson(response);
    }

    private static Map<String, Object> toMap(Finding f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("module", f.module());
        m.put("endpoint", f.endpoint());
        m.put("title", f.title());
        m.put("severity", f.severity().name());
        m.put("cweId", f.cweId());
        m.put("cvssScore", f.cvssScore());
        m.put("evidence", f.evidence());
        m.put("impact", f.impact());
        return m;
    }
}
