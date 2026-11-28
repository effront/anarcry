package gg.effront.anarcry.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import gg.effront.anarcry.Version;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.model.KnowledgeEntry;
import gg.effront.anarcry.model.Severity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds SARIF v2.1.0 output with support for multiple runs (AnarCry + ARTEX or
 * other tools).
 *
 * <p>
 * Each call to {@link #addAnarCryRun} or {@link #addArtexRun} appends a run to
 * the SARIF document. Call {@link #build()} to serialize the final JSON string.
 * </p>
 *
 * @see <a href=
 *      "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html">SARIF
 *      v2.1.0 spec</a>
 */
public class SarifBuilder {

    private static final String SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json";
    private static final String SARIF_VERSION = "2.1.0";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private final List<Map<String, Object>> runs = new ArrayList<>();

    public SarifBuilder() {
    }

    // -------------------------------------------------------------------------
    // AnarCry run
    // -------------------------------------------------------------------------

    /**
     * Adds a SARIF run for AnarCry findings.
     */
    public void addAnarCryRun(List<Finding> findings, String targetUrl) {
        Map<String, Object> run = new LinkedHashMap<>();

        // Tool descriptor
        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", "AnarCry");
        driver.put("version", Version.get());
        driver.put("informationUri", "https://github.com/effront/anarcry");

        // Rules -- one per unique CWE
        Map<String, Integer> ruleIndexMap = new LinkedHashMap<>();
        List<Map<String, Object>> rules = new ArrayList<>();
        for (Finding f : findings) {
            String ruleId = safe(f.cweId());
            if (!ruleIndexMap.containsKey(ruleId)) {
                ruleIndexMap.put(ruleId, rules.size());
                rules.add(buildRule(ruleId, f.cweTitle(), f.module()));
            }
        }
        driver.put("rules", rules);
        run.put("tool", Map.of("driver", driver));

        // Results
        List<Map<String, Object>> results = new ArrayList<>();
        for (Finding f : findings) {
            results.add(buildResult(f, ruleIndexMap));
        }
        run.put("results", results);

        // Invocation
        Map<String, Object> invocation = new LinkedHashMap<>();
        invocation.put("executionSuccessful", true);
        invocation.put("commandLine", "anarcry --target " + targetUrl);
        run.put("invocations", List.of(invocation));

        runs.add(run);
    }

    // -------------------------------------------------------------------------
    // ARTEX run
    // -------------------------------------------------------------------------

    /**
     * Adds a SARIF run for ARTEX findings from raw JSON objects.
     *
     * <p>
     * Expected fields per JsonObject: title, severity, endpoint, evidence, impact,
     * reproduction, recommendation, cweId, cweTitle, cvssScore, cvssVector, module.
     * </p>
     */
    public void addArtexRun(List<JsonObject> artexFindings) {
        Map<String, Object> run = new LinkedHashMap<>();

        // Tool descriptor
        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", "ARTEX");
        driver.put("version", "1.0.0");
        driver.put("informationUri", "https://github.com/effront/artex");

        // Rules -- one per unique CWE
        Map<String, Integer> ruleIndexMap = new LinkedHashMap<>();
        List<Map<String, Object>> rules = new ArrayList<>();
        for (JsonObject obj : artexFindings) {
            String ruleId = jsonStr(obj, "cweId", "CWE-0");
            if (!ruleIndexMap.containsKey(ruleId)) {
                ruleIndexMap.put(ruleId, rules.size());
                String cweTitle = jsonStr(obj, "cweTitle", ruleId);
                String module = jsonStr(obj, "module", "ARTEX");
                rules.add(buildRule(ruleId, cweTitle, module));
            }
        }
        driver.put("rules", rules);
        run.put("tool", Map.of("driver", driver));

        // Results
        List<Map<String, Object>> results = new ArrayList<>();
        for (JsonObject obj : artexFindings) {
            results.add(buildArtexResult(obj, ruleIndexMap));
        }
        run.put("results", results);

        // Invocation
        Map<String, Object> invocation = new LinkedHashMap<>();
        invocation.put("executionSuccessful", true);
        invocation.put("commandLine", "artex");
        run.put("invocations", List.of(invocation));

        runs.add(run);
    }

    // -------------------------------------------------------------------------
    // Build
    // -------------------------------------------------------------------------

    /**
     * Serializes the SARIF document to a JSON string.
     */
    public String build() {
        Map<String, Object> sarif = new LinkedHashMap<>();
        sarif.put("$schema", SARIF_SCHEMA);
        sarif.put("version", SARIF_VERSION);
        sarif.put("runs", runs);
        return GSON.toJson(sarif);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private static Map<String, Object> buildRule(String ruleId, String cweTitle, String module) {
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("id", ruleId);
        rule.put("shortDescription", Map.of("text", safe(cweTitle)));

        KnowledgeEntry kb = KnowledgeBase.getInstance().byModule(module).orElse(null);
        String helpText = kb != null && kb.recommendation() != null && !kb.recommendation().isBlank()
                ? kb.recommendation()
                : "See " + ruleId + " for remediation guidance.";
        rule.put("help", Map.of("text", helpText));

        // CWE help URI
        String cweNum = ruleId.replace("CWE-", "");
        rule.put("helpUri", "https://cwe.mitre.org/data/definitions/" + cweNum + ".html");

        Map<String, Object> props = new LinkedHashMap<>();
        List<String> tags = new ArrayList<>();
        tags.add("security");
        tags.add(ruleId);
        props.put("tags", tags);
        rule.put("properties", props);

        return rule;
    }

    private static Map<String, Object> buildResult(Finding f, Map<String, Integer> ruleIndexMap) {
        Map<String, Object> result = new LinkedHashMap<>();
        String ruleId = safe(f.cweId());
        result.put("ruleId", ruleId);
        Integer ri = ruleIndexMap.get(ruleId);
        if (ri != null) {
            result.put("ruleIndex", ri);
        }
        result.put("level", sarifLevel(f.severity()));
        result.put("message", Map.of("text", f.title() + " -- " + safe(f.evidence())));

        // Location
        Map<String, Object> artifactLocation = new LinkedHashMap<>();
        artifactLocation.put("uri", f.endpoint());
        result.put("locations", List.of(Map.of("physicalLocation", Map.of("artifactLocation", artifactLocation))));

        // Custom properties
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("module", f.module());
        props.put("severity", f.severity().name());
        props.put("cvssScore", f.cvssScore());
        props.put("cvssVector", safe(f.cvssVector()));
        props.put("evidence", safe(f.evidence()));
        props.put("impact", safe(f.impact()));
        props.put("reproduction", safe(f.reproduction()));
        result.put("properties", props);

        return result;
    }

    private static Map<String, Object> buildArtexResult(JsonObject obj, Map<String, Integer> ruleIndexMap) {
        Map<String, Object> result = new LinkedHashMap<>();
        String ruleId = jsonStr(obj, "cweId", "CWE-0");
        result.put("ruleId", ruleId);
        Integer ri = ruleIndexMap.get(ruleId);
        if (ri != null) {
            result.put("ruleIndex", ri);
        }

        String severityStr = jsonStr(obj, "severity", "MEDIUM").toUpperCase();
        Severity severity;
        try {
            severity = Severity.valueOf(severityStr);
        } catch (IllegalArgumentException e) {
            severity = Severity.MEDIUM;
        }
        result.put("level", sarifLevel(severity));

        String title = jsonStr(obj, "title", "ARTEX finding");
        String evidence = jsonStr(obj, "evidence", "");
        result.put("message", Map.of("text", title + " -- " + evidence));

        // Location
        String endpoint = jsonStr(obj, "endpoint", "");
        Map<String, Object> artifactLocation = new LinkedHashMap<>();
        artifactLocation.put("uri", endpoint);
        result.put("locations", List.of(Map.of("physicalLocation", Map.of("artifactLocation", artifactLocation))));

        // Custom properties
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("module", jsonStr(obj, "module", "ARTEX"));
        props.put("severity", severity.name());
        if (obj.has("cvssScore")) {
            props.put("cvssScore", obj.get("cvssScore").getAsDouble());
        }
        props.put("cvssVector", jsonStr(obj, "cvssVector", ""));
        props.put("evidence", evidence);
        props.put("impact", jsonStr(obj, "impact", ""));
        props.put("reproduction", jsonStr(obj, "reproduction", ""));
        result.put("properties", props);

        return result;
    }

    private static String sarifLevel(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW, INFO -> "note";
        };
    }

    private static String jsonStr(JsonObject obj, String key, String fallback) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return fallback;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
