package gg.effront.anarcry.apiclient.report;

import gg.effront.anarcry.apiclient.model.AssertionResult;
import gg.effront.anarcry.apiclient.model.Header;
import gg.effront.anarcry.apiclient.model.RequestResult;
import gg.effront.anarcry.apiclient.model.RunResult;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

public class CollectionReportEngine {

    public String toMarkdown(RunResult result, String collectionName, String envName) {
        StringBuilder md = new StringBuilder();
        md.append("# API Collection Run: ").append(collectionName).append("\n\n");
        md.append("**Environment:** ").append(envName != null ? envName : "none").append("  \n");
        md.append("**Date:** ").append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
                .append("  \n");
        md.append("**Duration:** ").append(result.durationMs()).append("ms  \n");
        md.append("**Results:** ").append(result.summary().passed()).append("/").append(result.summary().total())
                .append(" passed, ").append(result.summary().failed()).append(" failed\n\n");

        md.append("---\n\n");

        for (int i = 0; i < result.results().size(); i++) {
            RequestResult rr = result.results().get(i);
            appendRequestResult(md, rr, i + 1);
        }

        return md.toString();
    }

    public String toJson(RunResult result) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"summary\": {\n");
        json.append("    \"total\": ").append(result.summary().total()).append(",\n");
        json.append("    \"passed\": ").append(result.summary().passed()).append(",\n");
        json.append("    \"failed\": ").append(result.summary().failed()).append(",\n");
        json.append("    \"durationMs\": ").append(result.durationMs()).append("\n");
        json.append("  },\n");
        json.append("  \"results\": [\n");

        for (int i = 0; i < result.results().size(); i++) {
            if (i > 0) {
                json.append(",\n");
            }
            appendRequestResultJson(json, result.results().get(i));
        }

        json.append("\n  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private void appendRequestResult(StringBuilder md, RequestResult rr, int index) {
        String icon = rr.passed() ? "[PASS]" : "[FAIL]";
        md.append("## ").append(index).append(". ").append(icon).append(" ").append(rr.item().name()).append("\n\n");

        md.append("**Request:**\n```\n");
        md.append(rr.interpolatedRequest().method()).append(" ").append(rr.interpolatedRequest().url()).append("\n");
        for (Header h : rr.interpolatedRequest().headers()) {
            md.append(h.name()).append(": ").append(h.value()).append("\n");
        }
        md.append("```\n\n");

        if (rr.response() != null) {
            md.append("**Response:** ").append(rr.response().status()).append(" ").append(rr.response().statusText())
                    .append(" (").append(rr.response().responseTimeMs()).append("ms)\n");

            String body = rr.response().body();
            if (body != null && !body.isEmpty()) {
                String truncated = body.length() > 2000 ? body.substring(0, 2000) + "\n... (truncated)" : body;
                md.append("```json\n").append(truncated).append("\n```\n\n");
            }
        }

        if (!rr.assertions().isEmpty()) {
            md.append("**Assertions:**\n\n");
            md.append("| Status | Expression | Actual |\n");
            md.append("|--------|-----------|--------|\n");
            for (AssertionResult ar : rr.assertions()) {
                String status = ar.passed() ? "PASS" : "FAIL";
                String expr = ar.assertion().lhs() + " " + ar.assertion().op().symbol();
                if (ar.assertion().rhs() != null) {
                    expr += " " + ar.assertion().rhs();
                }
                md.append("| ").append(status).append(" | ").append(expr).append(" | ").append(ar.actual())
                        .append(" |\n");
            }
            md.append("\n");
        }

        md.append("---\n\n");
    }

    private void appendRequestResultJson(StringBuilder json, RequestResult rr) {
        json.append("    {\n");
        json.append("      \"name\": \"").append(escapeJson(rr.item().name())).append("\",\n");
        json.append("      \"method\": \"").append(rr.interpolatedRequest().method()).append("\",\n");
        json.append("      \"url\": \"").append(escapeJson(rr.interpolatedRequest().url())).append("\",\n");
        json.append("      \"status\": ").append(rr.response() != null ? rr.response().status() : 0).append(",\n");
        json.append("      \"responseTimeMs\": ").append(rr.response() != null ? rr.response().responseTimeMs() : 0)
                .append(",\n");
        json.append("      \"passed\": ").append(rr.passed()).append(",\n");
        json.append("      \"durationMs\": ").append(rr.durationMs()).append(",\n");

        json.append("      \"assertions\": [");
        List<AssertionResult> assertions = rr.assertions();
        for (int j = 0; j < assertions.size(); j++) {
            if (j > 0) {
                json.append(",");
            }
            AssertionResult ar = assertions.get(j);
            json.append("{\"passed\":").append(ar.passed()).append(",\"actual\":\"").append(escapeJson(ar.actual()))
                    .append("\"");
            if (!ar.message().isEmpty()) {
                json.append(",\"message\":\"").append(escapeJson(ar.message())).append("\"");
            }
            json.append("}");
        }
        json.append("],\n");

        json.append("      \"responseHeaders\": {");
        if (rr.response() != null) {
            boolean first = true;
            for (Map.Entry<String, List<String>> entry : rr.response().headers().entrySet()) {
                if (entry.getKey() == null) {
                    continue;
                }
                if (!first) {
                    json.append(",");
                }
                json.append("\"").append(escapeJson(entry.getKey())).append("\":\"")
                        .append(escapeJson(String.join(", ", entry.getValue()))).append("\"");
                first = false;
            }
        }
        json.append("}\n");
        json.append("    }");
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t",
                "\\t");
    }
}
