package gg.effront.anarcry.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public class ReportEngine {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final List<Severity> ORDER = List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
            Severity.INFO);

    public String export(List<Finding> findings, String targetUrl) throws IOException {
        String timestamp = LocalDateTime.now().format(FMT);
        String base = "anarcry-report-" + timestamp;

        List<Finding> sorted = findings.stream().sorted(Comparator.comparingInt(f -> ORDER.indexOf(f.severity())))
                .toList();

        Path mdPath = Path.of(base + ".md");
        Path jsonPath = Path.of(base + ".json");

        Files.writeString(mdPath, buildMarkdown(sorted, targetUrl, timestamp));
        Files.writeString(jsonPath, toJson(sorted));

        return mdPath.toString();
    }

    public String toJson(List<Finding> findings) {
        List<Finding> sorted = findings.stream().sorted(Comparator.comparingInt(f -> ORDER.indexOf(f.severity())))
                .toList();
        return GSON.toJson(sorted);
    }

    private String buildMarkdown(List<Finding> findings, String targetUrl, String timestamp) {
        StringBuilder sb = new StringBuilder();
        sb.append("# AnarCry Report\n\n");
        sb.append("**Target:** ").append(targetUrl).append("  \n");
        sb.append("**Data:** ").append(timestamp).append("  \n");
        sb.append("**Total findings:** ").append(findings.size()).append("\n\n");

        sb.append("## Resumo\n\n");
        for (Severity s : ORDER) {
            long count = findings.stream().filter(f -> f.severity() == s).count();
            if (count > 0) {
                sb.append("- **").append(s).append("**: ").append(count).append("\n");
            }
        }
        sb.append("\n");

        sb.append("## Findings\n\n");
        sb.append("| Severity | CVSS | CWE | Module | Endpoint | Title | Evidence | Recommendation |\n");
        sb.append("|----------|------|-----|--------|----------|-------|----------|----------------|\n");
        for (Finding f : findings) {
            sb.append("| ").append(f.severity()).append(" | ").append(f.cvssScore()).append(" | ")
                    .append(escape(f.cweId())).append(" | ").append(escape(f.module())).append(" | ")
                    .append(escape(f.endpoint())).append(" | ").append(escape(f.title())).append(" | ")
                    .append(escape(f.evidence())).append(" | ").append(escape(f.recommendation())).append(" |\n");
        }
        sb.append("\n");

        sb.append("## Detalhes\n\n");
        for (Finding f : findings) {
            sb.append("### [").append(f.severity()).append("] ").append(f.title()).append("\n\n");
            sb.append("**Módulo:** ").append(f.module()).append("  \n");
            sb.append("**Endpoint:** ").append(f.endpoint()).append("  \n");
            sb.append("**Evidência:** ").append(f.evidence()).append("  \n");
            sb.append("**Impacto:** ").append(f.impact()).append("  \n");
            sb.append("**Reprodução:**\n```\n").append(f.reproduction()).append("\n```\n");
            sb.append("**Recomendação:** ").append(f.recommendation()).append("  \n");
            sb.append("**CWE:** ").append(f.cweId()).append(" — ").append(f.cweTitle()).append("  \n");
            sb.append("**CVSS v3.1:** ").append(f.cvssScore()).append(" (").append(f.cvssVector()).append(")  \n");
            sb.append("\n---\n\n");
        }
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // HackerOne export
    // -------------------------------------------------------------------------

    public String exportH1(List<Finding> findings, String targetUrl, String programName) {
        String date = LocalDate.now().toString();
        StringBuilder sb = new StringBuilder();
        for (Finding f : findings) {
            sb.append("# [").append(f.severity()).append("] ").append(f.title()).append("\n\n");
            sb.append("**Program:** ").append(programName).append("\n");
            sb.append("**Asset:** ").append(targetUrl).append("\n");
            sb.append("**Severity:** ").append(h1SeverityLabel(f)).append(" (CVSS ")
                    .append(String.format("%.1f", f.cvssScore())).append(" — ").append(f.cvssVector()).append(")\n");
            sb.append("**Weakness:** ").append(f.cweId()).append(" — ").append(f.cweTitle()).append("\n");
            sb.append("**Reported:** ").append(date).append("\n\n");

            sb.append("## Summary\n");
            sb.append(f.impact()).append("\n\n");

            sb.append("## Description\n");
            sb.append(f.module()).append(" detectou ").append(f.title()).append(" em ").append(f.endpoint())
                    .append(".\n\n");
            sb.append(f.evidence()).append("\n\n");

            sb.append("## Steps to Reproduce\n");
            sb.append("```\n").append(f.reproduction()).append("\n```\n\n");

            sb.append("## Impact\n");
            sb.append(f.impact()).append("\n\n");

            sb.append("## Supporting Material\n");
            sb.append("- Scanner: AnarCry v1.0\n");
            sb.append("- Module: ").append(f.module()).append("\n");
            sb.append("- Endpoint: ").append(f.endpoint()).append("\n");
            sb.append("---\n\n");
        }
        return sb.toString();
    }

    private String h1SeverityLabel(Finding f) {
        return switch (f.severity()) {
            case CRITICAL -> "Critical";
            case HIGH -> "High";
            case MEDIUM -> "Medium";
            case LOW -> "Low";
            case INFO -> "Informational";
        };
    }

    // -------------------------------------------------------------------------
    // Bugcrowd export
    // -------------------------------------------------------------------------

    private static final Map<String, String> VRT = Map.ofEntries(
            Map.entry("SSRF", "Server Security Misconfiguration > SSRF"),
            Map.entry("CORS", "Broken Access Control > CORS Misconfiguration"),
            Map.entry("IDOR", "Broken Access Control > IDOR"),
            Map.entry("JWT", "Broken Authentication > JWT Vulnerability"),
            Map.entry("ReqSmuggling", "Server Security Misconfiguration > HTTP Request Smuggling"),
            Map.entry("SSTI", "Injection > Server-Side Template Injection"), Map.entry("XXE", "Injection > XXE"),
            Map.entry("MassAssign", "Broken Access Control > Mass Assignment"),
            Map.entry("CachePoisoning", "Server Security Misconfiguration > Web Cache Poisoning"),
            Map.entry("CRLF", "Injection > CRLF Injection"),
            Map.entry("HostHeader", "Server Security Misconfiguration > Host Header Injection"),
            Map.entry("OpenRedirect", "Broken Authentication > Open Redirect"),
            Map.entry("TLS", "Cryptography > Weak TLS Configuration"),
            Map.entry("Headers", "Server Security Misconfiguration > Security Headers"),
            Map.entry("OAuth", "Broken Authentication > OAuth Misconfiguration"),
            Map.entry("GraphQL", "Server Security Misconfiguration > GraphQL Misconfiguration"),
            Map.entry("Actuator", "Server Security Misconfiguration > Sensitive Data Exposure"));

    public String exportBugcrowd(List<Finding> findings, String targetUrl) {
        StringBuilder sb = new StringBuilder();
        for (Finding f : findings) {
            String vrt = VRT.getOrDefault(f.module(), "Other > Vulnerability");
            String evidenceSnippet = f.evidence() != null && f.evidence().length() > 200
                    ? f.evidence().substring(0, 200)
                    : f.evidence();

            sb.append("# BUG REPORT — ").append(f.title()).append("\n\n");
            sb.append("**Target:** ").append(targetUrl).append("\n");
            sb.append("**Classification:** ").append(vrt).append("\n");
            sb.append("**Severity:** ").append(String.format("%.1f", f.cvssScore())).append(" (").append(f.severity())
                    .append(")\n");
            sb.append("**CWE:** ").append(f.cweId()).append("\n\n");

            sb.append("## Description\n");
            sb.append(f.impact()).append(". ").append(f.title()).append(" detectado em ").append(f.endpoint())
                    .append(".\n\n");

            sb.append("## Proof of Concept\n");
            sb.append("```\n").append(f.reproduction()).append("\n```\n\n");

            sb.append("## Replication Steps\n");
            sb.append("1. Autentique no alvo\n");
            sb.append("2. Execute o PoC acima\n");
            sb.append("3. Observe: ").append(evidenceSnippet).append("\n\n");

            sb.append("## Impact\n");
            sb.append(f.impact()).append("\n");
            sb.append("---\n\n");
        }
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Unified platform export
    // -------------------------------------------------------------------------

    public String exportPlatform(List<Finding> findings, String targetUrl, String platform, String programName) {
        return switch (platform.toLowerCase()) {
            case "h1" -> exportH1(findings, targetUrl, programName);
            case "bugcrowd" -> exportBugcrowd(findings, targetUrl);
            default ->
                throw new IllegalArgumentException("Unknown platform: " + platform + ". Use 'h1' or 'bugcrowd'.");
        };
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private String escape(String s) {
        return s == null ? "" : s.replace("|", "\\|").replace("\n", " ");
    }
}
