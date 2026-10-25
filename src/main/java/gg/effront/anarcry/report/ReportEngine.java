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

    public String exportH1(List<Finding> findings, String targetUrl, String programName) throws IOException {
        String date = LocalDate.now().toString();
        StringBuilder sb = new StringBuilder();
        for (Finding f : findings) {
            sb.append("# [").append(f.severity()).append("] ").append(f.title()).append("\n\n");
            sb.append("**Program:** ").append(programName).append("\n");
            sb.append("**Asset:** ").append(targetUrl).append("\n");
            sb.append("**Severity:** ").append(h1SeverityLabel(f)).append(" (CVSS ")
                    .append(String.format("%.1f", f.cvssScore())).append(" — ").append(f.cvssVector()).append(")\n");
            sb.append("**Weakness:** ").append(f.cweId()).append(" — ").append(f.cweTitle()).append("\n\n");

            sb.append("## Summary\n");
            sb.append(f.impact()).append("\n\n");

            sb.append("## Description\n");
            sb.append(f.evidence()).append("\n\n");

            sb.append("## Steps to Reproduce\n");
            sb.append("```\n").append(f.reproduction()).append("\n```\n\n");

            sb.append("## Supporting Material\n");
            sb.append("- Scanner: AnarCry\n");
            sb.append("- Date: ").append(date).append("\n");
            String evidSnippet = f.evidence() != null && f.evidence().length() > 200
                    ? f.evidence().substring(0, 200)
                    : f.evidence();
            sb.append("- ").append(evidSnippet).append("\n\n");

            sb.append("## Impact\n");
            sb.append(f.impact()).append("\n\n");
            sb.append("---\n\n");
        }
        String markdown = sb.toString();
        String timestamp = LocalDateTime.now().format(FMT);
        Files.writeString(Path.of("h1-report-" + timestamp + ".md"), markdown);
        return markdown;
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
            Map.entry("SSRF", "server_security_misconfiguration.server_side_request_forgery"),
            Map.entry("CORS", "broken_authentication_and_session_management.authentication_bypass.other"),
            Map.entry("IDOR", "broken_access_control.insecure_direct_object_references"),
            Map.entry("JWT",
                    "broken_authentication_and_session_management.authentication_bypass.json_web_token_vulnerability"),
            Map.entry("CRLF", "cross_site_scripting_xss.reflected_xss"),
            Map.entry("ReqSmuggling", "server_security_misconfiguration.http_request_smuggling"),
            Map.entry("XSS", "cross_site_scripting_xss.reflected_xss"), Map.entry("SQLi", "injection.sql_injection"),
            Map.entry("LFI", "server_security_misconfiguration.path_traversal"),
            Map.entry("CmdInjection", "injection.remote_code_execution.command_injection"),
            Map.entry("SSTI", "injection.remote_code_execution.server_side_template_injection"),
            Map.entry("XXE", "injection.xml_external_entity_injection"),
            Map.entry("MassAssign", "broken_access_control.mass_assignment"),
            Map.entry("CachePoisoning", "server_security_misconfiguration.web_cache_poisoning"),
            Map.entry("HostHeader", "server_security_misconfiguration.host_header_injection"),
            Map.entry("OpenRedirect", "broken_authentication_and_session_management.open_redirect"),
            Map.entry("TLS", "cryptography_issues.weak_tls"),
            Map.entry("Headers", "server_security_misconfiguration.missing_security_headers"),
            Map.entry("OAuth", "broken_authentication_and_session_management.oauth_misconfiguration"),
            Map.entry("GraphQL", "server_security_misconfiguration.graphql_misconfiguration"),
            Map.entry("Actuator", "server_security_misconfiguration.sensitive_data_exposure"));

    public String exportBugcrowd(List<Finding> findings, String targetUrl) throws IOException {
        StringBuilder sb = new StringBuilder();
        for (Finding f : findings) {
            String vrt = VRT.getOrDefault(f.module(), "other");
            String evidenceSnippet = f.evidence() != null && f.evidence().length() > 300
                    ? f.evidence().substring(0, 300)
                    : f.evidence();

            sb.append("## ").append(f.title()).append("\n\n");
            sb.append("**Classification:** ").append(vrt).append("\n");
            sb.append("**Proof of Concept:** ").append(f.reproduction()).append("\n");

            sb.append("**Replication Steps:**\n");
            String[] steps = f.reproduction().split("\n");
            for (int i = 0; i < steps.length; i++) {
                String step = steps[i].trim();
                if (!step.isBlank()) {
                    sb.append(i + 1).append(". ").append(step).append("\n");
                }
            }

            sb.append("**Impact:** ").append(f.impact()).append("\n");
            sb.append("**Evidence:** ").append(evidenceSnippet).append("\n\n");
            sb.append("---\n\n");
        }
        String markdown = sb.toString();
        String timestamp = LocalDateTime.now().format(FMT);
        Files.writeString(Path.of("bugcrowd-report-" + timestamp + ".md"), markdown);
        return markdown;
    }

    // -------------------------------------------------------------------------
    // Unified platform export
    // -------------------------------------------------------------------------

    public String exportPlatform(List<Finding> findings, String targetUrl, String platform, String programName)
            throws IOException {
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
