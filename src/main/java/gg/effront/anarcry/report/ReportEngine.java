package gg.effront.anarcry.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.model.KnowledgeEntry;
import gg.effront.anarcry.model.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;

public class ReportEngine {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final List<Severity> ORDER = List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
            Severity.INFO);
    private static final Path REPORTS_DIR = Path.of("docs", "reports");

    public String export(List<Finding> findings, String targetUrl) throws IOException {
        String timestamp = LocalDateTime.now().format(FMT);
        String base = "anarcry-report-" + timestamp;

        List<Finding> sorted = findings.stream().sorted(Comparator.comparingInt(f -> ORDER.indexOf(f.severity())))
                .toList();

        Files.createDirectories(REPORTS_DIR);
        Path mdPath = REPORTS_DIR.resolve(base + ".md");
        Path jsonPath = REPORTS_DIR.resolve(base + ".json");

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
        sb.append("**Date:** ").append(timestamp).append("  \n");
        sb.append("**Total findings:** ").append(findings.size()).append("\n\n");

        sb.append("## Summary\n\n");
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

        sb.append("## Details\n\n");
        for (Finding f : findings) {
            sb.append("### [").append(f.severity()).append("] ").append(f.title()).append("\n\n");
            sb.append("**Module:** ").append(f.module()).append("  \n");
            sb.append("**Endpoint:** ").append(f.endpoint()).append("  \n");
            sb.append("**Evidence:** ").append(f.evidence()).append("  \n");
            sb.append("**Impact:** ").append(f.impact()).append("  \n");
            sb.append("**Reproduction:**\n```\n").append(f.reproduction()).append("\n```\n");
            sb.append("**Recommendation:** ").append(f.recommendation()).append("  \n");
            sb.append("**CWE:** ").append(f.cweId()).append(" -- ").append(f.cweTitle()).append("  \n");
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
        KnowledgeBase kb = KnowledgeBase.getInstance();
        StringBuilder sb = new StringBuilder();

        for (Finding f : findings) {
            KnowledgeEntry entry = kb.byModule(f.module()).orElse(null);
            String kbSummary = entry != null ? entry.summary() : f.impact();
            String kbDescription = entry != null ? entry.description() : "";
            String kbImpact = entry != null ? entry.impact() : f.impact();
            String kbRecommendation = entry != null ? entry.recommendation() : f.recommendation();

            sb.append("# [").append(f.severity()).append("] ").append(f.title()).append("\n\n");
            sb.append("**Program:** ").append(programName).append("\n");
            sb.append("**Asset:** ").append(targetUrl).append("\n");
            sb.append("**Severity:** ").append(h1SeverityLabel(f)).append(" (CVSS ")
                    .append(String.format("%.1f", f.cvssScore())).append(" -- ").append(f.cvssVector()).append(")\n");
            sb.append("**Weakness:** ").append(f.cweId()).append(" -- ").append(f.cweTitle()).append("\n\n");

            sb.append("## Summary\n\n");
            sb.append(kbSummary).append("\n\n");

            sb.append("## Description\n\n");
            sb.append(kbDescription).append("\n\n");
            sb.append("### Observed Evidence\n\n");
            sb.append("```\n").append(safe(f.evidence())).append("\n```\n\n");

            sb.append("## Steps to Reproduce\n\n");
            sb.append("1. Navigate to the target asset: `").append(targetUrl).append("`\n");
            String[] reproLines = safe(f.reproduction()).split("\n");
            int step = 2;
            for (String line : reproLines) {
                String trimmed = line.trim();
                if (!trimmed.isBlank()) {
                    sb.append(step++).append(". ").append(trimmed).append("\n");
                }
            }
            sb.append("\n");

            sb.append("## Impact\n\n");
            sb.append(kbImpact).append("\n\n");
            sb.append("**Affected endpoint:** `").append(f.endpoint()).append("`\n\n");

            sb.append("## Mitigation\n\n");
            sb.append(kbRecommendation).append("\n\n");

            sb.append("## Supporting Material\n\n");
            sb.append("- Scanner: AnarCry\n");
            sb.append("- Date: ").append(date).append("\n");
            sb.append("- Module: ").append(f.module()).append("\n\n");

            sb.append("---\n\n");
        }

        String markdown = sb.toString();
        String timestamp = LocalDateTime.now().format(FMT);
        Files.createDirectories(REPORTS_DIR);
        Path path = REPORTS_DIR.resolve("h1-report-" + timestamp + ".md");
        Files.writeString(path, markdown);
        return path.toString();
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

    public String exportBugcrowd(List<Finding> findings, String targetUrl) throws IOException {
        KnowledgeBase kb = KnowledgeBase.getInstance();
        StringBuilder sb = new StringBuilder();

        for (Finding f : findings) {
            KnowledgeEntry entry = kb.byModule(f.module()).orElse(null);
            String vrt = entry != null ? entry.vrtId() : "other";
            String kbSummary = entry != null ? entry.summary() : f.impact();
            String kbImpact = entry != null ? entry.impact() : f.impact();
            String kbRecommendation = entry != null ? entry.recommendation() : f.recommendation();

            sb.append("## ").append(f.title()).append("\n\n");
            sb.append("**Classification (VRT):** `").append(vrt).append("`\n");
            sb.append("**Severity:** ").append(f.severity()).append(" (CVSS ")
                    .append(String.format("%.1f", f.cvssScore())).append(")\n");
            sb.append("**Weakness:** ").append(f.cweId()).append(" -- ").append(f.cweTitle()).append("\n");
            sb.append("**Endpoint:** `").append(f.endpoint()).append("`\n\n");

            sb.append("### Summary\n\n");
            sb.append(kbSummary).append("\n\n");

            sb.append("### Proof of Concept\n\n");
            sb.append("**Evidence:**\n");
            sb.append("```\n").append(safe(f.evidence())).append("\n```\n\n");
            sb.append("**Reproduction:**\n");
            sb.append("```\n").append(safe(f.reproduction())).append("\n```\n\n");

            sb.append("### Replication Steps\n\n");
            String[] steps = safe(f.reproduction()).split("\n");
            int idx = 1;
            for (String line : steps) {
                String trimmed = line.trim();
                if (!trimmed.isBlank()) {
                    sb.append(idx++).append(". ").append(trimmed).append("\n");
                }
            }
            sb.append("\n");

            sb.append("### Impact\n\n");
            sb.append(kbImpact).append("\n\n");

            sb.append("### Remediation\n\n");
            sb.append(kbRecommendation).append("\n\n");

            sb.append("---\n\n");
        }

        String markdown = sb.toString();
        String timestamp = LocalDateTime.now().format(FMT);
        Files.createDirectories(REPORTS_DIR);
        Path path = REPORTS_DIR.resolve("bugcrowd-report-" + timestamp + ".md");
        Files.writeString(path, markdown);
        return path.toString();
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

    private static String safe(String s) {
        return s == null ? "(no data)" : s;
    }
}
