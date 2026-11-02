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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ReportEngine {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final List<Severity> ORDER = List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
            Severity.INFO);
    private static final Path REPORTS_DIR = Path.of("docs", "reports");

    public String export(List<Finding> findings, String targetUrl) throws IOException {
        return export(findings, targetUrl, List.of(), List.of());
    }

    public String export(List<Finding> findings, String targetUrl, List<String> testedModules, List<String> testedClean)
            throws IOException {
        String timestamp = LocalDateTime.now().format(FMT);
        String base = "anarcry-report-" + timestamp;

        List<Finding> sorted = findings.stream().sorted(Comparator.comparingInt(f -> ORDER.indexOf(f.severity())))
                .toList();

        Files.createDirectories(REPORTS_DIR);
        Path mdPath = REPORTS_DIR.resolve(base + ".md");
        Path jsonPath = REPORTS_DIR.resolve(base + ".json");

        Files.writeString(mdPath, buildMarkdown(sorted, targetUrl, timestamp, testedModules, testedClean));
        Files.writeString(jsonPath, toJson(sorted));

        return mdPath.toString();
    }

    public String toJson(List<Finding> findings) {
        List<Finding> sorted = findings.stream().sorted(Comparator.comparingInt(f -> ORDER.indexOf(f.severity())))
                .toList();
        return GSON.toJson(sorted);
    }

    private String buildMarkdown(List<Finding> findings, String targetUrl, String timestamp, List<String> testedModules,
            List<String> testedClean) {
        StringBuilder sb = new StringBuilder();
        sb.append("# AnarCry Report\n\n");
        sb.append("**Target:** ").append(targetUrl).append("  \n");
        sb.append("**Date:** ").append(timestamp).append("  \n");
        sb.append("**Total findings:** ").append(findings.size()).append("  \n");
        sb.append("**Modules tested:** ").append(testedModules.size()).append("  \n");
        sb.append("**Modules clean:** ").append(testedClean.size()).append("\n\n");

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

        buildRootCauseSection(sb, findings);

        if (!testedClean.isEmpty()) {
            buildNegativeCompanions(sb, testedClean);
        }

        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Root cause grouping -- groups findings by module (shared vulnerability class)
    // and generates unified analysis with one remediation per root cause.
    // -------------------------------------------------------------------------

    private void buildRootCauseSection(StringBuilder sb, List<Finding> findings) {
        sb.append("## Root Cause Analysis\n\n");

        Map<String, List<Finding>> byModule = new LinkedHashMap<>();
        for (Finding f : findings) {
            byModule.computeIfAbsent(f.module(), k -> new ArrayList<>()).add(f);
        }

        Severity worstOverall = findings.stream().map(Finding::severity)
                .min(Comparator.comparingInt(s -> ORDER.indexOf(s))).orElse(Severity.INFO);
        Finding anchor = findings.stream().min(Comparator.comparingInt(f -> ORDER.indexOf(f.severity()))).orElse(null);

        if (anchor != null) {
            sb.append("**Severity anchor:** ").append(anchor.title()).append(" on `").append(anchor.endpoint())
                    .append("` (").append(anchor.severity()).append(", CVSS ").append(anchor.cvssScore())
                    .append(")  \n\n");
        }

        int rootCauseIdx = 1;
        for (var entry : byModule.entrySet()) {
            String module = entry.getKey();
            List<Finding> group = entry.getValue();
            Finding rep = group.getFirst();
            KnowledgeBase kb = KnowledgeBase.getInstance();
            KnowledgeEntry kbEntry = kb.byModule(module).orElse(null);

            sb.append("### Root Cause ").append(rootCauseIdx++).append(" -- ").append(module).append(" (")
                    .append(group.size()).append(" finding");
            if (group.size() != 1) {
                sb.append("s");
            }
            sb.append(")\n\n");

            String rootCauseDesc = kbEntry != null ? kbEntry.summary() : rep.impact();
            sb.append("**Root cause:** ").append(rootCauseDesc).append("  \n");
            sb.append("**CWE:** ").append(rep.cweId()).append(" -- ").append(rep.cweTitle()).append("  \n");
            sb.append("**CVSS v3.1:** ").append(rep.cvssScore()).append(" (").append(rep.cvssVector())
                    .append(")  \n\n");

            if (group.size() == 1) {
                sb.append("**Endpoint:** `").append(rep.endpoint()).append("`  \n");
                sb.append("**Evidence:** ").append(rep.evidence()).append("  \n");
            } else {
                sb.append("**Affected endpoints (").append(group.size()).append("):**\n\n");
                sb.append("| # | Endpoint | Title | Severity | Evidence |\n");
                sb.append("|---|----------|-------|----------|----------|\n");
                int idx = 1;
                for (Finding f : group) {
                    sb.append("| ").append(idx++).append(" | `").append(escape(f.endpoint())).append("` | ")
                            .append(escape(f.title())).append(" | ").append(f.severity()).append(" | ")
                            .append(escape(f.evidence())).append(" |\n");
                }
                sb.append("\n");
            }

            sb.append("**Impact:** ").append(kbEntry != null ? kbEntry.impact() : rep.impact()).append("  \n\n");

            sb.append("**Reproduction:**\n```\n").append(rep.reproduction()).append("\n```\n\n");

            sb.append("**Unified remediation:** ")
                    .append(kbEntry != null ? kbEntry.recommendation() : rep.recommendation());
            if (group.size() > 1) {
                sb.append(" Apply this fix across all ").append(group.size())
                        .append(" affected endpoints -- the root cause is shared.");
            }
            sb.append("  \n");

            appendCves(sb, module);
            sb.append("\n---\n\n");
        }

        if (byModule.size() > 1) {
            buildCorrelationNotes(sb, byModule, worstOverall);
        }
    }

    // -------------------------------------------------------------------------
    // Cross-finding correlation -- notes on how findings chain together
    // -------------------------------------------------------------------------

    private void buildCorrelationNotes(StringBuilder sb, Map<String, List<Finding>> byModule, Severity worst) {
        sb.append("### Cross-Finding Correlation\n\n");

        List<String> chains = new ArrayList<>();

        boolean hasIdor = byModule.containsKey("IDOR");
        boolean hasAuth = byModule.containsKey("JWT") || byModule.containsKey("OAuth");
        boolean hasSsrf = byModule.containsKey("SSRF");
        boolean hasXss = byModule.containsKey("XSS");
        boolean hasSqli = byModule.containsKey("SQLi");
        boolean hasOpenRedirect = byModule.containsKey("OpenRedirect");
        boolean hasCors = byModule.containsKey("CORS");
        boolean hasSsti = byModule.containsKey("SSTI");
        boolean hasSmuggling = byModule.containsKey("ReqSmuggling");
        boolean hasCachePoisoning = byModule.containsKey("CachePoisoning");
        boolean hasCrlf = byModule.containsKey("CRLF");

        if (hasIdor && hasAuth) {
            chains.add("IDOR + auth weakness: broken authentication compounds with IDOR "
                    + "to enable full cross-account access without valid credentials");
        }
        if (hasSsrf && hasIdor) {
            chains.add("SSRF + IDOR: server-side request forgery can be chained with "
                    + "IDOR to access internal resources scoped to other users");
        }
        if (hasXss && hasCors) {
            chains.add("XSS + CORS misconfiguration: reflected XSS from an allowed "
                    + "origin can exfiltrate data cross-origin via the permissive CORS policy");
        }
        if (hasOpenRedirect && hasAuth) {
            chains.add("Open Redirect + OAuth/JWT: redirect bypass can steal authorization "
                    + "codes or tokens during OAuth flows");
        }
        if (hasSqli && hasIdor) {
            chains.add("SQLi + IDOR: SQL injection can escalate an IDOR from read to "
                    + "write, enabling data modification across accounts");
        }
        if (hasSsti) {
            chains.add("SSTI with RCE: server-side template injection with confirmed "
                    + "code execution -- this alone is full server compromise");
        }
        if (hasSmuggling && hasCachePoisoning) {
            chains.add("Request Smuggling + Cache Poisoning: smuggling can poison "
                    + "the cache for all users, turning a single request into mass exploitation");
        }
        if (hasCrlf && hasCachePoisoning) {
            chains.add("CRLF + Cache Poisoning: header injection can poison cached "
                    + "responses with injected headers or XSS payloads");
        }
        if (hasSmuggling && hasXss) {
            chains.add("Request Smuggling + XSS: smuggled requests can inject XSS "
                    + "payloads into other users' responses (stored XSS via smuggling)");
        }

        if (chains.isEmpty()) {
            sb.append("No direct attack chains identified between the finding groups. "
                    + "Each root cause should be remediated independently.\n\n");
        } else {
            sb.append("The following attack chains are possible by combining findings:\n\n");
            for (String chain : chains) {
                sb.append("- ").append(chain).append("\n");
            }
            sb.append("\n");
        }
    }

    // -------------------------------------------------------------------------
    // Negative companions -- modules that tested clean
    // -------------------------------------------------------------------------

    private void buildNegativeCompanions(StringBuilder sb, List<String> testedClean) {
        sb.append("## Tested and Secure\n\n");
        sb.append("The following modules were executed against the target and found ")
                .append("**no vulnerabilities**. This does not guarantee absence of issues, ")
                .append("but confirms that standard detection techniques for these classes ")
                .append("did not trigger.\n\n");
        sb.append("| Module | Vulnerability Class | Status |\n");
        sb.append("|--------|--------------------|---------|\n");
        KnowledgeBase kb = KnowledgeBase.getInstance();
        for (String moduleId : testedClean) {
            String vulnClass = kb.byModule(moduleId).map(KnowledgeEntry::title).orElse(moduleId);
            sb.append("| ").append(moduleId).append(" | ").append(escape(vulnClass)).append(" | Clean |\n");
        }
        sb.append("\n");
    }

    // -------------------------------------------------------------------------
    // HackerOne export
    // -------------------------------------------------------------------------

    public String exportH1(List<Finding> findings, String targetUrl, String programName) throws IOException {
        return exportH1(findings, targetUrl, programName, List.of(), List.of());
    }

    public String exportH1(List<Finding> findings, String targetUrl, String programName, List<String> testedModules,
            List<String> testedClean) throws IOException {
        String date = LocalDate.now().toString();
        KnowledgeBase kb = KnowledgeBase.getInstance();
        StringBuilder sb = new StringBuilder();

        Map<String, List<Finding>> rootCauses = new LinkedHashMap<>();
        for (Finding f : findings) {
            rootCauses.computeIfAbsent(f.module(), k -> new ArrayList<>()).add(f);
        }

        for (var entry : rootCauses.entrySet()) {
            String module = entry.getKey();
            List<Finding> group = entry.getValue();
            Finding rep = group.getFirst();
            KnowledgeEntry kbEntry = kb.byModule(module).orElse(null);
            String kbSummary = kbEntry != null ? kbEntry.summary() : rep.impact();
            String kbDescription = kbEntry != null ? kbEntry.description() : "";
            String kbImpact = kbEntry != null ? kbEntry.impact() : rep.impact();
            String kbRecommendation = kbEntry != null ? kbEntry.recommendation() : rep.recommendation();

            if (group.size() == 1) {
                sb.append("# [").append(rep.severity()).append("] ").append(rep.title()).append("\n\n");
            } else {
                sb.append("# [").append(rep.severity()).append("] ").append(module).append(": ").append(group.size())
                        .append(" findings, one root cause\n\n");
            }
            sb.append("**Program:** ").append(programName).append("\n");
            sb.append("**Asset:** ").append(targetUrl).append("\n");
            sb.append("**Severity:** ").append(h1SeverityLabel(rep)).append(" (CVSS ")
                    .append(String.format("%.1f", rep.cvssScore())).append(" -- ").append(rep.cvssVector())
                    .append(")\n");
            sb.append("**Weakness:** ").append(rep.cweId()).append(" -- ").append(rep.cweTitle()).append("\n\n");

            sb.append("## Summary\n\n");
            sb.append(kbSummary).append("\n\n");

            sb.append("## Description\n\n");
            sb.append(kbDescription).append("\n\n");

            sb.append("### Observed Evidence\n\n");
            if (group.size() == 1) {
                sb.append("**Endpoint:** `").append(rep.endpoint()).append("`\n\n");
                sb.append("```\n").append(safe(rep.evidence())).append("\n```\n\n");
            } else {
                for (int i = 0; i < group.size(); i++) {
                    Finding f = group.get(i);
                    sb.append("**Finding ").append(i + 1).append("** -- `").append(f.endpoint()).append("`  \n");
                    sb.append(f.title()).append("\n");
                    sb.append("```\n").append(safe(f.evidence())).append("\n```\n\n");
                }
                sb.append("**Root cause:** One shared vulnerability class (").append(rep.cweId()).append(") across ")
                        .append(group.size()).append(" endpoints. A single fix addresses all findings.\n\n");
            }

            sb.append("## Steps to Reproduce\n\n");
            sb.append("1. Navigate to the target asset: `").append(targetUrl).append("`\n");
            String[] reproLines = safe(rep.reproduction()).split("\n");
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
            if (group.size() == 1) {
                sb.append("**Affected endpoint:** `").append(rep.endpoint()).append("`\n\n");
            } else {
                sb.append("**Affected endpoints:** ")
                        .append(group.stream().map(f -> "`" + f.endpoint() + "`").collect(Collectors.joining(", ")))
                        .append("\n\n");
            }

            sb.append("## Mitigation\n\n");
            sb.append(kbRecommendation).append("\n\n");

            appendCvesH1(sb, module);

            sb.append("## Supporting Material\n\n");
            sb.append("- Scanner: AnarCry\n");
            sb.append("- Date: ").append(date).append("\n");
            sb.append("- Module: ").append(module).append("\n\n");

            sb.append("---\n\n");
        }

        if (!testedClean.isEmpty()) {
            sb.append("# Negative Companion -- Tested and Secure\n\n");
            sb.append("The following vulnerability classes were tested ")
                    .append("against the target and produced no findings:\n\n");
            for (String clean : testedClean) {
                String vulnClass = kb.byModule(clean).map(KnowledgeEntry::title).orElse(clean);
                sb.append("- **").append(clean).append("** -- ").append(vulnClass).append("\n");
            }
            sb.append("\n");
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
        return exportBugcrowd(findings, targetUrl, List.of(), List.of());
    }

    public String exportBugcrowd(List<Finding> findings, String targetUrl, List<String> testedModules,
            List<String> testedClean) throws IOException {
        KnowledgeBase kb = KnowledgeBase.getInstance();
        StringBuilder sb = new StringBuilder();

        Map<String, List<Finding>> rootCauses = new LinkedHashMap<>();
        for (Finding f : findings) {
            rootCauses.computeIfAbsent(f.module(), k -> new ArrayList<>()).add(f);
        }

        for (var entry : rootCauses.entrySet()) {
            String module = entry.getKey();
            List<Finding> group = entry.getValue();
            Finding rep = group.getFirst();
            KnowledgeEntry kbEntry = kb.byModule(module).orElse(null);
            String vrt = kbEntry != null ? kbEntry.vrtId() : "other";
            String kbSummary = kbEntry != null ? kbEntry.summary() : rep.impact();
            String kbImpact = kbEntry != null ? kbEntry.impact() : rep.impact();
            String kbRecommendation = kbEntry != null ? kbEntry.recommendation() : rep.recommendation();

            if (group.size() == 1) {
                sb.append("## ").append(rep.title()).append("\n\n");
            } else {
                sb.append("## ").append(module).append(": ").append(group.size())
                        .append(" findings, one root cause\n\n");
            }
            sb.append("**Classification (VRT):** `").append(vrt).append("`\n");
            sb.append("**Severity:** ").append(rep.severity()).append(" (CVSS ")
                    .append(String.format("%.1f", rep.cvssScore())).append(")\n");
            sb.append("**Weakness:** ").append(rep.cweId()).append(" -- ").append(rep.cweTitle()).append("\n");
            if (group.size() == 1) {
                sb.append("**Endpoint:** `").append(rep.endpoint()).append("`\n\n");
            } else {
                sb.append("**Endpoints:** ")
                        .append(group.stream().map(f -> "`" + f.endpoint() + "`").collect(Collectors.joining(", ")))
                        .append("\n\n");
            }

            sb.append("### Summary\n\n");
            sb.append(kbSummary).append("\n\n");

            sb.append("### Proof of Concept\n\n");
            if (group.size() == 1) {
                sb.append("**Evidence:**\n");
                sb.append("```\n").append(safe(rep.evidence())).append("\n```\n\n");
            } else {
                for (int i = 0; i < group.size(); i++) {
                    Finding f = group.get(i);
                    sb.append("**Finding ").append(i + 1).append("** -- `").append(f.endpoint()).append("`\n");
                    sb.append("```\n").append(safe(f.evidence())).append("\n```\n\n");
                }
            }
            sb.append("**Reproduction:**\n");
            sb.append("```\n").append(safe(rep.reproduction())).append("\n```\n\n");

            sb.append("### Replication Steps\n\n");
            String[] steps = safe(rep.reproduction()).split("\n");
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
            sb.append(kbRecommendation);
            if (group.size() > 1) {
                sb.append(" Apply this fix across all ").append(group.size())
                        .append(" affected endpoints -- the root cause is shared.");
            }
            sb.append("\n\n");

            appendCves(sb, module);

            sb.append("---\n\n");
        }

        if (!testedClean.isEmpty()) {
            sb.append("## Tested and Secure\n\n");
            for (String clean : testedClean) {
                String vulnClass = kb.byModule(clean).map(KnowledgeEntry::title).orElse(clean);
                sb.append("- **").append(clean).append("** -- ").append(vulnClass).append(": no findings\n");
            }
            sb.append("\n");
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
        return exportPlatform(findings, targetUrl, platform, programName, List.of(), List.of());
    }

    public String exportPlatform(List<Finding> findings, String targetUrl, String platform, String programName,
            List<String> testedModules, List<String> testedClean) throws IOException {
        return switch (platform.toLowerCase()) {
            case "h1" -> exportH1(findings, targetUrl, programName, testedModules, testedClean);
            case "bugcrowd" -> exportBugcrowd(findings, targetUrl, testedModules, testedClean);
            default ->
                throw new IllegalArgumentException("Unknown platform: " + platform + ". Use 'h1' or 'bugcrowd'.");
        };
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private void appendCves(StringBuilder sb, String module) {
        KnowledgeBase kb = KnowledgeBase.getInstance();
        List<KnowledgeEntry.CveEntry> cves = kb.byModule(module).map(KnowledgeEntry::notableCves).orElse(List.of());
        if (cves.isEmpty()) {
            return;
        }
        sb.append("\n**Known CVEs:**\n\n");
        sb.append("| CVE | Product | Year | Type |\n");
        sb.append("|-----|---------|------|------|\n");
        for (KnowledgeEntry.CveEntry c : cves) {
            sb.append("| ").append(c.cve()).append(" | ").append(escape(c.product())).append(" | ").append(c.year())
                    .append(" | ").append(escape(c.type())).append(" |\n");
        }
        sb.append("\n");
    }

    private void appendCvesH1(StringBuilder sb, String module) {
        KnowledgeBase kb = KnowledgeBase.getInstance();
        List<KnowledgeEntry.CveEntry> cves = kb.byModule(module).map(KnowledgeEntry::notableCves).orElse(List.of());
        if (cves.isEmpty()) {
            return;
        }
        sb.append("## Known CVEs\n\n");
        sb.append("This vulnerability class has been assigned multiple CVEs in widely-used products:\n\n");
        for (KnowledgeEntry.CveEntry c : cves) {
            sb.append("- **").append(c.cve()).append("** (").append(c.product()).append(", ").append(c.year())
                    .append("): ").append(c.description()).append("\n");
        }
        sb.append("\n");
    }

    private String escape(String s) {
        return s == null ? "" : s.replace("|", "\\|").replace("\n", " ");
    }

    private static String safe(String s) {
        return s == null ? "(no data)" : s;
    }
}
