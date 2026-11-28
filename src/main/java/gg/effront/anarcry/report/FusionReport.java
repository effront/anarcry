package gg.effront.anarcry.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Generates a unified report that combines AnarCry scanner findings with ARTEX
 * AI findings into a single document -- Markdown or JSON.
 *
 * <p>
 * The fusion report provides:
 * </p>
 * <ul>
 * <li>Executive summary with counts by source and severity</li>
 * <li>AnarCry findings grouped by severity</li>
 * <li>ARTEX AI findings grouped by severity</li>
 * <li>Attack chain hints where findings from different sources connect</li>
 * <li>Combined statistics</li>
 * </ul>
 */
public class FusionReport {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final List<Severity> ORDER = List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
            Severity.INFO);

    private final List<Finding> anarcryFindings;
    private final List<Finding> artexFindings;
    private final String targetUrl;

    public FusionReport(List<Finding> anarcryFindings, List<Finding> artexFindings, String targetUrl) {
        this.anarcryFindings = sortBySeverity(anarcryFindings);
        this.artexFindings = sortBySeverity(artexFindings);
        this.targetUrl = targetUrl;
    }

    // -------------------------------------------------------------------------
    // Markdown output
    // -------------------------------------------------------------------------

    /**
     * Generates the unified Markdown report.
     */
    public String generateMarkdown() {
        StringBuilder sb = new StringBuilder();
        String timestamp = LocalDateTime.now().format(FMT);

        sb.append("# AnarCry + ARTEX Fusion Report\n\n");
        sb.append("**Target:** ").append(targetUrl).append("  \n");
        sb.append("**Date:** ").append(timestamp).append("  \n");
        sb.append("**AnarCry findings:** ").append(anarcryFindings.size()).append("  \n");
        sb.append("**ARTEX findings:** ").append(artexFindings.size()).append("  \n");
        sb.append("**Total findings:** ").append(anarcryFindings.size() + artexFindings.size()).append("\n\n");

        buildExecutiveSummary(sb);
        buildFindingsSection(sb, "AnarCry Findings", anarcryFindings);
        buildFindingsSection(sb, "ARTEX AI Findings", artexFindings);
        buildAttackChainHints(sb);
        buildCombinedStatistics(sb);

        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // JSON output
    // -------------------------------------------------------------------------

    /**
     * Generates the unified JSON report.
     */
    public String generateJson() {
        Map<String, Object> report = new LinkedHashMap<>();
        String timestamp = LocalDateTime.now().format(FMT);

        report.put("title", "AnarCry + ARTEX Fusion Report");
        report.put("target", targetUrl);
        report.put("date", timestamp);

        // Summary
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("anarcryTotal", anarcryFindings.size());
        summary.put("artexTotal", artexFindings.size());
        summary.put("combinedTotal", anarcryFindings.size() + artexFindings.size());
        summary.put("anarcrySeverity", severityCounts(anarcryFindings));
        summary.put("artexSeverity", severityCounts(artexFindings));
        summary.put("combinedSeverity", severityCounts(mergedFindings()));
        report.put("summary", summary);

        // Findings
        report.put("anarcryFindings", findingsToMaps(anarcryFindings));
        report.put("artexFindings", findingsToMaps(artexFindings));

        // Attack chains
        report.put("attackChains", detectAttackChains());

        // Statistics
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("uniqueModules", countUniqueModules());
        stats.put("uniqueEndpoints", countUniqueEndpoints());
        stats.put("overlapModules", detectOverlapModules());
        report.put("statistics", stats);

        return GSON.toJson(report);
    }

    // -------------------------------------------------------------------------
    // Executive summary
    // -------------------------------------------------------------------------

    private void buildExecutiveSummary(StringBuilder sb) {
        sb.append("## Executive Summary\n\n");

        List<Finding> all = mergedFindings();

        sb.append("### Combined Severity Distribution\n\n");
        sb.append("| Severity | AnarCry | ARTEX | Total |\n");
        sb.append("|----------|---------|-------|-------|\n");
        for (Severity s : ORDER) {
            long ac = anarcryFindings.stream().filter(f -> f.severity() == s).count();
            long ax = artexFindings.stream().filter(f -> f.severity() == s).count();
            long total = ac + ax;
            if (total > 0) {
                sb.append("| ").append(s).append(" | ").append(ac).append(" | ").append(ax).append(" | ").append(total)
                        .append(" |\n");
            }
        }
        sb.append("\n");

        // Top 3 risks
        List<Finding> topRisks = all.stream().limit(3).toList();
        if (!topRisks.isEmpty()) {
            sb.append("### Top Risks\n\n");
            int idx = 1;
            for (Finding f : topRisks) {
                sb.append(idx++).append(". **[").append(f.severity()).append("]** ").append(f.title()).append(" -- `")
                        .append(f.endpoint()).append("` (CVSS ").append(String.format("%.1f", f.cvssScore()))
                        .append(")\n");
            }
            sb.append("\n");
        }
    }

    // -------------------------------------------------------------------------
    // Findings sections (grouped by severity)
    // -------------------------------------------------------------------------

    private void buildFindingsSection(StringBuilder sb, String sectionTitle, List<Finding> findings) {
        sb.append("## ").append(sectionTitle).append("\n\n");

        if (findings.isEmpty()) {
            sb.append("No findings reported.\n\n");
            return;
        }

        for (Severity s : ORDER) {
            List<Finding> group = findings.stream().filter(f -> f.severity() == s).toList();
            if (group.isEmpty()) {
                continue;
            }

            sb.append("### ").append(s).append(" (").append(group.size()).append(")\n\n");

            for (Finding f : group) {
                sb.append("#### [").append(f.severity()).append("] ").append(f.title()).append("\n\n");
                sb.append("**Module:** ").append(f.module()).append("  \n");
                sb.append("**Endpoint:** `").append(f.endpoint()).append("`  \n");
                sb.append("**CVSS:** ").append(String.format("%.1f", f.cvssScore())).append(" (")
                        .append(safe(f.cvssVector())).append(")  \n");
                sb.append("**CWE:** ").append(f.cweId()).append(" -- ").append(f.cweTitle()).append("\n\n");

                sb.append("**Evidence:**\n```\n").append(safe(f.evidence())).append("\n```\n\n");
                sb.append("**Impact:** ").append(safe(f.impact())).append("\n\n");
                sb.append("**Reproduction:**\n```\n").append(safe(f.reproduction())).append("\n```\n\n");
                sb.append("**Recommendation:** ").append(safe(f.recommendation())).append("\n\n");
                sb.append("---\n\n");
            }
        }
    }

    // -------------------------------------------------------------------------
    // Attack chain hints
    // -------------------------------------------------------------------------

    private void buildAttackChainHints(StringBuilder sb) {
        sb.append("## Attack Chain Hints\n\n");
        sb.append("Cross-source correlations where findings from AnarCry and ARTEX ").append("may chain together:\n\n");

        List<String> chains = detectAttackChains();

        if (chains.isEmpty()) {
            sb.append("No cross-source attack chains identified. Each finding should be ")
                    .append("remediated independently.\n\n");
        } else {
            for (String chain : chains) {
                sb.append("- ").append(chain).append("\n");
            }
            sb.append("\n");
        }
    }

    private List<String> detectAttackChains() {
        List<String> chains = new ArrayList<>();
        List<Finding> all = mergedFindings();

        Map<String, List<Finding>> byModule = new LinkedHashMap<>();
        for (Finding f : all) {
            byModule.computeIfAbsent(f.module(), k -> new ArrayList<>()).add(f);
        }

        boolean hasSsrf = byModule.containsKey("SSRF");
        boolean hasSqli = byModule.containsKey("SQLi");
        boolean hasXss = byModule.containsKey("XSS");
        boolean hasIdor = byModule.containsKey("IDOR");
        boolean hasAuth = byModule.containsKey("JWT") || byModule.containsKey("OAuth");
        boolean hasOpenRedirect = byModule.containsKey("OpenRedirect");
        boolean hasSsti = byModule.containsKey("SSTI");
        boolean hasLfi = byModule.containsKey("LFI");
        boolean hasCmdInject = byModule.containsKey("CmdInject");
        boolean hasCors = byModule.containsKey("CORS");
        boolean hasSmuggling = byModule.containsKey("ReqSmuggling");
        boolean hasCachePoisoning = byModule.containsKey("CachePoisoning");
        boolean hasCrlf = byModule.containsKey("CRLF");
        boolean hasXxe = byModule.containsKey("XXE");

        if (hasSsrf && hasSqli) {
            chains.add("SSRF -> SQLi: SSRF to internal endpoint can reach database "
                    + "interfaces vulnerable to SQL injection");
        }
        if (hasSsrf && hasLfi) {
            chains.add("SSRF -> LFI: server-side request forgery can be leveraged to "
                    + "read local files via file:// or internal endpoints");
        }
        if (hasIdor && hasAuth) {
            chains.add("Auth weakness + IDOR: broken authentication combined with "
                    + "insecure direct object references enables full cross-account access");
        }
        if (hasXss && hasCors) {
            chains.add("XSS + CORS: reflected XSS from an allowed origin can exfiltrate "
                    + "data cross-origin via permissive CORS policy");
        }
        if (hasOpenRedirect && hasAuth) {
            chains.add("Open Redirect + Auth: redirect bypass can steal authorization "
                    + "codes or tokens during OAuth/JWT flows");
        }
        if (hasSsti && hasCmdInject) {
            chains.add("SSTI + Command Injection: template injection achieving RCE "
                    + "confirms the same underlying command execution path");
        }
        if (hasSqli && hasIdor) {
            chains.add("SQLi + IDOR: SQL injection can escalate an IDOR from read to "
                    + "write, enabling data modification across accounts");
        }
        if (hasSmuggling && hasCachePoisoning) {
            chains.add("Request Smuggling + Cache Poisoning: smuggling can poison "
                    + "the cache for all users, turning a single request into mass exploitation");
        }
        if (hasCrlf && hasXss) {
            chains.add("CRLF + XSS: header injection via CRLF can inject XSS payloads "
                    + "in HTTP response headers or body");
        }
        if (hasXxe && hasSsrf) {
            chains.add("XXE + SSRF: XML external entity injection can be used to perform "
                    + "server-side requests to internal services");
        }

        // Cross-source overlap hint
        List<String> overlapModules = detectOverlapModules();
        if (!overlapModules.isEmpty()) {
            chains.add("Cross-validation: both AnarCry and ARTEX independently detected " + "issues in module(s) "
                    + String.join(", ", overlapModules) + " -- high confidence these are real vulnerabilities");
        }

        return chains;
    }

    // -------------------------------------------------------------------------
    // Combined statistics
    // -------------------------------------------------------------------------

    private void buildCombinedStatistics(StringBuilder sb) {
        sb.append("## Combined Statistics\n\n");

        sb.append("| Metric | Value |\n");
        sb.append("|--------|-------|\n");
        sb.append("| AnarCry findings | ").append(anarcryFindings.size()).append(" |\n");
        sb.append("| ARTEX findings | ").append(artexFindings.size()).append(" |\n");
        sb.append("| Combined total | ").append(anarcryFindings.size() + artexFindings.size()).append(" |\n");
        sb.append("| Unique modules | ").append(countUniqueModules()).append(" |\n");
        sb.append("| Unique endpoints | ").append(countUniqueEndpoints()).append(" |\n");

        List<String> overlap = detectOverlapModules();
        sb.append("| Cross-source overlap modules | ").append(overlap.isEmpty() ? "none" : String.join(", ", overlap))
                .append(" |\n");
        sb.append("\n");
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private List<Finding> mergedFindings() {
        List<Finding> all = new ArrayList<>(anarcryFindings);
        all.addAll(artexFindings);
        return sortBySeverity(all);
    }

    private static List<Finding> sortBySeverity(List<Finding> findings) {
        return findings.stream().sorted(Comparator.comparingInt(f -> ORDER.indexOf(f.severity()))).toList();
    }

    private Map<String, Long> severityCounts(List<Finding> findings) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (Severity s : ORDER) {
            long c = findings.stream().filter(f -> f.severity() == s).count();
            if (c > 0) {
                counts.put(s.name(), c);
            }
        }
        return counts;
    }

    private long countUniqueModules() {
        List<Finding> all = mergedFindings();
        return all.stream().map(Finding::module).distinct().count();
    }

    private long countUniqueEndpoints() {
        List<Finding> all = mergedFindings();
        return all.stream().map(Finding::endpoint).distinct().count();
    }

    private List<String> detectOverlapModules() {
        var acModules = anarcryFindings.stream().map(Finding::module).collect(Collectors.toSet());
        var axModules = artexFindings.stream().map(Finding::module).collect(Collectors.toSet());
        return acModules.stream().filter(axModules::contains).sorted().toList();
    }

    private static List<Map<String, Object>> findingsToMaps(List<Finding> findings) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (Finding f : findings) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("module", f.module());
            m.put("endpoint", f.endpoint());
            m.put("title", f.title());
            m.put("severity", f.severity().name());
            m.put("cvssScore", f.cvssScore());
            m.put("cvssVector", safe(f.cvssVector()));
            m.put("cweId", f.cweId());
            m.put("cweTitle", f.cweTitle());
            m.put("evidence", safe(f.evidence()));
            m.put("impact", safe(f.impact()));
            m.put("reproduction", safe(f.reproduction()));
            m.put("recommendation", safe(f.recommendation()));
            list.add(m);
        }
        return list;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
