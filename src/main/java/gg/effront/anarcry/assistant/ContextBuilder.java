package gg.effront.anarcry.assistant;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.model.KnowledgeEntry;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public final class ContextBuilder {

    private static final int MAX_FINDINGS_SUMMARY = 50;
    private static final int MAX_FINDING_DETAIL_LINES = 20;

    private final Supplier<List<Finding>> findingsSupplier;
    private final Supplier<ScanContext> contextSupplier;
    private final KnowledgeBase kb;

    public ContextBuilder(Supplier<List<Finding>> findingsSupplier, Supplier<ScanContext> contextSupplier,
            KnowledgeBase kb) {
        this.findingsSupplier = findingsSupplier;
        this.contextSupplier = contextSupplier;
        this.kb = kb;
    }

    public String build() {
        StringBuilder sb = new StringBuilder();
        sb.append("You are AnarCry's security assistant -- an expert vulnerability analyst.\n\n");

        ScanContext ctx = contextSupplier.get();
        if (ctx != null) {
            sb.append("Target: ").append(ctx.targetUrl()).append("\n");
            sb.append("Enabled modules: ").append(String.join(", ", ctx.enabledModules())).append("\n");
            appendAuthInfo(sb, ctx);
            sb.append("Discovered paths: ").append(ctx.discoveredPaths().pathCount()).append(" endpoints, ");
            sb.append(ctx.discoveredPaths().parameterCount()).append(" parameters\n");
        } else {
            sb.append("No scan is currently running.\n");
        }

        List<Finding> findings = findingsSupplier.get();
        sb.append("\nFindings (").append(findings.size()).append(" total):\n");
        findings.stream().sorted(Comparator.comparingInt(f -> f.severity().ordinal())).limit(MAX_FINDINGS_SUMMARY)
                .forEach(f -> sb.append("  - [").append(f.severity()).append("] ").append(f.module()).append(" | ")
                        .append(f.endpoint()).append(" | ").append(f.title()).append("\n"));

        if (findings.size() > MAX_FINDINGS_SUMMARY) {
            sb.append("  ... and ").append(findings.size() - MAX_FINDINGS_SUMMARY).append(" more\n");
        }

        sb.append("\nHelp the operator interpret scan results, suggest next steps, ");
        sb.append("explain vulnerability impact, and recommend remediation.\n");
        sb.append("Be direct and technical. Reference CWE/CVSS when relevant.\n");
        sb.append("You have tools to query findings, knowledge base, CWE details, ");
        sb.append("sitemap, and scan config -- use them when the operator asks for detail.\n");

        return sb.toString();
    }

    public String buildWithSlashCommand(String command, String arg) {
        StringBuilder sb = new StringBuilder(build());
        sb.append("\n--- Slash command context ---\n");

        switch (command.toLowerCase()) {
            case "/findings" -> appendFindingsDetail(sb);
            case "/explain" -> appendExplainDetail(sb, arg);
            case "/remediate" -> appendRemediateDetail(sb);
            case "/plan" -> appendPlanDetail(sb);
            case "/kb" -> appendKbDetail(sb, arg);
            case "/report" -> appendReportDetail(sb);
            default -> sb.append("Unknown command: ").append(command).append("\n");
        }

        return sb.toString();
    }

    private void appendAuthInfo(StringBuilder sb, ScanContext ctx) {
        if (!ctx.jwtToken().isEmpty()) {
            sb.append("Authentication: JWT/Bearer token present\n");
        } else if (!ctx.config().sessionCookie().isEmpty()) {
            sb.append("Authentication: Session cookie present\n");
        } else {
            sb.append("Authentication: None\n");
        }
    }

    private void appendFindingsDetail(StringBuilder sb) {
        sb.append("The operator requested full finding details.\n\n");
        List<Finding> findings = findingsSupplier.get();
        findings.stream().sorted(Comparator.comparingInt(f -> f.severity().ordinal())).forEach(f -> {
            sb.append("[").append(f.severity()).append("] ").append(f.title()).append("\n");
            sb.append("  Module: ").append(f.module()).append("\n");
            sb.append("  Endpoint: ").append(f.endpoint()).append("\n");
            sb.append("  CWE: ").append(f.cweId()).append(" -- ").append(f.cweTitle()).append("\n");
            sb.append("  CVSS: ").append(f.cvssScore()).append(" (").append(f.cvssVector()).append(")\n");
            sb.append("  Evidence: ").append(truncate(f.evidence(), 200)).append("\n");
            sb.append("  Impact: ").append(truncate(f.impact(), 200)).append("\n\n");
        });
    }

    private void appendExplainDetail(StringBuilder sb, String findingId) {
        sb.append("The operator wants a deep dive on a specific finding.\n\n");
        List<Finding> findings = findingsSupplier.get();

        Optional<Finding> match = findings.stream()
                .filter(f -> f.title().toLowerCase().contains(findingId.toLowerCase())
                        || f.module().equalsIgnoreCase(findingId) || f.cweId().equalsIgnoreCase(findingId))
                .findFirst();

        if (match.isPresent()) {
            Finding f = match.get();
            sb.append("Finding: ").append(f.title()).append("\n");
            sb.append("Module: ").append(f.module()).append("\n");
            sb.append("Endpoint: ").append(f.endpoint()).append("\n");
            sb.append("Severity: ").append(f.severity()).append("\n");
            sb.append("CWE: ").append(f.cweId()).append(" -- ").append(f.cweTitle()).append("\n");
            sb.append("CVSS: ").append(f.cvssScore()).append(" (").append(f.cvssVector()).append(")\n");
            sb.append("Evidence: ").append(f.evidence()).append("\n");
            sb.append("Impact: ").append(f.impact()).append("\n");
            sb.append("Reproduction: ").append(f.reproduction()).append("\n");
            sb.append("Recommendation: ").append(f.recommendation()).append("\n\n");

            kb.byModule(f.module()).ifPresent(entry -> {
                sb.append("Knowledge Base -- ").append(entry.title()).append(":\n");
                sb.append("  Description: ").append(truncate(entry.description(), 500)).append("\n");
                sb.append("  Impact: ").append(truncate(entry.impact(), 300)).append("\n");
                sb.append("  Recommendation: ").append(entry.recommendation()).append("\n");
                if (!entry.notableCves().isEmpty()) {
                    sb.append("  Notable CVEs:\n");
                    entry.notableCves().stream().limit(5).forEach(
                            c -> sb.append("    - ").append(c.cve()).append(": ").append(c.description()).append("\n"));
                }
            });
        } else {
            sb.append("No finding matched '").append(findingId).append("'. ");
            sb.append("Available finding titles/modules:\n");
            findings.stream().limit(MAX_FINDING_DETAIL_LINES)
                    .forEach(f -> sb.append("  - ").append(f.module()).append(": ").append(f.title()).append("\n"));
        }
    }

    private void appendRemediateDetail(StringBuilder sb) {
        sb.append("The operator wants a remediation plan for all findings.\n\n");
        List<Finding> findings = findingsSupplier.get();

        Map<String, List<Finding>> bySeverity = findings.stream()
                .collect(Collectors.groupingBy(f -> f.severity().name(), LinkedHashMap::new, Collectors.toList()));

        for (var entry : bySeverity.entrySet()) {
            sb.append("## ").append(entry.getKey()).append(" (").append(entry.getValue().size()).append(")\n");
            for (Finding f : entry.getValue()) {
                sb.append("- ").append(f.title()).append(" [").append(f.module()).append("]\n");
                sb.append("  Recommendation: ").append(truncate(f.recommendation(), 200)).append("\n");
                kb.byModule(f.module()).ifPresent(ke -> sb.append("  KB recommendation: ")
                        .append(truncate(ke.recommendation(), 200)).append("\n"));
            }
            sb.append("\n");
        }

        sb.append("Generate a prioritized remediation plan grouped by severity ");
        sb.append("and effort required. Identify quick wins vs. long-term fixes.\n");
    }

    private void appendPlanDetail(StringBuilder sb) {
        sb.append("The operator wants a pentest strategy for the target.\n\n");

        ScanContext ctx = contextSupplier.get();
        if (ctx != null) {
            sb.append("Target: ").append(ctx.targetUrl()).append("\n");
            sb.append("Modules already run: ").append(String.join(", ", ctx.enabledModules())).append("\n");

            int pathCount = ctx.discoveredPaths().pathCount();
            if (pathCount > 0) {
                sb.append("Discovered paths (sample): ");
                ctx.discoveredPaths().paths().stream().limit(20).forEach(p -> sb.append(p).append(", "));
                sb.append("\n");
            }
        }

        sb.append("\nSuggest which modules to run next based on the attack surface, ");
        sb.append("what manual testing to perform, and how to chain findings for maximum impact.\n");
    }

    private void appendKbDetail(StringBuilder sb, String topic) {
        sb.append("The operator wants knowledge base information on: ").append(topic).append("\n\n");

        String lower = topic.toLowerCase();
        List<KnowledgeEntry> matches = kb.all().values().stream()
                .filter(e -> (e.title() != null && e.title().toLowerCase().contains(lower))
                        || (e.module() != null && e.module().toLowerCase().contains(lower))
                        || (e.summary() != null && e.summary().toLowerCase().contains(lower))
                        || (e.cweTitle() != null && e.cweTitle().toLowerCase().contains(lower)))
                .limit(3).toList();

        if (matches.isEmpty()) {
            sb.append("No knowledge base entries found for '").append(topic).append("'.\n");
        } else {
            for (KnowledgeEntry e : matches) {
                sb.append("### ").append(e.title()).append(" (").append(e.module()).append(")\n");
                sb.append("CWE: ").append(e.cweId()).append(" -- ").append(e.cweTitle()).append("\n");
                sb.append("Summary: ").append(truncate(e.summary(), 400)).append("\n");
                sb.append("Impact: ").append(truncate(e.impact(), 300)).append("\n");
                sb.append("Recommendation: ").append(e.recommendation()).append("\n");
                if (!e.notableCves().isEmpty()) {
                    sb.append("Notable CVEs:\n");
                    e.notableCves().stream().limit(3).forEach(
                            c -> sb.append("  - ").append(c.cve()).append(": ").append(c.description()).append("\n"));
                }
                sb.append("\n");
            }
        }
    }

    private void appendReportDetail(StringBuilder sb) {
        sb.append("The operator wants an executive summary report.\n\n");
        List<Finding> findings = findingsSupplier.get();

        long critical = findings.stream().filter(f -> f.severity() == Severity.CRITICAL).count();
        long high = findings.stream().filter(f -> f.severity() == Severity.HIGH).count();
        long medium = findings.stream().filter(f -> f.severity() == Severity.MEDIUM).count();
        long low = findings.stream().filter(f -> f.severity() == Severity.LOW).count();
        long info = findings.stream().filter(f -> f.severity() == Severity.INFO).count();

        sb.append("Finding distribution:\n");
        sb.append("  CRITICAL: ").append(critical).append("\n");
        sb.append("  HIGH: ").append(high).append("\n");
        sb.append("  MEDIUM: ").append(medium).append("\n");
        sb.append("  LOW: ").append(low).append("\n");
        sb.append("  INFO: ").append(info).append("\n\n");

        sb.append("Affected endpoints:\n");
        findings.stream().map(Finding::endpoint).distinct().limit(20)
                .forEach(ep -> sb.append("  - ").append(ep).append("\n"));

        sb.append("\nGenerate a concise executive summary suitable for stakeholders. ");
        sb.append("Include: overall risk posture, top findings, and recommended next steps.\n");
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) {
            return "";
        }
        if (s.length() <= maxLen) {
            return s;
        }
        return s.substring(0, maxLen) + "...";
    }
}
