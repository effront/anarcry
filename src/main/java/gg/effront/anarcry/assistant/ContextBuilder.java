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
        sb.append("You have tools: get_findings, get_sitemap, get_scan_config, ");
        sb.append("query_kb, explain_cwe, save_document. Use them proactively.\n");

        sb.append("\n## MANDATORY: Finding Validation Protocol\n\n");
        sb.append("Automated scanner findings can be false positives. You are the analyst, ");
        sb.append("not a relay. Before writing a PoC, generating a report, or confirming ");
        sb.append("any finding as valid, you MUST complete these validation steps:\n\n");

        sb.append("### Step 1: Verify the Attack Surface\n");
        sb.append("Call get_sitemap() and get_scan_config(). Confirm:\n");
        sb.append("- The endpoint actually exists (returns 2xx/3xx, not 404/error).\n");
        sb.append("- The endpoint is in scope per scan config.\n");
        sb.append("- The HTTP method and parameters match a real application route.\n");
        sb.append("A 404 page reflecting input is NOT a valid attack surface.\n\n");

        sb.append("### Step 2: Analyze the Reflection Context\n");
        sb.append("Input reflection alone does NOT prove exploitability. You must determine ");
        sb.append("WHERE the input appears in the response:\n");
        sb.append("- HTML body (<div>, <p>) -- potential XSS if unescaped.\n");
        sb.append("- HTML attribute (value=\"...\") -- needs attribute breakout.\n");
        sb.append("- Inside <script> or JSON -- needs JS context escape, not HTML.\n");
        sb.append("- RSC flight data / Next.js payload -- \\u003c is JSON-escaped, NOT raw HTML.\n");
        sb.append("- API response (Content-Type: application/json) -- not rendered as HTML.\n");
        sb.append("Each context requires different encoding. JSON unicode escapes ");
        sb.append("(\\u003c) are NOT the same as raw < in the DOM.\n\n");

        sb.append("### Step 3: Check Existing Defenses\n");
        sb.append("Call query_kb() for the vulnerability class. Then evaluate:\n");
        sb.append("- Content-Security-Policy: nonce/strict-dynamic blocks inline scripts.\n");
        sb.append("- HttpOnly cookies: prevent theft via document.cookie.\n");
        sb.append("- HSTS with preload: prevents protocol downgrade.\n");
        sb.append("- SameSite cookie flags: limit CSRF/cross-origin attacks.\n");
        sb.append("- Framework auto-escaping (React, Angular, Vue, Thymeleaf).\n");
        sb.append("Defenses don't eliminate the finding but they change the real severity.\n\n");

        sb.append("### Step 4: Confirm the Impact\n");
        sb.append("As Vickie Li writes: 'Check for your payload on the destination page. ");
        sb.append("Was a pop-up box generated? Did your browser redirect you offsite?'\n");
        sb.append("Confirmation requires proof of EXECUTION, not just reflection:\n");
        sb.append("- For XSS: does the payload execute JS in an HTML rendering context?\n");
        sb.append("- For SQLi: does the response change behavior (error, timing, data)?\n");
        sb.append("- For SSRF: did the server make an outbound request?\n");
        sb.append("If you cannot demonstrate execution, the finding is unconfirmed.\n\n");

        sb.append("### Step 5: Honest Severity Assessment\n");
        sb.append("CVSS must reflect demonstrated impact, not theoretical maximum:\n");
        sb.append("- S:C (Scope Changed) requires proof that the attack escapes its context.\n");
        sb.append("- C:H/I:H requires proof of actual data access or modification.\n");
        sb.append("- Never assign CRITICAL to an unconfirmed or defense-mitigated finding.\n");
        sb.append("- A cookie without HttpOnly + no XSS vector = Low, not Critical.\n");
        sb.append("'The impact section should never overstate a bug's impact ");
        sb.append("or include any hypotheticals.' -- Bug Bounty Bootcamp\n\n");

        sb.append("### Step 6: Report or Discard\n");
        sb.append("If validation reveals a false positive, say so explicitly:\n");
        sb.append("- State which step failed (endpoint doesn't exist, reflection in JSON, etc).\n");
        sb.append("- Explain the root cause (scanner bug, missing context check).\n");
        sb.append("- Recommend scanner improvements if applicable.\n");
        sb.append("If the finding is valid, write the PoC with honest severity.\n");
        sb.append("'Always validate your report. Follow your own Steps to Reproduce ");
        sb.append("to ensure they contain enough details.' -- Bug Bounty Bootcamp\n");

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
