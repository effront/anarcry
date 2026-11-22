package gg.effront.anarcry.scanner.web.clickjacking;

import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public class ClickjackingModule implements Scanner {

    private static final int MAX_DISCOVERED_PAGES = 15;
    private static final long REQUEST_DELAY_MS = 100;

    /** Paths that indicate authentication, transactions, or wallet operations. */
    private static final Set<String> SENSITIVE_KEYWORDS = Set.of("login", "signin", "sign-in", "auth", "account",
            "wallet", "connect", "swap", "trade", "transfer", "withdraw", "deposit", "approve", "confirm",
            "transaction", "checkout", "payment", "settings", "profile", "admin", "dashboard");

    /** JS frame-busting patterns. */
    private static final List<Pattern> FRAME_BUST_PATTERNS = List.of(Pattern.compile("top\\s*!==?\\s*self"),
            Pattern.compile("self\\s*!==?\\s*top"), Pattern.compile("top\\.location"),
            Pattern.compile("parent\\.location\\s*="), Pattern.compile("window\\.top\\s*!==?\\s*window\\.self"));

    /** Per-page check result. */
    private record PageResult(String path, int statusCode, boolean hasXfo, boolean hasCspFrameAncestors,
            boolean hasJsFrameBusting, boolean skippedWaf) {
        boolean isProtected() {
            return hasXfo || hasCspFrameAncestors || hasJsFrameBusting || skippedWaf;
        }
    }

    @Override
    public String id() {
        return "Clickjacking";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String cweId = CweRegistry.cweId(id());
        String cweTitle = CweRegistry.cweTitle(id());
        String cvssVector = CweRegistry.cvssVector(id());
        double cvssScore = CvssCalculator.calculate(cvssVector);

        log.accept("[~] CLICKJACKING: starting clickjacking analysis on " + ctx.targetUrl());

        // -- 1. Collect pages to test --
        List<String> pages = collectPages(ctx);
        log.accept("[~] CLICKJACKING: testing " + pages.size() + " pages");

        HttpClient hc = HttpClientFactory.http2();
        List<PageResult> results = new ArrayList<>();

        // -- 2. Check each page --
        for (String page : pages) {
            String url = resolveUrl(ctx.targetUrl(), page);
            try {
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(10))
                        .header("User-Agent", gg.effront.anarcry.Version.userAgent()).GET().build();
                HttpResponse<String> response = Http.send(ctx, hc, request, HttpResponse.BodyHandlers.ofString(), id());

                int status = response.statusCode();
                String body = response.body() != null ? response.body() : "";
                Map<String, List<String>> headers = response.headers().map();

                // Skip WAF challenge pages (403 with JS challenge HTML)
                if (status == 403 && isJsChallengeBody(body)) {
                    log.accept("[!] CLICKJACKING: WAF challenge on " + page + " -- skipping");
                    results.add(new PageResult(page, status, false, false, false, true));
                    delay();
                    continue;
                }

                boolean hasXfo = checkXFrameOptions(headers);
                boolean hasCspFa = checkCspFrameAncestors(headers);
                boolean hasJsBust = checkJsFrameBusting(body);

                PageResult result = new PageResult(page, status, hasXfo, hasCspFa, hasJsBust, false);
                results.add(result);

                String protStatus = result.isProtected() ? "PROTECTED" : "VULNERABLE";
                String protDetails = protectionDetails(result);
                log.accept("[~] CLICKJACKING: " + page + " (HTTP " + status + ") -- " + protStatus + protDetails);

            } catch (Exception e) {
                log.accept("[!] CLICKJACKING: error checking " + page + " -- " + e.getMessage());
            }
            delay();
        }

        // -- 3. Analyze results --
        List<PageResult> vulnerable = results.stream().filter(r -> !r.isProtected()).toList();
        List<PageResult> protectedPages = results.stream().filter(PageResult::isProtected).toList();

        if (vulnerable.isEmpty()) {
            log.accept("[+] CLICKJACKING: all tested pages have frame protection");
            return List.of();
        }

        log.accept("[!!] CLICKJACKING: " + vulnerable.size() + " of " + results.size()
                + " pages vulnerable to clickjacking");

        // -- 4. Determine severity --
        boolean hasSensitivePage = vulnerable.stream().anyMatch(r -> isSensitivePath(r.path()));
        Severity severity = hasSensitivePage ? Severity.HIGH : Severity.MEDIUM;

        boolean inconsistent = !protectedPages.isEmpty() && !vulnerable.isEmpty();

        // -- 5. Build evidence table --
        StringBuilder evidence = new StringBuilder();
        evidence.append("Page protection analysis (").append(results.size()).append(" pages tested):\n\n");
        evidence.append(String.format("%-40s | %-6s | %-5s | %-14s | %-10s | %s%n", "Path", "Status", "XFO",
                "CSP frame-anc.", "JS busting", "Result"));
        evidence.append("-".repeat(100)).append("\n");
        for (PageResult r : results) {
            String status = r.skippedWaf() ? "WAF" : (r.isProtected() ? "SAFE" : "VULN");
            evidence.append(String.format("%-40s | %-6d | %-5s | %-14s | %-10s | %s%n", truncate(r.path(), 40),
                    r.statusCode(), r.hasXfo() ? "YES" : "NO", r.hasCspFrameAncestors() ? "YES" : "NO",
                    r.hasJsFrameBusting() ? "YES" : "NO", status));
        }

        if (inconsistent) {
            evidence.append("\n[!] INCONSISTENCY: ").append(protectedPages.size())
                    .append(" page(s) have frame protection while ").append(vulnerable.size())
                    .append(" page(s) do not -- indicates incomplete deployment of frame protection headers.");
        }

        // -- 6. Generate PoC --
        List<String> vulnPaths = vulnerable.stream().map(PageResult::path).toList();
        String pocPath;
        try {
            pocPath = ClickjackingPocGenerator.generate(ctx.targetUrl(), vulnPaths,
                    Path.of(System.getProperty("user.dir")));
            log.accept("[+] CLICKJACKING: PoC generated at " + pocPath);
        } catch (Exception e) {
            log.accept("[!] CLICKJACKING: failed to generate PoC -- " + e.getMessage());
            pocPath = "(PoC generation failed: " + e.getMessage() + ")";
        }

        // -- 7. Build reproduction steps --
        StringBuilder repro = new StringBuilder();
        repro.append("# Verify missing headers:\n");
        int curlCount = 0;
        for (PageResult r : vulnerable) {
            if (curlCount >= 3) {
                repro.append("# ... and ").append(vulnerable.size() - 3).append(" more pages\n");
                break;
            }
            String url = resolveUrl(ctx.targetUrl(), r.path());
            repro.append("curl -sI ").append(url).append(" | grep -iE 'x-frame-options|content-security-policy'\n");
            curlCount++;
        }
        repro.append("\n# PoC file:\n").append(pocPath);

        // -- 8. Create consolidated finding --
        String title = "Clickjacking -- Missing Frame Protection on " + vulnerable.size() + " page"
                + (vulnerable.size() != 1 ? "s" : "");
        String impact = "Site can be embedded in attacker-controlled iframe. On crypto/financial platforms, "
                + "enables wallet connection hijacking and transaction manipulation via UI redressing.";
        String recommendation = "Add X-Frame-Options: DENY and Content-Security-Policy: "
                + "frame-ancestors 'none' to all routes";

        List<Finding> findings = new ArrayList<>();
        findings.add(Finding.of(id(), ctx.targetUrl(), title, severity, evidence.toString(), impact, repro.toString(),
                recommendation, cweId, cweTitle, cvssVector, cvssScore));

        log.accept("[+] CLICKJACKING: " + findings.size() + " finding(s)");
        return findings;
    }

    /**
     * Collect pages to test: root, up to 15 from discovered paths, plus a 404
     * probe.
     */
    private List<String> collectPages(ScanContext ctx) {
        LinkedHashSet<String> pages = new LinkedHashSet<>();
        pages.add("/");

        Set<String> discovered = ctx.discoveredPaths().paths();
        int added = 0;
        for (String path : discovered) {
            if (added >= MAX_DISCOVERED_PAGES) {
                break;
            }
            String normalized = path.startsWith("/") ? path : "/" + path;
            if (pages.add(normalized)) {
                added++;
            }
        }

        // 404/error page probe
        pages.add("/anarcry-404-probe");
        return new ArrayList<>(pages);
    }

    /** Check if X-Frame-Options is present with DENY or SAMEORIGIN. */
    private boolean checkXFrameOptions(Map<String, List<String>> headers) {
        String xfo = getHeader(headers, "X-Frame-Options");
        if (xfo == null) {
            return false;
        }
        String val = xfo.trim().toUpperCase(Locale.ROOT);
        return val.contains("DENY") || val.contains("SAMEORIGIN");
    }

    /** Check if CSP has frame-ancestors with 'none' or 'self'. */
    private boolean checkCspFrameAncestors(Map<String, List<String>> headers) {
        String csp = getHeader(headers, "Content-Security-Policy");
        if (csp == null) {
            return false;
        }
        String lower = csp.toLowerCase(Locale.ROOT);
        for (String directive : lower.split(";")) {
            String d = directive.trim();
            if (d.startsWith("frame-ancestors")) {
                return d.contains("'none'") || d.contains("'self'");
            }
        }
        return false;
    }

    /** Check response body for JavaScript frame-busting code. */
    private boolean checkJsFrameBusting(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }
        for (Pattern p : FRAME_BUST_PATTERNS) {
            if (p.matcher(body).find()) {
                return true;
            }
        }
        return false;
    }

    /** Detect WAF JS challenge pages (e.g. Cloudflare challenge). */
    private boolean isJsChallengeBody(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }
        String lower = body.toLowerCase(Locale.ROOT);
        return (lower.contains("cf-challenge") || lower.contains("challenge-platform") || lower.contains("jschl-answer")
                || lower.contains("turnstile")) && lower.contains("<script");
    }

    private String getHeader(Map<String, List<String>> headers, String name) {
        return headers.entrySet().stream().filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase(name))
                .map(e -> e.getValue().isEmpty() ? null : e.getValue().get(0)).findFirst().orElse(null);
    }

    private static String resolveUrl(String baseUrl, String path) {
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String p = path.startsWith("/") ? path : "/" + path;
        return base + p;
    }

    private static boolean isSensitivePath(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        return SENSITIVE_KEYWORDS.stream().anyMatch(lower::contains);
    }

    private static String protectionDetails(PageResult r) {
        if (r.skippedWaf()) {
            return " (WAF challenge)";
        }
        if (!r.isProtected()) {
            return "";
        }
        List<String> details = new ArrayList<>();
        if (r.hasXfo()) {
            details.add("XFO");
        }
        if (r.hasCspFrameAncestors()) {
            details.add("CSP frame-ancestors");
        }
        if (r.hasJsFrameBusting()) {
            details.add("JS frame-busting");
        }
        return " (" + String.join(", ", details) + ")";
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max - 3) + "...";
    }

    private static void delay() {
        try {
            Thread.sleep(REQUEST_DELAY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
