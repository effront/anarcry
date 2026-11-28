package gg.effront.anarcry.scanner.web.errordisclosure;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ErrorDisclosureModule -- detects sensitive information leaks in error
 * responses (CWE-209).
 *
 * <p>
 * Sends malformed or unusual requests designed to trigger error responses, then
 * scans them for stack traces, internal paths, framework versions, database
 * information, source code fragments, and environment variables.
 *
 * <p>
 * Categories are deduplicated: only the best evidence per category is reported.
 */
public class ErrorDisclosureModule implements Scanner {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    private static final String CWE_ID = "CWE-209";
    private static final String CWE_TITLE = "Generation of Error Message Containing Sensitive Information";
    private static final String CVSS_STACK_TRACE = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
    private static final String CVSS_SOURCE_CODE = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";

    private static final int MAX_EVIDENCE_LEN = 500;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(6);

    // -------------------------------------------------------------------------
    // Detection patterns
    // -------------------------------------------------------------------------

    // Stack traces -- Java, Python, Node.js, .NET
    private static final Pattern STACK_TRACE = Pattern
            .compile("(?m)(\\bat\\s+(?:com|org|java|sun|io\\.netty|jakarta)\\.[\\w.$]+\\(.+?\\))"
                    + "|(Traceback \\(most recent)" + "|(File \"[^\"]+\",\\s+line \\d+)"
                    + "|(node_modules/[\\w@/.-]+\\.js:\\d+)" + "|([\\w/.-]+\\.(?:ts|js):\\d+:\\d+)"
                    + "|(\\bat\\s+\\S+\\s+\\((?:/[^)]+|[A-Z]:\\\\[^)]+):\\d+:\\d+\\))"
                    + "|(System\\.(?:NullReferenceException|ArgumentException|InvalidOperationException))");

    // Internal file system paths
    private static final Pattern INTERNAL_PATH = Pattern
            .compile("(?:/(?:home|var|usr|opt|app|srv|etc|tmp)/[\\w./-]{3,})" + "|(?:[A-Z]:\\\\[\\w\\\\. -]{3,})");

    // Framework and server version strings
    private static final Pattern FRAMEWORK_VERSION = Pattern.compile("(?i)(?:Express/[\\d.]+)"
            + "|(?:Next\\.js[/ ][\\d.]+)" + "|(?:NestJS[/ ][\\d.]+)" + "|(?:Django[/ ][\\d.]+)"
            + "|(?:Rails[/ ][\\d.]+)" + "|(?:Spring Boot[/ ][\\d.]+)" + "|(?:Laravel[/ ][\\d.]+)"
            + "|(?:Tomcat/[\\d.]+)" + "|(?:nginx/[\\d.]+)" + "|(?:Apache/[\\d.]+)" + "|(?:Kestrel[/ ][\\d.]+)"
            + "|(?:Gunicorn/[\\d.]+)" + "|(?:Uvicorn[/ ][\\d.]+)" + "|(?:Puma[/ ][\\d.]+)" + "|(?:Flask[/ ][\\d.]+)"
            + "|(?:ASP\\.NET[/ ][\\d.]+)" + "|(?:X-Powered-By:\\s*[\\w./ ]+\\d+\\.\\d+)");

    // Database information leaks
    private static final Pattern DATABASE_INFO = Pattern.compile("(?i)(?:PostgreSQL\\s+error)"
            + "|(?:MySQL(?:Error|Exception|Warning))" + "|(?:SQLSTATE\\[\\w+\\])" + "|(?:MongoDB(?:Error|ServerError))"
            + "|(?:Redis(?:Error|ConnectionError))" + "|(?:MSSQL|Microsoft SQL Server)" + "|(?:ORA-\\d{5})"
            + "|(?:(?:postgres|mysql|mongodb|redis)://[^\\s\"'<>]{5,})"
            + "|(?:connection\\s+(?:string|refused|reset)\\s+.*(?:port|host|database))");

    // Source code fragments -- function/class definitions, imports
    private static final Pattern SOURCE_CODE = Pattern
            .compile("(?m)^\\s*(?:def |class |function |const |let |var |import |from |require\\(|export )"
                    + "|(?:(?:public|private|protected)\\s+(?:static\\s+)?"
                    + "(?:void|String|int|boolean|async)\\s+\\w+\\()");

    // Environment variable leaks
    private static final Pattern ENV_VARS = Pattern.compile("(?:NODE_ENV\\s*[=:]\\s*\\w+)"
            + "|(?:DATABASE_URL\\s*[=:]\\s*\\S+)" + "|(?:AWS_(?:ACCESS_KEY|SECRET|REGION)\\s*[=:]\\s*\\S+)"
            + "|(?:NEXT_PUBLIC_\\w+\\s*[=:]\\s*\\S+)" + "|(?:MONGO_URI\\s*[=:]\\s*\\S+)"
            + "|(?:REDIS_URL\\s*[=:]\\s*\\S+)" + "|(?:JWT_SECRET\\s*[=:]\\s*\\S+)" + "|(?:API_KEY\\s*[=:]\\s*\\S+)");

    // Hardcoded GET error probe paths (for KB merge deduplication)
    private static final List<String> ERROR_PROBE_PATHS = List.of("/api/v1/nonexistent/path/that/does/not/exist",
            "/api/user/undefined", "/api/user/null", "/api/user/NaN");

    // -------------------------------------------------------------------------
    // Disclosure categories
    // -------------------------------------------------------------------------

    private enum Category {
        STACK_TRACE, INTERNAL_PATH, FRAMEWORK_VERSION, DATABASE_INFO, SOURCE_CODE, ENV_VARS
    }

    private record DisclosureHit(Category category, String evidence, String probeDescription, String endpoint) {
    }

    // -------------------------------------------------------------------------
    // Scanner contract
    // -------------------------------------------------------------------------

    @Override
    public String id() {
        return "ErrorDisclosure";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] " + id() + ": iniciando scan de error disclosure em " + base);

        // Collect all hits across probes; we deduplicate per category at the end
        Map<Category, DisclosureHit> bestHits = new EnumMap<>(Category.class);

        // -----------------------------------------------------------------
        // Probe 1: Invalid JSON body
        // -----------------------------------------------------------------
        probePost(ctx, hc, base + "/api", "application/json", "{\"broken\": }", "Invalid JSON body", bestHits, log);

        // -----------------------------------------------------------------
        // Probe 2: Invalid content type
        // -----------------------------------------------------------------
        probePost(ctx, hc, base + "/", "application/xml", "<x>", "Invalid content type (XML)", bestHits, log);

        // -----------------------------------------------------------------
        // Probe 3: Oversized parameter
        // -----------------------------------------------------------------
        String oversizedParam = "A".repeat(2000);
        probeGet(ctx, hc, base + "/?x=" + oversizedParam, "Oversized parameter (2000 chars)", bestHits, log);

        // -----------------------------------------------------------------
        // Probe 4: Non-existent deep path
        // -----------------------------------------------------------------
        probeGet(ctx, hc, base + "/api/v1/nonexistent/path/that/does/not/exist", "Non-existent deep path", bestHits,
                log);

        // -----------------------------------------------------------------
        // Probe 5: SQL-like input
        // -----------------------------------------------------------------
        probeGet(ctx, hc, base + "/?id='", "SQL-like input (single quote)", bestHits, log);

        // -----------------------------------------------------------------
        // Probe 6: Type confusion
        // -----------------------------------------------------------------
        for (String suffix : List.of("undefined", "null", "NaN")) {
            probeGet(ctx, hc, base + "/api/user/" + suffix, "Type confusion (" + suffix + ")", bestHits, log);
        }

        // -----------------------------------------------------------------
        // Probe 7: Discovered paths with ..%00 suffix
        // -----------------------------------------------------------------
        Set<String> discovered = ctx.discoveredPaths().paths();
        int probed = 0;
        int maxDiscoveredProbes = 15;
        for (String path : discovered) {
            if (probed >= maxDiscoveredProbes) {
                break;
            }
            String probePath = path.endsWith("/") ? path + "..%00" : path + "/..%00";
            probeGet(ctx, hc, base + probePath, "Discovered path with ..%00 (" + path + ")", bestHits, log);
            probed++;
        }

        // -----------------------------------------------------------------
        // KB-sourced error probes
        // -----------------------------------------------------------------
        for (String kbProbe : mergeKbErrorProbes()) {
            if (ERROR_PROBE_PATHS.contains(kbProbe)) {
                continue;
            }
            probeGet(ctx, hc, base + kbProbe, "KB error probe", bestHits, log);
        }

        // -----------------------------------------------------------------
        // Build findings from best evidence per category
        // -----------------------------------------------------------------
        List<Finding> findings = new ArrayList<>();
        for (Map.Entry<Category, DisclosureHit> entry : bestHits.entrySet()) {
            DisclosureHit hit = entry.getValue();
            Finding f = buildFinding(hit, base);
            if (f != null) {
                findings.add(f);
                log.accept("[!!] " + id() + ": " + f.title() + " via " + hit.probeDescription());
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": nenhuma divulgacao de erro detectada");
        }
        return findings;
    }

    // -------------------------------------------------------------------------
    // Probe helpers
    // -------------------------------------------------------------------------

    private void probeGet(ScanContext ctx, HttpClient hc, String url, String probeDesc,
            Map<Category, DisclosureHit> bestHits, Consumer<String> log) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(REQUEST_TIMEOUT).GET().build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            analyzeResponse(resp, url, probeDesc, bestHits);
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[~] " + id() + ": probe falhou (" + probeDesc + "): " + e.getMessage());
        }
    }

    private void probePost(ScanContext ctx, HttpClient hc, String url, String contentType, String body,
            String probeDesc, Map<Category, DisclosureHit> bestHits, Consumer<String> log) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", contentType).POST(HttpRequest.BodyPublishers.ofString(body)).build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            analyzeResponse(resp, url, probeDesc, bestHits);
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[~] " + id() + ": probe falhou (" + probeDesc + "): " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Response analysis
    // -------------------------------------------------------------------------

    private void analyzeResponse(HttpResponse<String> resp, String endpoint, String probeDesc,
            Map<Category, DisclosureHit> bestHits) {
        String body = resp.body() != null ? resp.body() : "";
        if (body.isBlank()) {
            return;
        }

        // Also check response headers for version leaks (Server, X-Powered-By)
        String serverHeader = resp.headers().firstValue("Server").orElse("");
        String poweredBy = resp.headers().firstValue("X-Powered-By").orElse("");
        String headerContext = serverHeader + " " + poweredBy;

        checkPattern(STACK_TRACE, Category.STACK_TRACE, body, endpoint, probeDesc, bestHits);
        checkPattern(INTERNAL_PATH, Category.INTERNAL_PATH, body, endpoint, probeDesc, bestHits);
        checkPattern(DATABASE_INFO, Category.DATABASE_INFO, body, endpoint, probeDesc, bestHits);
        checkPattern(SOURCE_CODE, Category.SOURCE_CODE, body, endpoint, probeDesc, bestHits);
        checkPattern(ENV_VARS, Category.ENV_VARS, body, endpoint, probeDesc, bestHits);

        // Framework version -- check both body and headers
        String combined = body + "\n" + headerContext;
        checkPattern(FRAMEWORK_VERSION, Category.FRAMEWORK_VERSION, combined, endpoint, probeDesc, bestHits);
    }

    private void checkPattern(Pattern pattern, Category category, String text, String endpoint, String probeDesc,
            Map<Category, DisclosureHit> bestHits) {
        Matcher m = pattern.matcher(text);
        if (m.find()) {
            String evidence = extractEvidence(text, m);
            DisclosureHit existing = bestHits.get(category);
            // Keep the hit with longer evidence (more informative)
            if (existing == null || evidence.length() > existing.evidence().length()) {
                bestHits.put(category, new DisclosureHit(category, evidence, probeDesc, endpoint));
            }
        }
    }

    /**
     * Extracts evidence around the match, truncating to {@link #MAX_EVIDENCE_LEN}
     * chars. Includes context lines around the match for readability.
     */
    private String extractEvidence(String text, Matcher m) {
        int matchStart = m.start();
        int contextStart = Math.max(0, matchStart - 80);
        int contextEnd = Math.min(text.length(), m.end() + 200);
        String snippet = text.substring(contextStart, contextEnd).strip();
        // Normalize whitespace for cleaner evidence
        snippet = snippet.replaceAll("\\s+", " ");
        if (snippet.length() > MAX_EVIDENCE_LEN) {
            snippet = snippet.substring(0, MAX_EVIDENCE_LEN) + "...";
        }
        return snippet;
    }

    // -------------------------------------------------------------------------
    // Finding construction
    // -------------------------------------------------------------------------

    private Finding buildFinding(DisclosureHit hit, String baseUrl) {
        return switch (hit.category()) {
            case STACK_TRACE -> Finding.of(id(), hit.endpoint(), "Error Response Exposes Stack Trace", Severity.HIGH,
                    "Probe: " + hit.probeDescription() + " | Leaked: " + hit.evidence(),
                    "Stack traces reveal internal class names, library versions, and application "
                            + "structure. Attackers use this to identify specific framework versions "
                            + "with known CVEs and to map the internal architecture for targeted attacks.",
                    curlPoc(hit),
                    "Configure custom error pages for all HTTP error codes; disable debug/development "
                            + "mode in production; implement a global exception handler that logs details "
                            + "server-side and returns only generic messages to the client.",
                    CWE_ID, CWE_TITLE, CVSS_STACK_TRACE, CvssCalculator.calculate(CVSS_STACK_TRACE));

            case INTERNAL_PATH -> Finding
                    .of(id(), hit.endpoint(), "Error Response Leaks Internal Paths", Severity.MEDIUM,
                            "Probe: " + hit.probeDescription() + " | Leaked: " + hit.evidence(),
                            "Internal file system paths reveal the deployment directory structure, OS type, "
                                    + "and potentially usernames. This aids path traversal attacks and "
                                    + "helps attackers locate configuration files, logs, and source code.",
                            curlPoc(hit),
                            "Sanitize all error responses to strip absolute file paths; use relative paths "
                                    + "in application code; configure the web server to serve generic error pages.",
                            CWE_ID, CWE_TITLE, CVSS_STACK_TRACE, CvssCalculator.calculate(CVSS_STACK_TRACE));

            case FRAMEWORK_VERSION -> Finding.of(id(), hit.endpoint(), "Error Response Discloses Framework Version",
                    Severity.LOW, "Probe: " + hit.probeDescription() + " | Leaked: " + hit.evidence(),
                    "Framework and server version strings allow attackers to look up specific CVEs "
                            + "and known exploits for the exact version in use, reducing attack complexity.",
                    curlPoc(hit),
                    "Remove or obfuscate Server and X-Powered-By headers; disable version banners "
                            + "in framework configuration; use custom error pages that do not "
                            + "expose technology details.",
                    CWE_ID, CWE_TITLE, CVSS_STACK_TRACE, CvssCalculator.calculate(CVSS_STACK_TRACE));

            case DATABASE_INFO -> Finding
                    .of(id(), hit.endpoint(), "Error Response Leaks Database Information", Severity.HIGH,
                            "Probe: " + hit.probeDescription() + " | Leaked: " + hit.evidence(),
                            "Database error messages and connection strings reveal the DBMS type, version, "
                                    + "hostname, port, and sometimes credentials. This information enables "
                                    + "targeted SQL injection attacks and direct database access attempts.",
                            curlPoc(hit),
                            "Catch all database exceptions at the application layer and return generic errors; "
                                    + "never expose connection strings in error responses; use environment "
                                    + "variables for database credentials and ensure they are not logged.",
                            CWE_ID, CWE_TITLE, CVSS_STACK_TRACE, CvssCalculator.calculate(CVSS_STACK_TRACE));

            case SOURCE_CODE -> Finding.of(id(), hit.endpoint(), "Error Response Leaks Source Code", Severity.CRITICAL,
                    "Probe: " + hit.probeDescription() + " | Leaked: " + hit.evidence(),
                    "Source code fragments in error responses expose business logic, authentication "
                            + "mechanisms, internal API endpoints, and potentially hardcoded secrets. "
                            + "This is a severe information leak that significantly reduces "
                            + "exploitation complexity for all other vulnerabilities.",
                    curlPoc(hit),
                    "Disable source code display in error pages; set debug mode to false in production; "
                            + "implement a global exception handler; ensure stack traces and source "
                            + "context are logged server-side only, never sent to the client.",
                    CWE_ID, CWE_TITLE, CVSS_SOURCE_CODE, CvssCalculator.calculate(CVSS_SOURCE_CODE));

            case ENV_VARS -> Finding.of(id(), hit.endpoint(), "Error Response Leaks Environment Variables",
                    Severity.HIGH, "Probe: " + hit.probeDescription() + " | Leaked: " + hit.evidence(),
                    "Environment variables in error responses may contain API keys, database credentials, "
                            + "cloud provider secrets (AWS keys), and internal configuration. "
                            + "Direct credential exposure can lead to full system compromise.",
                    curlPoc(hit),
                    "Never render environment variables in error output; disable debug endpoints "
                            + "and verbose error pages in production; audit application startup "
                            + "to ensure env vars are not logged or echoed.",
                    CWE_ID, CWE_TITLE, CVSS_SOURCE_CODE, CvssCalculator.calculate(CVSS_SOURCE_CODE));
        };
    }

    private String curlPoc(DisclosureHit hit) {
        return "curl -v '" + hit.endpoint() + "'";
    }

    // -------------------------------------------------------------------------
    // KB payload merge
    // -------------------------------------------------------------------------

    private List<String> mergeKbErrorProbes() {
        LinkedHashSet<String> merged = new LinkedHashSet<>(ERROR_PROBE_PATHS);
        for (String kbp : KnowledgeBase.getInstance().filteredPayloads(id())) {
            merged.add(kbp);
        }
        return List.copyOf(merged);
    }
}
