package gg.effront.anarcry.scanner.web.jsanalyzer;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.JsBundleDiscovery;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts API endpoint definitions from JavaScript bundles by detecting fetch,
 * $fetch, axios, and XMLHttpRequest calls. Feeds discovered API paths into the
 * shared DiscoveredPaths for downstream modules.
 */
public class JsAnalyzerModule implements Scanner {

    // -- API call detection patterns --

    // fetch("/api/...", { method: "POST", headers: {...} })
    // fetch(`/api/${id}/details`, { ... })
    private static final Pattern FETCH_CALL = Pattern.compile(
            "\\bfetch\\s*\\(\\s*[\"'`]([^\"'`]{1,500})[\"'`](?:\\s*,\\s*\\{([^}]{0,2000})\\})?", Pattern.DOTALL);

    // $fetch("/api/...") -- Nuxt useFetch / $fetch
    private static final Pattern DOLLAR_FETCH_CALL = Pattern.compile(
            "\\$fetch\\s*\\(\\s*[\"'`]([^\"'`]{1,500})[\"'`](?:\\s*,\\s*\\{([^}]{0,2000})\\})?", Pattern.DOTALL);

    // axios.get("/api/..."), axios.post("/api/...", data, config)
    // axios({ method: "post", url: "/api/..." })
    private static final Pattern AXIOS_METHOD_CALL = Pattern.compile(
            "axios\\s*\\.\\s*(get|post|put|patch|delete|head|options)\\s*\\("
                    + "\\s*[\"'`]([^\"'`]{1,500})[\"'`](?:\\s*,\\s*([^)]{0,2000}))?",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private static final Pattern AXIOS_CONFIG_CALL = Pattern.compile("axios\\s*\\(\\s*\\{([^}]{1,3000})\\}",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    // XMLHttpRequest.open("GET", "/api/...")
    private static final Pattern XHR_OPEN = Pattern.compile(
            "\\.open\\s*\\(\\s*[\"']([A-Z]{3,7})[\"']\\s*,\\s*[\"'`]([^\"'`]{1,500})[\"'`]", Pattern.CASE_INSENSITIVE);

    // Patterns to extract details from options objects
    private static final Pattern METHOD_PATTERN = Pattern.compile("(?i)method\\s*:\\s*[\"']([A-Z]{3,7})[\"']");

    private static final Pattern CONTENT_TYPE_PATTERN = Pattern
            .compile("(?i)[\"']?Content-Type[\"']?\\s*:\\s*[\"']([^\"']+)[\"']");

    private static final Pattern AUTH_HEADER_PATTERN = Pattern
            .compile("(?i)(?:Authorization|auth|x-api-key|x-auth-token|Bearer)\\s*[\"':]");

    private static final Pattern URL_IN_CONFIG = Pattern.compile("(?i)url\\s*:\\s*[\"'`]([^\"'`]{1,500})[\"'`]");

    // Template literal parameter pattern: ${...} -> {param}
    private static final Pattern TEMPLATE_PARAM = Pattern.compile("\\$\\{([^}]+)\\}");

    /** Represents a single discovered API endpoint from JS analysis. */
    private record ApiEndpoint(String method, String path, String contentType, boolean hasAuth) {
    }

    @Override
    public String id() {
        return "JsAnalyzer";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();
        Set<String> scannedUrls = new HashSet<>();
        Set<String> jsUrls = new LinkedHashSet<>();
        List<ApiEndpoint> allEndpoints = new ArrayList<>();
        Set<String> seenEndpoints = new HashSet<>();

        String base = ctx.targetUrl().replaceAll("/+$", "");

        // Phase 1: Discover all JS bundles (including lazy-loaded chunks)
        jsUrls.addAll(JsBundleDiscovery.discover(ctx, hc, base, log));
        log.accept("[~] " + id() + ": found " + jsUrls.size() + " JS bundle(s) to analyze");

        // Phase 2: Download and analyze each JS bundle
        for (String jsUrl : jsUrls) {
            if (!scannedUrls.add(jsUrl)) {
                continue;
            }
            String body = fetchBody(ctx, hc, jsUrl, log);
            if (body == null || body.isBlank()) {
                continue;
            }
            analyzeJsContent(body, jsUrl, allEndpoints, seenEndpoints, log);
        }

        // Phase 3: Feed discovered API paths into discoveredPaths
        int addedPaths = 0;
        for (ApiEndpoint ep : allEndpoints) {
            String cleanPath = ep.path;
            // Only add paths that look like relative API paths
            if (cleanPath.startsWith("/")) {
                ctx.discoveredPaths().addPath(cleanPath);
                addedPaths++;
            }
        }
        log.accept("[+] " + id() + ": discovered " + allEndpoints.size() + " API endpoint(s), added " + addedPaths
                + " path(s) to discovery");

        // Phase 4: Generate findings
        if (!allEndpoints.isEmpty()) {
            // INFO finding listing all discovered endpoints
            StringBuilder evidence = new StringBuilder();
            evidence.append("Discovered API endpoints from JS analysis:\n");
            for (ApiEndpoint ep : allEndpoints) {
                evidence.append("  ").append(ep.method).append(" ").append(ep.path);
                if (ep.contentType != null && !ep.contentType.isEmpty()) {
                    evidence.append(" [").append(ep.contentType).append("]");
                }
                evidence.append(ep.hasAuth ? " (auth)" : " (no-auth)");
                evidence.append("\n");
            }

            findings.add(
                    Finding.of(id(), base, "API Endpoints Discovered in JS Bundles", Severity.INFO, evidence.toString(),
                            "API endpoint definitions embedded in client-side JavaScript reveal "
                                    + "the application's full API surface, including paths, methods, "
                                    + "and authentication requirements. Attackers can use this to "
                                    + "map and target the backend.",
                            "curl -s '" + base + "' | grep -oE 'fetch\\(|axios\\.'",
                            "Minimize API surface exposure in client bundles. Use code splitting "
                                    + "to load endpoint references only where needed. Ensure all "
                                    + "endpoints enforce proper server-side authentication and "
                                    + "authorization regardless of client-side checks."));

            // MEDIUM findings for unauthenticated endpoints
            List<ApiEndpoint> unauthEndpoints = allEndpoints.stream().filter(ep -> !ep.hasAuth).toList();

            if (!unauthEndpoints.isEmpty()) {
                StringBuilder unauthEvidence = new StringBuilder();
                unauthEvidence.append("API endpoints with no client-side authentication headers:\n");
                for (ApiEndpoint ep : unauthEndpoints) {
                    unauthEvidence.append("  ").append(ep.method).append(" ").append(ep.path).append("\n");
                }

                log.accept(
                        "[!] " + id() + ": " + unauthEndpoints.size() + " endpoint(s) with no auth headers detected");
                findings.add(Finding.of(id(), base, "Unauthenticated API Endpoint", Severity.MEDIUM,
                        unauthEvidence.toString(),
                        "API endpoints called without authentication headers in "
                                + "client-side code may lack server-side auth enforcement. "
                                + "Attackers can invoke these endpoints directly, potentially "
                                + "accessing sensitive data or performing unauthorized actions.",
                        "curl -s '" + base + "' -- inspect JS bundles for fetch/axios calls without "
                                + "Authorization headers",
                        "Ensure all API endpoints enforce server-side authentication. "
                                + "Do not rely on client-side auth header injection as the "
                                + "sole access control. Implement proper RBAC and session "
                                + "validation on the backend."));
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": no API endpoints extracted from JS bundles");
        } else {
            log.accept("[+] " + id() + ": " + findings.size() + " finding(s) from JS analysis");
        }
        return findings;
    }

    private void analyzeJsContent(String content, String jsUrl, List<ApiEndpoint> endpoints, Set<String> seenEndpoints,
            Consumer<String> log) {
        // 1. fetch() calls
        Matcher fetchMatcher = FETCH_CALL.matcher(content);
        while (fetchMatcher.find()) {
            String path = normalizeTemplateLiterals(fetchMatcher.group(1));
            String options = fetchMatcher.group(2);
            if (!isApiPath(path) || !seenEndpoints.add("fetch|" + path)) {
                continue;
            }
            String method = extractMethod(options, "GET");
            String contentType = extractContentType(options);
            boolean hasAuth = hasAuthHeader(options);
            endpoints.add(new ApiEndpoint(method, path, contentType, hasAuth));
        }

        // 2. $fetch() calls (Nuxt)
        Matcher dollarFetchMatcher = DOLLAR_FETCH_CALL.matcher(content);
        while (dollarFetchMatcher.find()) {
            String path = normalizeTemplateLiterals(dollarFetchMatcher.group(1));
            String options = dollarFetchMatcher.group(2);
            if (!isApiPath(path) || !seenEndpoints.add("$fetch|" + path)) {
                continue;
            }
            String method = extractMethod(options, "GET");
            String contentType = extractContentType(options);
            boolean hasAuth = hasAuthHeader(options);
            endpoints.add(new ApiEndpoint(method, path, contentType, hasAuth));
        }

        // 3. axios.method() calls
        Matcher axiosMethodMatcher = AXIOS_METHOD_CALL.matcher(content);
        while (axiosMethodMatcher.find()) {
            String method = axiosMethodMatcher.group(1).toUpperCase();
            String path = normalizeTemplateLiterals(axiosMethodMatcher.group(2));
            String configBlock = axiosMethodMatcher.group(3);
            if (!isApiPath(path) || !seenEndpoints.add("axios|" + method + "|" + path)) {
                continue;
            }
            String contentType = extractContentType(configBlock);
            boolean hasAuth = hasAuthHeader(configBlock);
            endpoints.add(new ApiEndpoint(method, path, contentType, hasAuth));
        }

        // 4. axios({ url: "...", method: "..." }) config style
        Matcher axiosConfigMatcher = AXIOS_CONFIG_CALL.matcher(content);
        while (axiosConfigMatcher.find()) {
            String configBlock = axiosConfigMatcher.group(1);
            Matcher urlMatcher = URL_IN_CONFIG.matcher(configBlock);
            if (!urlMatcher.find()) {
                continue;
            }
            String path = normalizeTemplateLiterals(urlMatcher.group(1));
            if (!isApiPath(path) || !seenEndpoints.add("axiosCfg|" + path)) {
                continue;
            }
            String method = extractMethod(configBlock, "GET");
            String contentType = extractContentType(configBlock);
            boolean hasAuth = hasAuthHeader(configBlock);
            endpoints.add(new ApiEndpoint(method, path, contentType, hasAuth));
        }

        // 5. XMLHttpRequest.open()
        Matcher xhrMatcher = XHR_OPEN.matcher(content);
        while (xhrMatcher.find()) {
            String method = xhrMatcher.group(1).toUpperCase();
            String path = normalizeTemplateLiterals(xhrMatcher.group(2));
            if (!isApiPath(path) || !seenEndpoints.add("xhr|" + method + "|" + path)) {
                continue;
            }
            // XHR auth detection is limited -- check surrounding context
            int start = Math.max(0, xhrMatcher.start() - 500);
            int end = Math.min(content.length(), xhrMatcher.end() + 1000);
            String context = content.substring(start, end);
            boolean hasAuth = AUTH_HEADER_PATTERN.matcher(context).find();
            endpoints.add(new ApiEndpoint(method, path, null, hasAuth));
        }

        if (!endpoints.isEmpty()) {
            log.accept("[+] " + id() + ": extracted endpoints from " + jsUrl);
        }
    }

    private static String normalizeTemplateLiterals(String path) {
        // Replace ${...} template expressions with {param}
        Matcher m = TEMPLATE_PARAM.matcher(path);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String paramName = m.group(1).trim();
            // Use the variable name as the parameter name if simple, otherwise "param"
            String normalized = paramName.matches("[a-zA-Z_][a-zA-Z0-9_]*") ? paramName : "param";
            m.appendReplacement(sb, "{" + normalized + "}");
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static boolean isApiPath(String path) {
        if (path == null || path.isBlank()) {
            return false;
        }
        // Accept relative paths starting with /
        if (path.startsWith("/")) {
            return true;
        }
        // Accept full URLs
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return true;
        }
        return false;
    }

    private static String extractMethod(String options, String defaultMethod) {
        if (options == null || options.isBlank()) {
            return defaultMethod;
        }
        Matcher m = METHOD_PATTERN.matcher(options);
        if (m.find()) {
            return m.group(1).toUpperCase();
        }
        return defaultMethod;
    }

    private static String extractContentType(String options) {
        if (options == null || options.isBlank()) {
            return null;
        }
        Matcher m = CONTENT_TYPE_PATTERN.matcher(options);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }

    private static boolean hasAuthHeader(String options) {
        if (options == null || options.isBlank()) {
            return false;
        }
        return AUTH_HEADER_PATTERN.matcher(options).find();
    }

    private String fetchBody(ScanContext ctx, HttpClient hc, String url, Consumer<String> log) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            if (resp.statusCode() >= 200 && resp.statusCode() < 400) {
                return resp.body();
            }
        } catch (Exception e) {
            // Connection errors, timeouts -- skip silently
        }
        return null;
    }

    private static String resolveUrl(String base, String path) {
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return path;
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return base + path;
    }
}
