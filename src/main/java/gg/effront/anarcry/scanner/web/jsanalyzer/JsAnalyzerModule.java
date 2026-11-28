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

    // -- tRPC patterns --

    private static final Pattern TRPC_HOOK = Pattern.compile("\\w+\\.(\\w+)\\.(\\w+)\\.(useQuery|useMutation)");

    private static final Pattern TRPC_CONCAT_URL = Pattern
            .compile("\\.concat\\s*\\(\\s*[\"']([^\"']+)[\"']\\s*,\\s*[\"']/trpc[\"']\\)");

    private static final Pattern TRPC_URL = Pattern.compile("url\\s*:\\s*[\"']([^\"']*/trpc)[\"']");

    // -- UploadThing patterns --

    private static final Pattern UPLOADTHING_SLUG = Pattern
            .compile("(?:endpoint|slug)\\s*[=:]\\s*[\"']([a-zA-Z]+(?:Uploader|Upload)[a-zA-Z]*)[\"']");

    private static final Pattern UPLOADTHING_CALL = Pattern
            .compile("(?:startUpload|useUploadThing)\\s*\\(\\s*[\"']([a-zA-Z]+(?:Uploader|uploader))[\"']");

    // -- Next.js Server Actions --

    private static final Pattern SERVER_ACTION_REF = Pattern.compile(
            "createServerReference\\s*\\(\\s*[\"']([0-9a-f]{20,50})[\"'](?:[^)]*,\\s*[\"']([a-zA-Z_]+)[\"'])?");

    // -- Analytics key patterns --

    private static final Pattern POSTHOG_INIT = Pattern
            .compile("(?:posthog|PostHog)\\s*\\.\\s*init\\s*\\(\\s*[\"']?([^\"',)]+)[\"']?");

    private static final Pattern PHC_KEY = Pattern.compile("phc_[A-Za-z0-9_-]{20,}");

    private static final Pattern PK_KEY = Pattern.compile("pk_(?:live|test)_[A-Za-z0-9_-]{20,}");

    // -- Environment / config leaks --

    private static final Pattern NEXT_PUBLIC_ENV = Pattern.compile("(?:env|process\\.env)\\.?(NEXT_PUBLIC_[A-Z_]+)");

    private static final Pattern ISSUE_TRACKER_REF = Pattern.compile("[\"']([A-Z]{2,10}-\\d{1,6})[\"']");

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
        Set<String> trpcBaseUrls = new LinkedHashSet<>();
        Set<String> serverActions = new LinkedHashSet<>();
        Set<String> analyticsKeys = new LinkedHashSet<>();
        Set<String> envVarRefs = new LinkedHashSet<>();
        Set<String> issueRefs = new LinkedHashSet<>();

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
            analyzeFrameworkMetadata(body, trpcBaseUrls, serverActions, analyticsKeys, envVarRefs, issueRefs);
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

        // Phase 5: Framework metadata findings
        if (!trpcBaseUrls.isEmpty()) {
            StringBuilder ev = new StringBuilder("tRPC base URL(s) detected:\n");
            for (String url : trpcBaseUrls) {
                ev.append("  ").append(url).append("\n");
            }
            findings.add(Finding.of(id(), base, "tRPC Base URL Exposed in JS Bundle", Severity.INFO, ev.toString(),
                    "tRPC endpoint base URL is embedded in client JavaScript, "
                            + "revealing the RPC API surface for enumeration.",
                    "curl -s '" + base + "' | grep -oE '/trpc'",
                    "Ensure all tRPC procedures enforce server-side " + "authentication and authorization."));
        }

        if (!serverActions.isEmpty()) {
            StringBuilder ev = new StringBuilder("Next.js Server Action references:\n");
            for (String action : serverActions) {
                ev.append("  ").append(action).append("\n");
            }
            findings.add(Finding.of(id(), base, "Next.js Server Actions Exposed in JS Bundle", Severity.INFO,
                    ev.toString(),
                    "Server Action hashes embedded in client bundles allow direct "
                            + "invocation via POST with the Next-Action header.",
                    "curl -X POST '" + base + "' -H 'Next-Action: <hash>' -H 'Content-Type: text/plain;charset=UTF-8'",
                    "Ensure Server Actions validate authentication and input. "
                            + "Do not expose sensitive operations as Server Actions "
                            + "without proper access control."));
        }

        if (!analyticsKeys.isEmpty()) {
            StringBuilder ev = new StringBuilder("Analytics/tracking keys found in JS:\n");
            for (String key : analyticsKeys) {
                ev.append("  ").append(key).append("\n");
            }
            findings.add(Finding.of(id(), base, "Analytics Keys Exposed in JS Bundle", Severity.LOW, ev.toString(),
                    "Exposed analytics project keys allow attackers to pollute "
                            + "analytics data or enumerate project configuration.",
                    "curl -s '" + base + "' | grep -oE 'phc_[A-Za-z0-9_-]+'",
                    "Rotate exposed keys if they grant write access. "
                            + "Use server-side proxying for analytics to avoid "
                            + "exposing project keys in client bundles."));
        }

        if (!envVarRefs.isEmpty()) {
            StringBuilder ev = new StringBuilder("NEXT_PUBLIC environment variables referenced:\n");
            for (String v : envVarRefs) {
                ev.append("  ").append(v).append("\n");
            }
            findings.add(Finding.of(id(), base, "NEXT_PUBLIC Environment Variables in JS Bundle", Severity.INFO,
                    ev.toString(),
                    "NEXT_PUBLIC_ prefixed environment variables are inlined into "
                            + "client bundles at build time, revealing application configuration.",
                    "curl -s '" + base + "' | grep -oE 'NEXT_PUBLIC_[A-Z_]+'",
                    "Audit all NEXT_PUBLIC_ variables to ensure no secrets or "
                            + "internal infrastructure details are exposed. Use "
                            + "server-side environment variables for sensitive config."));
        }

        if (!issueRefs.isEmpty()) {
            StringBuilder ev = new StringBuilder("Issue tracker references found in JS:\n");
            for (String ref : issueRefs) {
                ev.append("  ").append(ref).append("\n");
            }
            findings.add(Finding.of(id(), base, "Issue Tracker References in JS Bundle", Severity.INFO, ev.toString(),
                    "Internal issue tracker IDs (Jira, Linear) embedded in client "
                            + "code reveal project management details and feature flags.",
                    "curl -s '" + base + "' | grep -oE '[A-Z]+-[0-9]+'",
                    "Remove hardcoded issue tracker references from production "
                            + "bundles. Use feature flag systems instead of ticket IDs."));
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

        // 6. tRPC React hook calls
        Matcher trpcHookMatcher = TRPC_HOOK.matcher(content);
        while (trpcHookMatcher.find()) {
            String namespace = trpcHookMatcher.group(1);
            String procedure = trpcHookMatcher.group(2);
            String path = "/trpc/" + namespace + "." + procedure + "?batch=1";
            if (!seenEndpoints.add("trpc|" + path)) {
                continue;
            }
            endpoints.add(new ApiEndpoint("POST", path, "application/json", false));
        }

        // 7. UploadThing slugs
        Set<String> utSlugs = new HashSet<>();
        Matcher utSlugMatcher = UPLOADTHING_SLUG.matcher(content);
        while (utSlugMatcher.find()) {
            utSlugs.add(utSlugMatcher.group(1));
        }
        Matcher utCallMatcher = UPLOADTHING_CALL.matcher(content);
        while (utCallMatcher.find()) {
            utSlugs.add(utCallMatcher.group(1));
        }
        for (String slug : utSlugs) {
            String path = "/api/uploadthing?slug=" + slug + "&actionType=upload";
            if (!seenEndpoints.add("uploadthing|" + slug)) {
                continue;
            }
            endpoints.add(new ApiEndpoint("POST", path, "multipart/form-data", false));
        }

        if (!endpoints.isEmpty()) {
            log.accept("[+] " + id() + ": extracted endpoints from " + jsUrl);
        }
    }

    private static void analyzeFrameworkMetadata(String content, Set<String> trpcBaseUrls, Set<String> serverActions,
            Set<String> analyticsKeys, Set<String> envVarRefs, Set<String> issueRefs) {
        Matcher concatMatcher = TRPC_CONCAT_URL.matcher(content);
        while (concatMatcher.find()) {
            trpcBaseUrls.add(concatMatcher.group(1) + "/trpc");
        }
        Matcher trpcUrlMatcher = TRPC_URL.matcher(content);
        while (trpcUrlMatcher.find()) {
            trpcBaseUrls.add(trpcUrlMatcher.group(1));
        }

        Matcher saMatcher = SERVER_ACTION_REF.matcher(content);
        while (saMatcher.find()) {
            String hash = saMatcher.group(1);
            String name = saMatcher.group(2);
            serverActions.add(name != null ? name + " (" + hash + ")" : hash);
        }

        Matcher phMatcher = POSTHOG_INIT.matcher(content);
        while (phMatcher.find()) {
            analyticsKeys.add("posthog:" + phMatcher.group(1).trim());
        }
        Matcher phcMatcher = PHC_KEY.matcher(content);
        while (phcMatcher.find()) {
            analyticsKeys.add(phcMatcher.group());
        }
        Matcher pkMatcher = PK_KEY.matcher(content);
        while (pkMatcher.find()) {
            analyticsKeys.add(pkMatcher.group());
        }

        Matcher envMatcher = NEXT_PUBLIC_ENV.matcher(content);
        while (envMatcher.find()) {
            envVarRefs.add(envMatcher.group(1));
        }

        Matcher issueMatcher = ISSUE_TRACKER_REF.matcher(content);
        while (issueMatcher.find()) {
            issueRefs.add(issueMatcher.group(1));
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
