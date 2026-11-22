package gg.effront.anarcry.scanner.web.frameworkconfig;

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
 * Extracts framework-specific configuration objects from HTML pages and JS
 * bundles, identifying exposed backend URLs, credentials, and runtime config.
 */
public class FrameworkConfigModule implements Scanner {

    // -- Framework config patterns (match the assignment or JSON block) --

    private static final Pattern NUXT_CONFIG = Pattern.compile("window\\.__NUXT__\\s*=\\s*\\{([^;]{1,20000})",
            Pattern.DOTALL);

    private static final Pattern NEXT_DATA = Pattern.compile("window\\.__NEXT_DATA__\\s*=\\s*\\{([^;]{1,20000})",
            Pattern.DOTALL);

    private static final Pattern REMIX_CONTEXT = Pattern
            .compile("window\\.__REMIX_CONTEXT__\\s*=\\s*\\{([^;]{1,20000})", Pattern.DOTALL);

    private static final Pattern WINDOW_ENV = Pattern.compile("window\\.env\\s*=\\s*\\{([^;]{1,10000})",
            Pattern.DOTALL);

    private static final Pattern WINDOW_UNDERSCORE_ENV = Pattern.compile("window\\._env_\\s*=\\s*\\{([^;]{1,10000})",
            Pattern.DOTALL);

    private static final Pattern IMPORT_META_ENV = Pattern.compile("import\\.meta\\.env\\s*=\\s*\\{([^;]{1,10000})",
            Pattern.DOTALL);

    private record FrameworkPattern(String framework, Pattern pattern) {
    }

    private static final List<FrameworkPattern> FRAMEWORK_PATTERNS = List.of(
            new FrameworkPattern("Nuxt.js (__NUXT__)", NUXT_CONFIG),
            new FrameworkPattern("Next.js (__NEXT_DATA__)", NEXT_DATA),
            new FrameworkPattern("Remix (__REMIX_CONTEXT__)", REMIX_CONTEXT),
            new FrameworkPattern("window.env", WINDOW_ENV), new FrameworkPattern("window._env_", WINDOW_UNDERSCORE_ENV),
            new FrameworkPattern("import.meta.env", IMPORT_META_ENV));

    // -- URL extraction patterns within config blocks --

    private static final Pattern BACKEND_URL_PATTERN = Pattern
            .compile("(?i)(?:apiBase|baseURL|API_URL|BACKEND_URL|SERVER_URL|api_url|backend_url|"
                    + "server_url|api_base|base_url|BASE_URL)\\s*[:=]\\s*[\"']" + "(https?://[^\"'\\s]{4,200})[\"']");

    // Generic URL pattern for values inside config blocks
    private static final Pattern CONFIG_URL_PATTERN = Pattern.compile("[\"'](https?://[^\"'\\s]{4,200})[\"']");

    // Credential patterns inside config blocks
    private static final Pattern CONFIG_SECRET_PATTERN = Pattern
            .compile("(?i)(?:secret|password|passwd|api_key|apikey|api_secret|access_token|"
                    + "private_key|token|auth_token|client_secret)\\s*[:=]\\s*" + "[\"']([^\"']{8,})[\"']");

    // JS assignment patterns for backend URLs (outside framework config blocks)
    private static final Pattern JS_BACKEND_ASSIGNMENT = Pattern
            .compile("(?i)(?:const|let|var|)\\s*(?:apiBase|baseURL|API_URL|BACKEND_URL|SERVER_URL|"
                    + "api_url|backend_url|server_url|api_base|base_url|BASE_URL)\\s*=\\s*"
                    + "[\"'](https?://[^\"'\\s]{4,200})[\"']");

    @Override
    public String id() {
        return "FrameworkConfig";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();
        Set<String> scannedUrls = new HashSet<>();
        Set<String> jsUrls = new LinkedHashSet<>();
        Set<String> discoveredBackendUrls = new LinkedHashSet<>();
        Set<String> seenConfigs = new HashSet<>();
        Set<String> seenCredentials = new HashSet<>();

        String base = ctx.targetUrl().replaceAll("/+$", "");

        // Phase 1: Scan crawled pages for framework configs
        log.accept("[~] " + id() + ": scanning pages for framework configuration objects");
        Set<String> paths = ctx.discoveredPaths().paths();
        if (paths.isEmpty()) {
            paths = Set.of("/");
        }

        for (String path : paths) {
            String url = resolveUrl(base, path);
            if (!scannedUrls.add(url)) {
                continue;
            }
            String body = fetchBody(ctx, hc, url, log);
            if (body == null || body.isBlank()) {
                continue;
            }
            // Scan HTML for framework configs
            scanForFrameworkConfigs(body, url, findings, discoveredBackendUrls, seenConfigs, seenCredentials, log);
            // Scan for standalone backend URL assignments
            scanForBackendAssignments(body, url, findings, discoveredBackendUrls, seenConfigs, log);
        }

        // Phase 2: Discover all JS bundles (including lazy-loaded chunks)
        jsUrls.addAll(JsBundleDiscovery.discover(ctx, hc, base, log));
        log.accept("[~] " + id() + ": scanning " + jsUrls.size() + " JS bundle(s) for configs");
        for (String jsUrl : jsUrls) {
            if (!scannedUrls.add(jsUrl)) {
                continue;
            }
            String body = fetchBody(ctx, hc, jsUrl, log);
            if (body == null || body.isBlank()) {
                continue;
            }
            scanForFrameworkConfigs(body, jsUrl, findings, discoveredBackendUrls, seenConfigs, seenCredentials, log);
            scanForBackendAssignments(body, jsUrl, findings, discoveredBackendUrls, seenConfigs, log);
        }

        // Phase 3: Feed discovered backend URLs into discoveredPaths for downstream
        // modules
        for (String backendUrl : discoveredBackendUrls) {
            ctx.discoveredPaths().addPath(backendUrl);
            log.accept("[+] " + id() + ": registered backend URL for downstream: " + backendUrl);
        }

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": no exposed framework configurations detected");
        } else {
            log.accept("[!] " + id() + ": " + findings.size() + " finding(s) from framework config analysis");
        }
        return findings;
    }

    private void scanForFrameworkConfigs(String content, String url, List<Finding> findings,
            Set<String> discoveredBackendUrls, Set<String> seenConfigs, Set<String> seenCredentials,
            Consumer<String> log) {
        for (FrameworkPattern fp : FRAMEWORK_PATTERNS) {
            Matcher matcher = fp.pattern.matcher(content);
            if (!matcher.find()) {
                continue;
            }
            String configBlock = matcher.group(1);
            String configKey = fp.framework + "|" + url;
            if (!seenConfigs.add(configKey)) {
                continue;
            }

            // INFO finding for exposed framework config
            String snippet = configBlock.length() > 300 ? configBlock.substring(0, 300) + "..." : configBlock;
            log.accept("[+] " + id() + ": " + fp.framework + " config detected in " + url);
            findings.add(Finding.of(id(), url, "Exposed " + fp.framework + " Configuration", Severity.INFO,
                    fp.framework + " config block found in " + url + ": {" + snippet + "}",
                    "Exposed framework configuration may reveal internal architecture, "
                            + "environment variables, API endpoints, and deployment details " + "to attackers.",
                    "curl -s '" + url + "' | grep -o '" + fp.framework.split(" ")[0] + "'",
                    "Move sensitive configuration to server-side only. Use runtime "
                            + "environment variables that are not bundled into client code. "
                            + "Review framework documentation for secure config patterns."));

            // Check for backend URLs inside config block
            extractBackendUrls(configBlock, url, fp.framework, findings, discoveredBackendUrls, seenConfigs, log);

            // Check for credentials inside config block
            Matcher credMatcher = CONFIG_SECRET_PATTERN.matcher(configBlock);
            while (credMatcher.find()) {
                String credValue = credMatcher.group(1);
                if (seenCredentials.add(credValue)) {
                    String masked = maskValue(credValue);
                    log.accept("[!!] " + id() + ": credential found in " + fp.framework + " config at " + url);
                    findings.add(Finding.of(id(), url, "Credential in " + fp.framework + " Config", Severity.HIGH,
                            "Credential found in " + fp.framework + " config block at " + url + ": " + masked,
                            "Hardcoded credentials in client-side framework configuration "
                                    + "are directly accessible to any visitor. This can lead to "
                                    + "unauthorized access to backend services, APIs, or databases.",
                            "curl -s '" + url + "' | grep -iE '(secret|password|api_key|token)'",
                            "Remove all credentials from client-side code immediately. "
                                    + "Use server-side environment variables and proxy API calls "
                                    + "through a backend. Rotate all exposed credentials."));
                }
            }
        }
    }

    private void extractBackendUrls(String configBlock, String pageUrl, String framework, List<Finding> findings,
            Set<String> discoveredBackendUrls, Set<String> seenConfigs, Consumer<String> log) {
        // First try named backend URL keys
        Matcher namedMatcher = BACKEND_URL_PATTERN.matcher(configBlock);
        while (namedMatcher.find()) {
            String backendUrl = namedMatcher.group(1);
            if (discoveredBackendUrls.add(backendUrl) && isExternalOrigin(pageUrl, backendUrl)) {
                log.accept("[!] " + id() + ": external backend URL in " + framework + " config: " + backendUrl);
                findings.add(
                        Finding.of(id(), pageUrl, "Exposed Backend URL in " + framework + " Config", Severity.MEDIUM,
                                "Backend URL " + backendUrl + " found in " + framework + " config at " + pageUrl,
                                "Exposed backend URLs reveal internal infrastructure and can be "
                                        + "targeted directly, bypassing frontend security controls "
                                        + "such as rate limiting, WAF rules, and authentication checks.",
                                "curl -s '" + pageUrl + "' | grep -oE \"https?://[^ \\\"]+\"",
                                "Do not expose backend URLs in client-side configuration. "
                                        + "Use relative paths or a reverse proxy. If the backend "
                                        + "must be public, ensure proper authentication and rate limiting."));
            }
        }

        // Also scan for any URL in the config block that might be external
        Matcher urlMatcher = CONFIG_URL_PATTERN.matcher(configBlock);
        while (urlMatcher.find()) {
            String foundUrl = urlMatcher.group(1);
            if (discoveredBackendUrls.add(foundUrl) && isExternalOrigin(pageUrl, foundUrl)) {
                // Only log, do not generate duplicate findings for every URL
                log.accept("[~] " + id() + ": external URL in " + framework + " config: " + foundUrl);
            }
        }
    }

    private void scanForBackendAssignments(String content, String url, List<Finding> findings,
            Set<String> discoveredBackendUrls, Set<String> seenConfigs, Consumer<String> log) {
        Matcher matcher = JS_BACKEND_ASSIGNMENT.matcher(content);
        while (matcher.find()) {
            String backendUrl = matcher.group(1);
            String key = "jsAssign|" + backendUrl;
            if (!seenConfigs.add(key)) {
                continue;
            }
            discoveredBackendUrls.add(backendUrl);
            if (isExternalOrigin(url, backendUrl)) {
                log.accept("[!] " + id() + ": backend URL assignment found in " + url + ": " + backendUrl);
                findings.add(Finding.of(id(), url, "Backend URL in JS Assignment", Severity.MEDIUM,
                        "Backend URL " + backendUrl + " assigned in JavaScript at " + url,
                        "Hardcoded backend URLs in JavaScript expose internal "
                                + "infrastructure to attackers, enabling direct targeting " + "of backend services.",
                        "curl -s '" + url + "' | grep -oiE \"(apiBase|baseURL|API_URL|BACKEND_URL|SERVER_URL)\"",
                        "Use relative API paths or server-side configuration. "
                                + "Avoid embedding absolute backend URLs in client bundles."));
            }
        }
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

    private static boolean isExternalOrigin(String pageUrl, String candidateUrl) {
        try {
            String pageHost = URI.create(pageUrl).getHost();
            String candidateHost = URI.create(candidateUrl).getHost();
            if (pageHost == null || candidateHost == null) {
                return false;
            }
            return !pageHost.equalsIgnoreCase(candidateHost);
        } catch (Exception e) {
            return false;
        }
    }

    private static String maskValue(String value) {
        if (value.length() <= 12) {
            return value.substring(0, Math.min(4, value.length())) + "****";
        }
        return value.substring(0, 8) + "..." + value.substring(value.length() - 4);
    }
}
