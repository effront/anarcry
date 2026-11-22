package gg.effront.anarcry.scanner.web.backendliveness;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.ConnectException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BackendLivenessModule implements Scanner {

    // Backend URL patterns in frontend code
    private static final Pattern BACKEND_VAR_URL = Pattern
            .compile("(?i)(?:apiBase|baseURL|API_URL|BACKEND_URL|SERVER_URL|apiUrl|serverUrl)"
                    + "\\s*[:=]\\s*[\"']?(https?://[^\"'\\s,;]+)[\"']?");

    private static final Pattern NUXT_CONFIG_URL = Pattern
            .compile("window\\.__NUXT__[^}]*[\"'](https?://[^\"']+)[\"']");

    private static final Pattern PLATFORM_URL = Pattern
            .compile("https?://[^\"'\\s]+\\.(?:ondigitalocean\\.app|herokuapp\\.com|vercel\\.app"
                    + "|netlify\\.app|railway\\.app|onrender\\.com|fly\\.dev|web\\.app"
                    + "|pages\\.dev|azurewebsites\\.net)");

    // Pattern to extract script src attributes from HTML
    private static final Pattern SCRIPT_SRC = Pattern.compile("<script[^>]+src=[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE);

    @Override
    public String id() {
        return "BackendLiveness";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String base = ctx.targetUrl().replaceAll("/+$", "");
        String targetHost = ctx.host();

        // Collect all page content: HTML pages + JS bundles
        Map<String, String> contentByUrl = new LinkedHashMap<>();
        Set<String> jsUrls = new LinkedHashSet<>();
        Set<String> scannedUrls = new LinkedHashSet<>();

        // Phase 1: Fetch crawled pages and extract script URLs
        log.accept("[~] " + id() + ": scanning frontend code for backend URL references");
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
            contentByUrl.put(url, body);
            extractScriptUrls(body, base, url, jsUrls);
        }

        // Phase 2: Fetch JS bundles
        log.accept("[~] " + id() + ": fetching " + jsUrls.size() + " JS bundle(s)");
        for (String jsUrl : jsUrls) {
            if (!scannedUrls.add(jsUrl)) {
                continue;
            }
            String body = fetchBody(ctx, hc, jsUrl, log);
            if (body == null || body.isBlank()) {
                continue;
            }
            contentByUrl.put(jsUrl, body);
        }

        // Phase 3: Extract backend URLs from all content
        Map<String, String> urlsByHostname = new LinkedHashMap<>(); // hostname -> first URL found
        Map<String, String> sourceByHostname = new LinkedHashMap<>(); // hostname -> source file
        Map<String, String> contextByHostname = new LinkedHashMap<>(); // hostname -> context snippet

        for (var entry : contentByUrl.entrySet()) {
            String sourceUrl = entry.getKey();
            String content = entry.getValue();
            extractBackendUrls(content, sourceUrl, targetHost, urlsByHostname, sourceByHostname, contextByHostname);
        }

        if (urlsByHostname.isEmpty()) {
            log.accept("[+] " + id() + ": no external backend references found");
            return findings;
        }

        log.accept(
                "[~] " + id() + ": found " + urlsByHostname.size() + " unique external backend hostname(s) to check");

        // Phase 4: Probe each external backend
        for (var entry : urlsByHostname.entrySet()) {
            String hostname = entry.getKey();
            String backendUrl = entry.getValue();
            String source = sourceByHostname.get(hostname);
            String snippet = contextByHostname.get(hostname);

            probeBackend(ctx, hc, hostname, backendUrl, source, snippet, findings, log);
        }

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": all external backend references appear healthy");
        } else {
            log.accept("[!!] " + id() + ": " + findings.size() + " backend liveness issue(s) detected");
        }
        return findings;
    }

    private void extractBackendUrls(String content, String sourceUrl, String targetHost,
            Map<String, String> urlsByHostname, Map<String, String> sourceByHostname,
            Map<String, String> contextByHostname) {

        Pattern[] patterns = {BACKEND_VAR_URL, NUXT_CONFIG_URL, PLATFORM_URL};

        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                String url = matcher.group(pattern == PLATFORM_URL ? 0 : 1);
                if (url == null || url.isBlank()) {
                    continue;
                }
                // Clean trailing punctuation that may have been captured
                url = url.replaceAll("[\"'\\s;,]+$", "");

                String hostname;
                try {
                    hostname = URI.create(url).getHost();
                } catch (Exception e) {
                    continue;
                }
                if (hostname == null || hostname.isBlank()) {
                    continue;
                }

                // Skip URLs matching the target's own hostname
                if (hostname.equalsIgnoreCase(targetHost)) {
                    continue;
                }

                // Deduplicate by hostname -- keep first occurrence
                if (!urlsByHostname.containsKey(hostname)) {
                    urlsByHostname.put(hostname, url);
                    sourceByHostname.put(hostname, sourceUrl);

                    // Extract context snippet around the match
                    int start = Math.max(0, matcher.start() - 40);
                    int end = Math.min(content.length(), matcher.end() + 40);
                    String snippet = content.substring(start, end).replace("\n", " ").replace("\r", "");
                    contextByHostname.put(hostname, snippet);
                }
            }
        }
    }

    private void probeBackend(ScanContext ctx, HttpClient hc, String hostname, String backendUrl, String source,
            String snippet, List<Finding> findings, Consumer<String> log) {

        String evidence = "Source: " + source + "\nURL: " + backendUrl + "\nContext: ..." + snippet + "...";

        // Step 1: DNS check
        try {
            InetAddress.getByName(hostname);
        } catch (UnknownHostException e) {
            log.accept("[!!] " + id() + ": NXDOMAIN for " + hostname + " referenced in " + source);
            findings.add(buildFinding(backendUrl, "Dangling Backend Reference -- NXDOMAIN", Severity.CRITICAL,
                    evidence + "\nDNS: NXDOMAIN -- hostname does not resolve",
                    "The frontend references a backend at " + hostname
                            + " that no longer exists in DNS. An attacker can register this hostname "
                            + "on the hosting platform and serve malicious responses to all users.",
                    "dig " + hostname + "\ncurl -sI " + backendUrl + "\n# Referenced in: " + source));
            return;
        }

        // Step 2: HTTP HEAD probe
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(backendUrl)).timeout(Duration.ofSeconds(8))
                    .method("HEAD", HttpRequest.BodyPublishers.noBody()).build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            int status = resp.statusCode();

            if (status >= 500) {
                log.accept("[!] " + id() + ": unhealthy backend " + hostname + " -- HTTP " + status);
                findings.add(buildFinding(backendUrl, "Unhealthy Backend -- " + status, Severity.MEDIUM,
                        evidence + "\nDNS: resolves\nHTTP: " + status,
                        "The frontend references a backend at " + hostname
                                + " that returns server errors. This may indicate "
                                + "a misconfigured or failing service.",
                        "curl -sI " + backendUrl + "\n# Referenced in: " + source));
            } else if (status >= 200 && status < 400) {
                log.accept("[~] " + id() + ": external backend " + hostname + " is alive (HTTP " + status + ")");
                findings.add(buildFinding(backendUrl, "External Backend Reference Detected", Severity.INFO,
                        evidence + "\nDNS: resolves\nHTTP: " + status,
                        "The frontend references an external backend at " + hostname
                                + ". Verify this is intentional and that all endpoints "
                                + "require proper authentication.",
                        "curl -sI " + backendUrl + "\n# Referenced in: " + source));
            }
        } catch (ConnectException e) {
            log.accept("[!] " + id() + ": connection failed to " + hostname);
            findings.add(buildFinding(backendUrl, "Dead Backend Reference -- Connection Failed", Severity.HIGH,
                    evidence + "\nDNS: resolves\nHTTP: ConnectException -- " + e.getMessage(),
                    "The frontend references a backend at " + hostname
                            + " that resolves in DNS but refuses connections. "
                            + "An attacker who claims this IP or hostname on the hosting platform "
                            + "can intercept API traffic.",
                    "curl -sI " + backendUrl + "\n# Referenced in: " + source));
        } catch (Exception e) {
            // Timeouts, SSL errors, etc. -- treat as connection failure
            if (isConnectionFailure(e)) {
                log.accept("[!] " + id() + ": connection failed to " + hostname + " -- " + e.getMessage());
                findings.add(buildFinding(backendUrl, "Dead Backend Reference -- Connection Failed", Severity.HIGH,
                        evidence + "\nDNS: resolves\nHTTP: " + e.getClass().getSimpleName() + " -- " + e.getMessage(),
                        "The frontend references a backend at " + hostname
                                + " that resolves in DNS but is unreachable. "
                                + "An attacker who claims this hostname on the hosting platform "
                                + "can intercept API traffic.",
                        "curl -sI " + backendUrl + "\n# Referenced in: " + source));
            }
        }
    }

    private boolean isConnectionFailure(Exception e) {
        Throwable cause = e;
        while (cause != null) {
            if (cause instanceof ConnectException || cause instanceof java.net.SocketTimeoutException) {
                return true;
            }
            String msg = cause.getMessage();
            if (msg != null && (msg.contains("timed out") || msg.contains("Connection refused"))) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private Finding buildFinding(String endpoint, String title, Severity severity, String evidence, String impact,
            String reproduction) {
        return Finding.of(id(), endpoint, title, severity, evidence, impact, reproduction,
                "Remove dead backend reference from frontend configuration. "
                        + "Deploy replacement with authentication on all endpoints.");
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

    private void extractScriptUrls(String html, String base, String pageUrl, Set<String> jsUrls) {
        Matcher matcher = SCRIPT_SRC.matcher(html);
        while (matcher.find()) {
            String src = matcher.group(1);
            if (src.startsWith("//")) {
                jsUrls.add("https:" + src);
            } else if (src.startsWith("http://") || src.startsWith("https://")) {
                jsUrls.add(src);
            } else if (src.startsWith("/")) {
                jsUrls.add(base + src);
            } else {
                String parentPath = pageUrl.substring(0, pageUrl.lastIndexOf('/') + 1);
                jsUrls.add(parentPath + src);
            }
        }
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
