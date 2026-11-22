package gg.effront.anarcry.scanner.web.domsink;

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

public class DomSinkModule implements Scanner {

    // -- Sink definitions --

    private record SinkDef(String type, Pattern pattern) {
    }

    private static final List<SinkDef> SINK_DEFS = List.of(
            new SinkDef("innerHTML/outerHTML", Pattern.compile("\\.(innerHTML|outerHTML)\\s*=")),
            new SinkDef("document.write", Pattern.compile("document\\s*\\.\\s*(write|writeln)\\s*\\(")),
            new SinkDef("insertAdjacentHTML", Pattern.compile("\\.insertAdjacentHTML\\s*\\(")),
            new SinkDef("eval", Pattern.compile("\\beval\\s*\\(")),
            new SinkDef("new Function", Pattern.compile("\\bnew\\s+Function\\s*\\(")),
            new SinkDef("setTimeout(string)", Pattern.compile("\\bsetTimeout\\s*\\(\\s*[\"'`]")),
            new SinkDef("setInterval(string)", Pattern.compile("\\bsetInterval\\s*\\(\\s*[\"'`]")),
            new SinkDef("DOMParser+adoptNode/importNode", Pattern.compile("(adoptNode|importNode)\\s*\\(")));

    // Data source indicators -- external/tainted data flowing into a sink
    private static final Pattern DATA_SOURCE = Pattern
            .compile("\\bfetch\\b|\\bresponse\\b|\\bres\\.|" + "\\.json\\(\\)|\\$fetch\\b|\\blocation\\.|"
                    + "\\bURL\\b|\\bsearchParams\\b|\\bdocument\\.cookie\\b|\\bwindow\\.name\\b");

    // Static string patterns -- sinks clearly fed by hardcoded literals (not
    // exploitable)
    private static final Pattern STATIC_INNER_HTML = Pattern
            .compile("\\.(innerHTML|outerHTML)\\s*=\\s*[\"'][^\"']{0,500}[\"']");
    private static final Pattern STATIC_DOC_WRITE = Pattern
            .compile("document\\s*\\.\\s*(write|writeln)\\s*\\(\\s*[\"'][^\"']{0,500}[\"']\\s*\\)");
    private static final Pattern STATIC_EVAL = Pattern.compile("\\beval\\s*\\(\\s*[\"'][^\"']{0,500}[\"']\\s*\\)");
    private static final Pattern STATIC_NEW_FUNCTION = Pattern
            .compile("\\bnew\\s+Function\\s*\\(\\s*[\"'][^\"']{0,500}[\"']\\s*\\)");
    private static final Pattern STATIC_INSERT_HTML = Pattern
            .compile("\\.insertAdjacentHTML\\s*\\(\\s*[\"'][^\"']*[\"']\\s*,\\s*[\"'][^\"']{0,500}[\"']\\s*\\)");
    private static final Pattern STATIC_SET_TIMEOUT = Pattern
            .compile("\\bsetTimeout\\s*\\(\\s*[\"'][^\"']{0,500}[\"']\\s*,");
    private static final Pattern STATIC_SET_INTERVAL = Pattern
            .compile("\\bsetInterval\\s*\\(\\s*[\"'][^\"']{0,500}[\"']\\s*,");

    private static final int CONTEXT_CHARS = 120;
    private static final int LOOKBACK_CHARS = 500;
    private static final int DEDUP_KEY_CHARS = 60;

    @Override
    public String id() {
        return "DomSinks";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();
        Set<String> scannedUrls = new HashSet<>();
        Set<String> dedupKeys = new HashSet<>();
        Set<String> jsUrls = new LinkedHashSet<>();

        String base = ctx.targetUrl().replaceAll("/+$", "");

        // Phase 1: Discover all JS bundles (including lazy-loaded chunks)
        jsUrls.addAll(JsBundleDiscovery.discover(ctx, hc, base, log));
        log.accept("[~] " + id() + ": scanning " + jsUrls.size() + " JavaScript bundle(s) for DOM sinks");
        for (String jsUrl : jsUrls) {
            if (!scannedUrls.add(jsUrl)) {
                continue;
            }
            String body = fetchBody(ctx, hc, jsUrl, log);
            if (body == null || body.isBlank()) {
                continue;
            }
            scanJsContent(body, jsUrl, findings, dedupKeys, log);
        }

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": no DOM sink patterns detected");
        } else {
            log.accept("[!!] " + id() + ": " + findings.size() + " DOM sink(s) detected");
        }
        return findings;
    }

    private void scanJsContent(String js, String jsUrl, List<Finding> findings, Set<String> dedupKeys,
            Consumer<String> log) {
        for (SinkDef def : SINK_DEFS) {
            Matcher matcher = def.pattern.matcher(js);
            while (matcher.find()) {
                int matchStart = matcher.start();
                int matchEnd = matcher.end();

                // Skip sinks clearly fed by static/hardcoded strings
                if (isStaticSink(js, matchStart, def.type)) {
                    continue;
                }

                // Extract ~120 chars of surrounding context
                int ctxStart = Math.max(0, matchStart - CONTEXT_CHARS / 2);
                int ctxEnd = Math.min(js.length(), matchEnd + CONTEXT_CHARS / 2);
                String context = js.substring(ctxStart, ctxEnd).replaceAll("\\s+", " ").trim();

                // Deduplicate by sinkType + first 60 chars of context
                String dedupContext = context.length() > DEDUP_KEY_CHARS
                        ? context.substring(0, DEDUP_KEY_CHARS)
                        : context;
                String dedupKey = def.type + "|" + dedupContext;
                if (!dedupKeys.add(dedupKey)) {
                    continue;
                }

                // Look backwards ~500 chars for data source indicators
                int lookbackStart = Math.max(0, matchStart - LOOKBACK_CHARS);
                String lookback = js.substring(lookbackStart, matchStart);
                Matcher sourceMatcher = DATA_SOURCE.matcher(lookback);

                if (sourceMatcher.find()) {
                    String dataSource = sourceMatcher.group();
                    String title = "DOM XSS Sink: " + def.type + " fed by " + dataSource;
                    log.accept("[!!] " + id() + ": " + title + " in " + jsUrl);
                    findings.add(buildFinding(jsUrl, title, Severity.MEDIUM, context, def.pattern.pattern(), jsUrl));
                } else {
                    String title = "Potential DOM Sink: " + def.type;
                    log.accept("[!] " + id() + ": " + title + " in " + jsUrl);
                    findings.add(buildFinding(jsUrl, title, Severity.LOW, context, def.pattern.pattern(), jsUrl));
                }
            }
        }
    }

    private boolean isStaticSink(String js, int matchStart, String sinkType) {
        int windowEnd = Math.min(js.length(), matchStart + 600);
        String window = js.substring(matchStart, windowEnd);
        return switch (sinkType) {
            case "innerHTML/outerHTML" -> STATIC_INNER_HTML.matcher(window).lookingAt();
            case "document.write" -> STATIC_DOC_WRITE.matcher(window).lookingAt();
            case "eval" -> STATIC_EVAL.matcher(window).lookingAt();
            case "new Function" -> STATIC_NEW_FUNCTION.matcher(window).lookingAt();
            case "insertAdjacentHTML" -> STATIC_INSERT_HTML.matcher(window).lookingAt();
            case "setTimeout(string)" -> STATIC_SET_TIMEOUT.matcher(window).lookingAt();
            case "setInterval(string)" -> STATIC_SET_INTERVAL.matcher(window).lookingAt();
            default -> false;
        };
    }

    private Finding buildFinding(String endpoint, String title, Severity severity, String evidence, String sinkPattern,
            String jsUrl) {
        return Finding.of(id(), endpoint, title, severity, evidence,
                "DOM-based XSS allows attackers to execute arbitrary JavaScript in the victim's "
                        + "browser by injecting malicious input through client-side data sources "
                        + "(URL parameters, document.cookie, window.name) into dangerous DOM sinks.",
                "grep -n '" + sinkPattern + "' " + jsUrl,
                "Replace innerHTML with textContent, or sanitize with DOMPurify before DOM insertion");
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
